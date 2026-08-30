package org.xiyu.githubdirect.core.dns

import org.xiyu.githubdirect.core.data.ResolvedIps
import org.xiyu.githubdirect.core.net.NetworkBinder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * DoH 解析器（从原 DohResolver 迁移：多服务器回退 + CidrFilter 过滤 + GET 查询，参数化）。
 *
 * - 网络访问全部经 NetworkBinder（VPN 进程绑底层物理网络，防环回）
 * - 单次查询：服务器逐个尝试；任一服务器返回有效 IP 即成功（快速路径）
 * - 明显污染/私网地址始终丢弃；另外 CIDR 过滤后再决定是否采用
 * - 服务器有响应但 IP 全被过滤（污染）→ 继续下一个服务器
 */
class EndpointResolver(
    private val binder: NetworkBinder,
    private val servers: List<String> = DoHServers.DEFAULT,
    private val connectTimeoutMs: Int = 3000,
    private val readTimeoutMs: Int = 3000,
    private val wireClient: WireDohClient? = null,
    private val wireTimeoutMs: Int = 2500,
    /** 候选发现才开启：合并独立解析器视角；普通 DNS 回答保持最快可信端点。 */
    private val mergeIndependentWireAnswers: Boolean = false,
) {

    /**
     * 候选发现的双信任域结果。只有 [trusted] 可进入 TLS 上游探测；[observed] 只能用于
     * 防火墙污染目标观测，不能被提升为上游候选。
     */
    data class DiscoveryResult(
        val trusted: ResolvedIps,
        val observed: ResolvedIps,
        val trustedResponseObserved: Boolean,
        val observerResponseObserved: Boolean,
    )

    private data class TypeDiscovery(
        val trusted: List<ByteArray>,
        val observed: List<ByteArray>,
        val trustedResponseObserved: Boolean,
        val observerResponseObserved: Boolean,
    )

    fun resolveA(domain: String, cidr: CidrFilter?): List<ByteArray>? =
        resolveType(domain, 1, cidr)

    /** 同时查询 A + AAAA，CIDR 过滤后返回。全部服务器失败返回 null。 */
    fun resolve(domain: String, cidr: CidrFilter?): ResolvedIps? {
        if (wireClient != null) return resolveWire(domain, cidr)
        for (server in servers) {
            val v4 = queryDohType(server, domain, 1, cidr)
            val v6 = queryDohType(server, domain, 28, cidr)
            val responded = v4 != null || v6 != null
            val hasV4 = v4 != null && v4.isNotEmpty()
            val hasV6 = v6 != null && v6.isNotEmpty()
            if (responded && (hasV4 || hasV6)) {
                return ResolvedIps(
                    v4 = v4.orEmpty(),
                    v6 = v6.orEmpty(),
                )
            }
            // 有响应但全被过滤（污染）→ 尝试下一服务器；无响应同理
        }
        return null
    }

    /**
     * 按单个 qtype 查询（1=A, 28=AAAA），CIDR 过滤后返回。
     * 全部服务器失败返回 null；有响应但无有效 IP 返回空列表。
     */
    fun resolveType(domain: String, qtype: Int, cidr: CidrFilter?): List<ByteArray>? {
        // 当前实现是 IP-address JSON adapter，只允许 A/AAAA。
        // 其他 QTYPE 必须由后续 RFC8484 raw-wire forwarder 处理，不能伪装成 A 查询。
        if (qtype != 1 && qtype != 28) return emptyList()
        if (wireClient != null) return queryWireType(domain, qtype, cidr, wireTimeoutMs)
        var lastResponded = false
        for (server in servers) {
            val result = queryDohType(server, domain, qtype, cidr)
            if (result != null) {
                lastResponded = true
                if (result.isNotEmpty()) return result
            }
        }
        return if (lastResponded) emptyList() else null
    }

    /** 候选 provider 专用；普通 DNS 回答不得调用或合并 [DiscoveryResult.observed]。 */
    fun discover(domain: String, cidr: CidrFilter?): DiscoveryResult? {
        if (wireClient == null) {
            val trusted = resolve(domain, cidr) ?: return null
            return DiscoveryResult(
                trusted = trusted,
                observed = ResolvedIps.EMPTY,
                trustedResponseObserved = true,
                observerResponseObserved = false,
            )
        }
        return resolveWireDiscovery(domain, cidr)
    }

    /** 单个 DoH 服务器、单个类型的查询。null = 服务器不可用；空列表 = 有响应但全被过滤。 */
    private fun queryDohType(server: String, domain: String, type: Int, cidr: CidrFilter?): List<ByteArray>? {
        val typeStr = if (type == 28) "AAAA" else "A"
        val url = "$server?name=$domain&type=$typeStr"
        val json = binder.httpGet(url, connectTimeoutMs, readTimeoutMs) ?: return null
        if (DoHJson.status(json) != 0) return null

        val result = ArrayList<ByteArray>(4)
        for ((answerType, data) in DoHJson.answers(json)) {
            if (answerType != type) continue
            val bytes = IpAddresses.parseIpAddress(data) ?: continue
            if (IpAddresses.isBogonOrPoisoned(bytes)) continue
            if (cidr != null) {
                if (bytes.size == 4 && !cidr.allowsIpv4(bytes)) continue
                if (bytes.size == 16 && !cidr.allowsIpv6(bytes)) continue
            }
            result.add(bytes)
        }
        return result
    }

    /** A/AAAA 并发，共享一个严格全局 deadline，避免旧实现按服务器串行累积到数十秒。 */
    private fun resolveWire(domain: String, cidr: CidrFilter?): ResolvedIps? {
        if (mergeIndependentWireAnswers) {
            val discovery = resolveWireDiscovery(domain, cidr) ?: return null
            return discovery.trusted.takeIf { it.v4.isNotEmpty() || it.v6.isNotEmpty() }
        }
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(wireTimeoutMs.toLong())
        val v4 = AtomicReference<List<ByteArray>?>(null)
        val v6 = AtomicReference<List<ByteArray>?>(null)
        val latch = CountDownLatch(2)
        fun launch(qtype: Int, target: AtomicReference<List<ByteArray>?>) {
            val task = Runnable {
                try {
                    val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
                        .toInt().coerceAtLeast(1)
                    target.set(queryWireType(domain, qtype, cidr, remaining))
                } catch (_: Throwable) {
                    // 解析失败保持 null；线程资源压力不能穿透到前台服务主进程。
                } finally {
                    latch.countDown()
                }
            }
            try {
                Thread(null, task, "GHD-Wire-$qtype", WIRE_THREAD_STACK_BYTES).apply {
                    isDaemon = true
                    start()
                }
            } catch (_: Throwable) {
                latch.countDown()
            }
        }
        launch(1, v4)
        launch(28, v6)
        try {
            latch.await(wireTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        val a = v4.get()
        val aaaa = v6.get()
        if (a == null && aaaa == null) return null
        if (a.orEmpty().isEmpty() && aaaa.orEmpty().isEmpty()) return null
        return ResolvedIps(a.orEmpty(), aaaa.orEmpty())
    }

    /** A/AAAA 候选发现并发执行，但按响应端点信任属性分别聚合。 */
    private fun resolveWireDiscovery(domain: String, cidr: CidrFilter?): DiscoveryResult? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(wireTimeoutMs.toLong())
        val v4 = AtomicReference<TypeDiscovery?>(null)
        val v6 = AtomicReference<TypeDiscovery?>(null)
        val latch = CountDownLatch(2)
        fun launch(qtype: Int, target: AtomicReference<TypeDiscovery?>) {
            val task = Runnable {
                try {
                    val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
                        .toInt().coerceAtLeast(1)
                    target.set(queryWireDiscoveryType(domain, qtype, cidr, remaining))
                } catch (_: Throwable) {
                    // fail-close：该 qtype 本轮无可信发现结果。
                } finally {
                    latch.countDown()
                }
            }
            try {
                Thread(null, task, "GHD-Wire-Discover-$qtype", WIRE_THREAD_STACK_BYTES).apply {
                    isDaemon = true
                    start()
                }
            } catch (_: Throwable) {
                latch.countDown()
            }
        }
        launch(1, v4)
        launch(28, v6)
        try {
            latch.await(wireTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        val a = v4.get()
        val aaaa = v6.get()
        if (a == null && aaaa == null) return null
        return DiscoveryResult(
            trusted = ResolvedIps(a?.trusted.orEmpty(), aaaa?.trusted.orEmpty()),
            observed = ResolvedIps(a?.observed.orEmpty(), aaaa?.observed.orEmpty()),
            trustedResponseObserved = a?.trustedResponseObserved == true ||
                aaaa?.trustedResponseObserved == true,
            observerResponseObserved = a?.observerResponseObserved == true ||
                aaaa?.observerResponseObserved == true,
        )
    }

    private fun queryWireType(
        domain: String,
        qtype: Int,
        cidr: CidrFilter?,
        timeoutMs: Int,
    ): List<ByteArray>? {
        val client = wireClient ?: return null
        val query = DnsWireCodec.buildQuery(domain, qtype) ?: return emptyList()
        val expectedId = DnsPacketCodec.readU16(query, 0)
        if (mergeIndependentWireAnswers) {
            return queryWireDiscoveryType(domain, qtype, cidr, timeoutMs)?.trusted
        }
        val responses = listOfNotNull(client.post(query, timeoutMs))
        if (responses.isEmpty()) return null

        var parsedResponse = false
        val addresses = LinkedHashMap<String, ByteArray>()
        for (response in responses) {
            val answer = DnsWireCodec.parseAnswers(response, expectedId, qtype) ?: continue
            parsedResponse = true
            if (answer.rcode != 0) continue
            answer.addresses.forEach { bytes ->
                if (IpAddresses.isBogonOrPoisoned(bytes)) return@forEach
                if (cidr != null && bytes.size == 4 && !cidr.allowsIpv4(bytes)) return@forEach
                if (cidr != null && bytes.size == 16 && !cidr.allowsIpv6(bytes)) return@forEach
                val address = if (bytes.size == 4) {
                    IpAddresses.ipv4ToString(bytes)
                } else {
                    IpAddresses.ipv6ToString(bytes)
                }
                addresses.putIfAbsent(address, bytes)
            }
        }
        return if (parsedResponse) addresses.values.toList() else null
    }

    private fun queryWireDiscoveryType(
        domain: String,
        qtype: Int,
        cidr: CidrFilter?,
        timeoutMs: Int,
    ): TypeDiscovery? {
        val client = wireClient ?: return null
        val query = DnsWireCodec.buildQuery(domain, qtype) ?: return null
        val expectedId = DnsPacketCodec.readU16(query, 0)
        val responses = client.postAllDistinctResolvers(query, timeoutMs)
        if (responses.isEmpty()) return null

        var trustedResponseObserved = false
        var observerResponseObserved = false
        val trusted = LinkedHashMap<String, ByteArray>()
        val observed = LinkedHashMap<String, ByteArray>()
        for (response in responses) {
            val answer = DnsWireCodec.parseAnswers(response.body, expectedId, qtype) ?: continue
            if (response.endpoint.trustedForAnswers) {
                trustedResponseObserved = true
            } else {
                observerResponseObserved = true
            }
            if (answer.rcode != 0) continue
            val destination = if (response.endpoint.trustedForAnswers) trusted else observed
            answer.addresses.forEach { bytes ->
                if (IpAddresses.isBogonOrPoisoned(bytes)) return@forEach
                if (cidr != null && bytes.size == 4 && !cidr.allowsIpv4(bytes)) return@forEach
                if (cidr != null && bytes.size == 16 && !cidr.allowsIpv6(bytes)) return@forEach
                val address = if (bytes.size == 4) {
                    IpAddresses.ipv4ToString(bytes)
                } else {
                    IpAddresses.ipv6ToString(bytes)
                }
                destination.putIfAbsent(address, bytes)
            }
        }
        return TypeDiscovery(
            trusted = trusted.values.toList(),
            observed = observed.values.toList(),
            trustedResponseObserved = trustedResponseObserved,
            observerResponseObserved = observerResponseObserved,
        )
    }

    companion object {
        /** Android 默认线程栈约 4 MiB；发现任务调用深度有限，512 KiB 足够并显著降低峰值。 */
        private const val WIRE_THREAD_STACK_BYTES = 512L * 1024L
    }
}

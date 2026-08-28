package org.xiyu.githubdirect.core.dns

import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import org.xiyu.githubdirect.core.net.NetworkBinder

/**
 * RFC8484 wire DoH 客户端（纯 JDK javax.net.ssl，无 android.* 依赖）。
 *
 * - POST endpoint.path，请求体 = raw DNS 查询字节，响应 = raw DNS 响应字节（RCode 天然保留）
 * - SSLSocket 直连端点 IP:443，SNI 设为期望主机名；
 *   HostnameVerifier 按期望主机名校验证书（§31 bootstrap 安全，禁止 TrustAll）
 * - 健康状态（§32）：UNKNOWN/HEALTHY/DEGRADED/BACKOFF；
 *   连续 2 次失败 → BACKOFF（冷却 60s，冷却期跳过）；成功 → HEALTHY
 * - Hedging（§33）：按健康排序，先发 primary；350ms 未完成 → 发 secondary；
 *   第一个成功响应胜；全部失败 → null。绝不并发请求全部 endpoint。
 *
 * 线程安全：全部状态 @Volatile/原子，无网络全局锁。
 */
class WireDohClient @JvmOverloads constructor(
    private val endpoints: List<WireEndpoint> = DEFAULT_ENDPOINTS,
    private val hedgeDelayMs: Long = 350,
    private val backoffMs: Long = 60_000,
    private val maxFailuresBeforeBackoff: Int = 2,
    /** 进程内 deadline/退避使用单调时钟，避免系统时间校准导致超时失真。 */
    private val clock: () -> Long = { System.nanoTime() / 1_000_000L },
    private val binder: NetworkBinder? = null,
    /**
     * 可选传输实现。Android 生产路径注入 OkHttp HTTP/2 传输；null 时保留纯 JDK
     * HTTP/1.1 实现，供 JVM/兼容路径使用。
     */
    private val transport: ((WireEndpoint, ByteArray, Int) -> ByteArray?)? = null,
) {

    enum class Health { UNKNOWN, HEALTHY, DEGRADED, BACKOFF }

    /**
     * wire DoH 端点：IP 字面量直连 + 期望主机名（SNI / 证书校验）。
     *
     * [trustedForAnswers] 为 false 的端点只参与候选发现，用于观察 DNS 污染；其响应不得直接
     * 返回给目标应用。[resolverId] 将同一提供方的多个 IP 归为一个独立解析器。
     */
    data class WireEndpoint(
        val ip: String,
        val hostname: String,
        val port: Int = 443,
        val path: String = "/dns-query",
        val resolverId: String = hostname,
        val trustedForAnswers: Boolean = true,
    )

    /** 候选发现响应必须保留端点身份，调用方才能隔离可信答案与污染观察。 */
    data class ResolverResponse(
        val endpoint: WireEndpoint,
        val body: ByteArray,
    )

    private class EndpointState {
        @Volatile var health: Health = Health.UNKNOWN
        val failures = AtomicInteger(0)
        val backoffUntil = AtomicLong(0)
    }

    private val states = ConcurrentHashMap<WireEndpoint, EndpointState>().apply {
        for (ep in endpoints) put(ep, EndpointState())
    }
    private val discoveryCursor = AtomicInteger()

    private val sslSocketFactory: SSLSocketFactory =
        SSLSocketFactory.getDefault() as SSLSocketFactory
    private val hostnameVerifier: HostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()

    /**
     * raw wire DoH 查询：发 primary，hedge 窗口未完成则发 secondary；
     * 第一个成功响应胜；全部失败 → null。
     * 实现：每次查询最多 2 个短命工作线程 + 阻塞队列收结果。
     */
    fun post(rawQuery: ByteArray, timeoutMs: Int): ByteArray? {
        if (rawQuery.size < 12 || timeoutMs <= 0) return null
        val candidates = orderedCandidates().filter(WireEndpoint::trustedForAnswers)
        if (candidates.isEmpty()) return null

        val queue = LinkedBlockingQueue<Pair<WireEndpoint, ByteArray?>>()
        val threads = ArrayList<Thread>()
        val openSockets = ConcurrentHashMap.newKeySet<Socket>()
        val deadline = clock() + timeoutMs
        var hedged = false
        var interrupted = false
        val submitted = LinkedHashSet<WireEndpoint>()
        val completed = HashSet<WireEndpoint>()

        submit(candidates[0], rawQuery, deadline, queue, threads, openSockets)
        submitted += candidates[0]

        while (true) {
            val remaining = deadline - clock()
            if (remaining <= 0) break
            // 没有 secondary 时不存在 hedge 窗口，必须让唯一端点使用完整 deadline。
            val waitMs = if (hedged || candidates.size == 1) {
                remaining
            } else {
                minOf(remaining, hedgeDelayMs)
            }
            val result = try {
                queue.poll(waitMs, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                interrupted = true
                break
            }
            if (result != null) {
                val (endpoint, body) = result
                completed += endpoint
                if (body != null) {
                    recordSuccess(endpoint)
                    cancelAll(threads, openSockets)
                    return body
                }
                recordFailure(endpoint)
                // primary 快速失败 → 立即补发 secondary
                if (!hedged && candidates.size > 1) {
                    hedged = true
                    submit(candidates[1], rawQuery, deadline, queue, threads, openSockets)
                    submitted += candidates[1]
                    continue
                }
                if (hedged && completed.size < submitted.size) continue
                break
            }
            // hedge 窗口超时 → 发 secondary
            if (!hedged && candidates.size > 1) {
                hedged = true
                submit(candidates[1], rawQuery, deadline, queue, threads, openSockets)
                submitted += candidates[1]
                continue
            }
            break
        }
        if (!interrupted) {
            // 截止前未返回的 endpoint 也必须累计失败，否则永久卡住的 primary 每次都被首选。
            (submitted - completed).forEach(::recordFailure)
        }
        cancelAll(threads, openSockets)
        if (interrupted) Thread.currentThread().interrupt()
        return null
    }

    /**
     * 候选发现专用：并发查询不同 [WireEndpoint.resolverId]，合并独立视角。
     *
     * 与 [post] 的安全边界不同：这里允许观察器端点返回污染样本，但调用者只能把结果交给
     * 严格 TLS SNI/系统证书探测；未通过探测的地址必须保持 intercept-only。
     */
    internal fun postAllDistinctResolvers(
        rawQuery: ByteArray,
        timeoutMs: Int,
        maxTrustedResponses: Int = 2,
        maxObserverResponses: Int = 1,
        maxResolvers: Int = 3,
    ): List<ResolverResponse> {
        if (
            rawQuery.size < 12 || timeoutMs <= 0 || maxTrustedResponses < 0 ||
            maxObserverResponses < 0 || maxResolvers <= 0 ||
            maxTrustedResponses + maxObserverResponses == 0
        ) {
            return emptyList()
        }
        val candidates = distinctResolverCandidates(maxResolvers)
        if (candidates.isEmpty()) return emptyList()

        val queue = LinkedBlockingQueue<Pair<WireEndpoint, ByteArray?>>()
        val threads = ArrayList<Thread>(candidates.size)
        val openSockets = ConcurrentHashMap.newKeySet<Socket>()
        val deadline = clock() + timeoutMs
        val completed = HashSet<WireEndpoint>()
        val responses = ArrayList<ResolverResponse>(
            minOf(maxTrustedResponses + maxObserverResponses, candidates.size),
        )
        var trustedCount = 0
        var observerCount = 0

        candidates.forEach { submit(it, rawQuery, deadline, queue, threads, openSockets) }
        var interrupted = false
        while (
            completed.size < candidates.size &&
            (trustedCount < maxTrustedResponses || observerCount < maxObserverResponses)
        ) {
            val remaining = deadline - clock()
            if (remaining <= 0) break
            val result = try {
                queue.poll(remaining, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                interrupted = true
                break
            } ?: break
            val (endpoint, body) = result
            if (!completed.add(endpoint)) continue
            if (body == null) {
                recordFailure(endpoint)
            } else {
                recordSuccess(endpoint)
                if (endpoint.trustedForAnswers && trustedCount < maxTrustedResponses) {
                    responses += ResolverResponse(endpoint, body)
                    trustedCount++
                } else if (!endpoint.trustedForAnswers && observerCount < maxObserverResponses) {
                    responses += ResolverResponse(endpoint, body)
                    observerCount++
                }
            }
        }

        // 只有真实 deadline/中断前失败才降级；达到足够独立响应后取消的请求不算失败。
        if (
            !interrupted &&
            (trustedCount < maxTrustedResponses || observerCount < maxObserverResponses)
        ) {
            (candidates - completed).forEach(::recordFailure)
        }
        cancelAll(threads, openSockets)
        if (interrupted) Thread.currentThread().interrupt()
        return responses
    }

    /** hostname → 健康状态（诊断/测试）。 */
    fun healthSnapshot(): Map<String, Health> =
        endpoints.associate { it.hostname to (states[it]?.health ?: Health.UNKNOWN) }

    // ==================== 健康状态（§32） ====================

    private fun recordSuccess(endpoint: WireEndpoint) {
        states[endpoint]?.let { s ->
            s.failures.set(0)
            s.health = Health.HEALTHY
        }
    }

    private fun recordFailure(endpoint: WireEndpoint) {
        states[endpoint]?.let { s ->
            if (s.failures.incrementAndGet() >= maxFailuresBeforeBackoff) {
                s.backoffUntil.set(clock() + backoffMs)
                s.health = Health.BACKOFF
            } else {
                s.health = Health.DEGRADED
            }
        }
    }

    /** 跳过冷却期端点，按健康程度排序（HEALTHY → UNKNOWN → DEGRADED）。 */
    private fun orderedCandidates(): List<WireEndpoint> {
        return availableCandidates().sortedBy { healthRank(states[it]!!.health) }
    }

    /**
     * 候选发现保留一个稳定可信解析器，并轮换其余可信提供方；同一提供方每轮只选一个 IP。
     * 观察器仍固定保留至多一个槽。这样总并发保持 2 trusted + 1 observer，同时新增提供方
     * 不会因为配置顺序永久拿不到查询机会。
     */
    private fun distinctResolverCandidates(maxResolvers: Int): List<WireEndpoint> {
        val seen = HashSet<String>()
        val distinct = ArrayList<WireEndpoint>()
        for (endpoint in availableCandidates()) {
            if (!seen.add(endpoint.resolverId)) continue
            distinct += endpoint
        }
        val observers = distinct.filterNot(WireEndpoint::trustedForAnswers)
        val trusted = distinct.filter(WireEndpoint::trustedForAnswers)
        val trustedSlots = (maxResolvers - if (observers.isEmpty()) 0 else 1).coerceAtLeast(0)
        return buildList(maxResolvers) {
            if (trustedSlots > 0 && trusted.isNotEmpty()) {
                add(trusted.first())
                val rotating = trusted.drop(1)
                if (rotating.isNotEmpty()) {
                    val start = Math.floorMod(discoveryCursor.getAndIncrement(), rotating.size)
                    repeat(minOf(trustedSlots - 1, rotating.size)) { offset ->
                        add(rotating[(start + offset) % rotating.size])
                    }
                }
            }
            if (observers.isNotEmpty() && size < maxResolvers) add(observers.first())
        }
    }

    private fun availableCandidates(): List<WireEndpoint> {
        val now = clock()
        return endpoints.filter { ep ->
            val s = states[ep] ?: return@filter true
            if (s.health != Health.BACKOFF) return@filter true
            if (now >= s.backoffUntil.get()) {
                s.health = Health.UNKNOWN
                s.failures.set(0)
                return@filter true
            }
            false
        }
    }

    private fun healthRank(h: Health): Int = when (h) {
        Health.HEALTHY -> 0
        Health.UNKNOWN -> 1
        Health.DEGRADED -> 2
        Health.BACKOFF -> 3
    }

    // ==================== 查询执行 ====================

    private fun submit(
        endpoint: WireEndpoint,
        rawQuery: ByteArray,
        deadline: Long,
        queue: LinkedBlockingQueue<Pair<WireEndpoint, ByteArray?>>,
        threads: MutableList<Thread>,
        openSockets: MutableSet<Socket>,
    ) {
        val t = Thread({
            val body = try {
                wireRequest(endpoint, rawQuery, deadline, openSockets)
            } catch (_: Exception) {
                null
            }
            queue.offer(endpoint to body)
        }, "WireDoh-${endpoint.hostname}")
        t.isDaemon = true
        threads.add(t)
        t.start()
    }

    private fun wireRequest(
        endpoint: WireEndpoint,
        rawQuery: ByteArray,
        deadline: Long,
        openSockets: MutableSet<Socket>,
    ): ByteArray? {
        val injected = transport
        if (injected != null) return injected(endpoint, rawQuery, timeoutBudget(deadline))
        return realWireRequest(endpoint, rawQuery, deadline, openSockets)
    }

    private fun timeoutBudget(deadline: Long): Int =
        (deadline - clock()).toInt().coerceAtLeast(1)

    /** 真实 TLS 路径：SSLSocket → SNI → 握手 → HostnameVerifier → POST → 读响应。 */
    private fun realWireRequest(
        endpoint: WireEndpoint,
        rawQuery: ByteArray,
        deadline: Long,
        openSockets: MutableSet<Socket>,
    ): ByteArray? {
        val socket = sslSocketFactory.createSocket() as SSLSocket
        openSockets.add(socket)
        try {
            binder?.bindSocket(socket)
            val params = socket.sslParameters
            params.serverNames = listOf(SNIHostName(endpoint.hostname))
            socket.sslParameters = params

            socket.connect(InetSocketAddress(endpoint.ip, endpoint.port), timeoutBudget(deadline))
            socket.soTimeout = timeoutBudget(deadline)
            socket.startHandshake()

            // §31：按期望主机名校验证书链（系统信任锚 + 主机名 SAN），禁止 TrustAll
            if (!hostnameVerifier.verify(endpoint.hostname, socket.session)) return null

            val out = socket.getOutputStream()
            out.write(buildHttpPost(endpoint.hostname, endpoint.path, rawQuery))
            out.flush()

            val input = socket.getInputStream()
            val response = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (true) {
                if (clock() >= deadline) return null
                socket.soTimeout = timeoutBudget(deadline)
                val n = input.read(buf)
                if (n < 0) break
                if (response.size() + n > MAX_HTTP_RESPONSE_BYTES) return null
                response.write(buf, 0, n)
            }

            val responseBytes = response.toByteArray()
            val parsed = parseHttpResponse(responseBytes) ?: return null
            if (parsed.first != 200) return null
            if (!hasDnsMessageContentType(responseBytes)) return null
            val body = parsed.second ?: return null
            return if (isResponseForQuery(rawQuery, body)) body else null
        } catch (_: Exception) {
            return null
        } finally {
            openSockets.remove(socket)
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    /** 成功返回后取消在途线程（关 socket 解阻塞 + interrupt）。 */
    private fun cancelAll(threads: List<Thread>, openSockets: MutableSet<Socket>) {
        for (s in openSockets) {
            try {
                s.close()
            } catch (_: Exception) {
            }
        }
        for (t in threads) t.interrupt()
    }

    companion object {

        /**
         * 固定 IP + 严格证书端点表。
         *
         * 优先使用无内容过滤的 Mullvad 与 Control D；CleanBrowsing Security Filter 仅作
         * 可信回退。阿里/腾讯只作为污染观察器，不得被 [post] 直接选为目标应用的 DNS 回答。
         */
        val DEFAULT_ENDPOINTS: List<WireEndpoint> = listOf(
            WireEndpoint(
                "194.242.2.2",
                "dns.mullvad.net",
                path = "/dns-query",
                resolverId = "mullvad",
            ),
            WireEndpoint(
                "2a07:e340::2",
                "dns.mullvad.net",
                path = "/dns-query",
                resolverId = "mullvad",
            ),
            WireEndpoint(
                "76.76.10.11",
                "freedns.controld.com",
                path = "/p0",
                resolverId = "controld-unfiltered",
            ),
            WireEndpoint(
                "76.76.2.11",
                "freedns.controld.com",
                path = "/p0",
                resolverId = "controld-unfiltered",
            ),
            WireEndpoint(
                "2606:1a40:1::11",
                "freedns.controld.com",
                path = "/p0",
                resolverId = "controld-unfiltered",
            ),
            WireEndpoint(
                "2606:1a40::11",
                "freedns.controld.com",
                path = "/p0",
                resolverId = "controld-unfiltered",
            ),
            WireEndpoint(
                "185.228.168.9",
                "doh.cleanbrowsing.org",
                path = "/doh/security-filter/",
                resolverId = "cleanbrowsing",
            ),
            WireEndpoint(
                "185.228.169.9",
                "doh.cleanbrowsing.org",
                path = "/doh/security-filter/",
                resolverId = "cleanbrowsing",
            ),
            WireEndpoint("1.1.1.1", "cloudflare-dns.com", resolverId = "cloudflare"),
            WireEndpoint("8.8.8.8", "dns.google", resolverId = "google"),
            WireEndpoint("9.9.9.10", "dns10.quad9.net", resolverId = "quad9-unfiltered"),
            WireEndpoint("149.112.112.10", "dns10.quad9.net", resolverId = "quad9-unfiltered"),
            WireEndpoint(
                "223.5.5.5",
                "dns.alidns.com",
                resolverId = "alidns-observer",
                trustedForAnswers = false,
            ),
            WireEndpoint(
                "1.12.12.12",
                "doh.pub",
                resolverId = "tencent-observer",
                trustedForAnswers = false,
            ),
            WireEndpoint(
                "120.53.53.53",
                "doh.pub",
                resolverId = "tencent-observer",
                trustedForAnswers = false,
            ),
        )

        /** 构造 RFC8484 wire DoH POST 请求字节（纯函数，测试直测字节格式）。 */
        fun buildHttpPost(host: String, body: ByteArray): ByteArray =
            buildHttpPost(host, "/dns-query", body)

        /** 支持提供方声明的 RFC8484 路径；拒绝任何可注入 HTTP 请求行/头的字符。 */
        fun buildHttpPost(host: String, path: String, body: ByteArray): ByteArray {
            require(host.isNotBlank() && host.none { it == '\r' || it == '\n' || it <= ' ' })
            require(path.startsWith('/') && path.none { it == '\r' || it == '\n' || it == ' ' })
            val head = ("POST $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "Accept: application/dns-message\r\n" +
                "Content-Type: application/dns-message\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Connection: close\r\n" +
                "\r\n").toByteArray(Charsets.US_ASCII)
            val req = ByteArray(head.size + body.size)
            System.arraycopy(head, 0, req, 0, head.size)
            System.arraycopy(body, 0, req, head.size, body.size)
            return req
        }

        /**
         * 解析 HTTP/1.1 响应字节 → (status, body)。
         * - 非 200 → (status, null)
         * - Transfer-Encoding: chunked → null（不支持）
         * - 无 Content-Length → 取剩余全部字节（Connection: close 帧）
         * - Content-Length 非法或声明超出可用字节 → null
         * - 格式非法（无状态行 / 无空行）→ null
         */
        fun parseHttpResponse(bytes: ByteArray): Pair<Int, ByteArray?>? {
            if (bytes.isEmpty()) return null
            val headerEnd = indexOfDoubleCrLf(bytes) ?: return null
            val head = String(bytes, 0, headerEnd, Charsets.US_ASCII)
            val lines = head.split("\r\n")
            val status = lines.firstOrNull()?.let { parseStatusLine(it) } ?: return null
            val headers = HashMap<String, String>()
            for (line in lines.drop(1)) {
                val idx = line.indexOf(':')
                if (idx <= 0) continue
                headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
            }
            val bodyStart = headerEnd + 4
            if (status != 200) return status to null
            if (headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true) return null
            val declaredRaw = headers["content-length"]
            val declared = declaredRaw?.toIntOrNull()
            if (declaredRaw != null && (declared == null || declared !in 0..MAX_HTTP_RESPONSE_BYTES)) {
                return null
            }
            val available = (bytes.size - bodyStart).coerceAtLeast(0)
            if (declared != null && declared > available) return null
            val bodyLen = declared ?: available
            return status to bytes.copyOfRange(bodyStart, bodyStart + bodyLen)
        }

        /** 最低限度绑定请求与响应，避免把错误端点/错误事务标记为健康。 */
        internal fun isResponseForQuery(query: ByteArray, response: ByteArray): Boolean {
            if (query.size < 12 || response.size < 12) return false
            if (query[0] != response[0] || query[1] != response[1]) return false
            if ((response[2].toInt() and 0x80) == 0) return false // QR=response
            return (query[2].toInt() and 0x78) == (response[2].toInt() and 0x78) // opcode
        }

        /** 本实现只解析 RFC 8484 wire media type；其他未来 DNS media type 必须显式实现后才能接收。 */
        internal fun hasDnsMessageContentType(bytes: ByteArray): Boolean {
            val headerEnd = indexOfDoubleCrLf(bytes) ?: return false
            val head = String(bytes, 0, headerEnd, Charsets.US_ASCII)
            val value = head.split("\r\n").drop(1).firstNotNullOfOrNull { line ->
                val index = line.indexOf(':')
                if (index <= 0 || !line.substring(0, index).trim().equals("content-type", true)) {
                    null
                } else {
                    line.substring(index + 1).substringBefore(';').trim()
                }
            }
            return value.equals("application/dns-message", ignoreCase = true)
        }

        private fun parseStatusLine(line: String): Int? {
            val fields = line.split(' ', limit = 3)
            if (fields.firstOrNull() != "HTTP/1.1" && fields.firstOrNull() != "HTTP/1.0") return null
            val code = fields.getOrNull(1)?.toIntOrNull() ?: return null
            return if (code in 100..599) code else null
        }

        private fun indexOfDoubleCrLf(bytes: ByteArray): Int? {
            var i = 0
            while (i + 3 < bytes.size) {
                if (bytes[i] == 0x0D.toByte() && bytes[i + 1] == 0x0A.toByte() &&
                    bytes[i + 2] == 0x0D.toByte() && bytes[i + 3] == 0x0A.toByte()
                ) {
                    return i
                }
                i++
            }
            return null
        }

        private const val MAX_HTTP_RESPONSE_BYTES = 128 * 1024
    }
}

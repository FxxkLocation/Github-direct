package org.xiyu.githubdirect.core.dns

import org.xiyu.githubdirect.core.data.ResolvedIps
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.VirtualIpPool
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.DomainPolicy
import org.xiyu.githubdirect.core.rules.ResolverPolicy
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.TransportPolicy

/**
 * 选择性 DNS 引擎（Phase 2 核心，设计 §25）。
 *
 * 决策流：
 * 1. parseDnsQuery 失败 → null（调用方回 SERVFAIL 或丢弃）
 * 2. normalize 失败 → rawForward（不能破坏）
 * 3. registry.match 未命中 → 所有 QTYPE rawForward，保证非目标域响应语义不变
 * 4. 命中 → handleTarget：NXDOMAIN / aaaaSuppress→NODATA / relay A→vIP 合成、
 *    relay AAAA→严格 DoH 的真实 IPv6 /
 *    CLEAN_DNS A|AAAA→JSON DoH 真实 IP / HTTPS/SVCB→严格 Wire DoH（失败时 NODATA）/
 *    其余 qtype rawForward
 * 5. 错误语义（§29）：合成路径失败 → SERVFAIL（内部错误）；raw 转发失败 → null（调用方回 SERVFAIL）；
 *    绝不把失败变成 NXDOMAIN；上游 RCode 原样保留（raw 转发天然满足）。
 *
 * 纯 JVM，无 android.* 依赖；网络 I/O 全部经注入的 wire/plain 客户端。
 */
class SelectiveDnsEngine @JvmOverloads constructor(
    private val registry: RuleRegistry,
    private val resolver: EndpointResolver,     // JSON DoH，A/AAAA 合成用
    private val cache: EndpointCache,
    private val pool: VirtualIpPool,
    private val relayTable: RelayIpTable,
    private val wire: WireDohClient,
    private val plain: PlainDnsClient,
    /** 额外 raw 上游（TCP/53 变体，可注入便于测试）。 */
    private val rawUpstreamTcp: (ByteArray) -> ByteArray? = { raw -> plain.queryTcp(raw) },
) {

    private val dnsTtlSec = 300
    private val wireTimeoutMs = 3000
    private val plainTimeoutMs = 3000

    /**
     * 入 raw DNS query 字节（>=12），出 raw DNS response 字节。
     * 内部解析失败/无法处理 → null（调用方回 SERVFAIL 或丢弃）。
     */
    fun handleQuery(raw: ByteArray): ByteArray? {
        val question = DnsPacketCodec.parseDnsQuery(raw) ?: return null
        val domain = DnsNames.normalize(question.domain)
        if (domain == null) return rawForward(raw) // 不能破坏：原样转发
        val match = registry.match(domain)
        if (match == null) return rawForward(raw)
        return handleTarget(question, raw, match.policy)
    }

    /** 目标域合成路径（原 VpnDnsHandler 逻辑迁移+修正）。 */
    private fun handleTarget(question: DnsQuestion, raw: ByteArray, policy: DomainPolicy): ByteArray? {
        val domain = DnsNames.normalize(question.domain) ?: return rawForward(raw)

        // NXDOMAIN 屏蔽域（block 支配 allow 由 RuleRegistry 仲裁完成）
        if (policy.transport == TransportPolicy.NXDOMAIN) {
            return DnsPacketCodec.buildNxdomainResponse(raw)
        }

        // AAAA 抑制（profile/规则级 flag）→ NODATA，绝不 NXDOMAIN
        if (policy.aaaaSuppress && question.qtype == 28) {
            return DnsPacketCodec.buildNodataResponse(raw, question.questionEnd)
        }

        return when (policy.transport) {
            TransportPolicy.CLEAN_DNS -> handleCleanDns(question, raw, domain, policy)
            TransportPolicy.DIRECT_IP, TransportPolicy.TLS_FRAGMENT_RELAY ->
                handleRelay(question, raw, domain, policy)
            TransportPolicy.PASSTHROUGH, TransportPolicy.NXDOMAIN -> rawForward(raw)
        }
    }

    /**
     * relay 域：A 查询 → 先取真实 IP 再分配 vIP（不变式 2）；AAAA 查询在未抑制时
     * 由严格 DoH/已验证候选返回真实 IPv6（无 IPv6 vIP NAT）；
     * HTTPS/SVCB → NODATA（Chrome 会立刻改走 A + TCP 443，这才进得了分片中继）；
     * 其它非 A → rawForward。
     */
    private fun handleRelay(q: DnsQuestion, raw: ByteArray, domain: String, policy: DomainPolicy): ByteArray? {
        if (q.qtype == QTYPE_HTTPS || q.qtype == QTYPE_SVCB) {
            return DnsPacketCodec.buildNodataResponse(raw, q.questionEnd)
        }
        if (q.qtype == 28) {
            val addresses = resolveRelayIpv6(domain, policy)
                ?: return DnsPacketCodec.buildServFailResponse(raw)
            if (addresses.isEmpty()) return DnsPacketCodec.buildNodataResponse(raw, q.questionEnd)
            return DnsPacketCodec.buildDnsResponse(raw, q.questionEnd, addresses, 28, dnsTtlSec)
                ?: DnsPacketCodec.buildServFailResponse(raw)
        }
        if (q.qtype != 1) return rawForward(raw)

        val realIp = resolveRelayRealIp(domain, policy)
        if (realIp == null) {
            return DnsPacketCodec.buildServFailResponse(raw)
        }

        val vip = pool.allocate(domain, realIp, null)
        if (vip < 0) {
            return DnsPacketCodec.buildServFailResponse(raw) // 池满
        }

        val vipBytes = IpAddresses.intToIpv4(vip)
        return DnsPacketCodec.buildDnsResponse(raw, q.questionEnd, listOf(vipBytes), 1, dnsTtlSec)
            ?: DnsPacketCodec.buildServFailResponse(raw)
    }

    /** 真实 IP 链：fixedIp → 已验证 relayTable → DoH（缓存 + single-flight）。 */
    private fun resolveRelayRealIp(domain: String, policy: DomainPolicy): ByteArray? {
        if (policy.fixedIp != null) {
            return IpAddresses.parseIpv4(policy.fixedIp)
        }
        relayTable.firstIpv4(domain)?.let(IpAddresses::parseIpv4)?.let { return it }
        when (policy.resolver) {
            ResolverPolicy.PROVIDER_ONLY -> {
                return null
            }
            else -> Unit
        }
        return resolveViaDoh(domain, policy)?.v4?.firstOrNull()
    }

    private fun resolveRelayIpv6(domain: String, policy: DomainPolicy): List<ByteArray>? {
        policy.fixedIp?.let { fixed ->
            IpAddresses.parseIpv6(fixed)?.let { return listOf(it) }
        }
        val candidates = relayTable.lookup(domain).orEmpty().mapNotNull(IpAddresses::parseIpv6)
        if (candidates.isNotEmpty()) return candidates
        if (policy.resolver == ResolverPolicy.PROVIDER_ONLY) return emptyList()
        return resolveViaDoh(domain, policy)?.v6
    }

    /**
     * CLEAN_DNS：
     * - A/AAAA → JSON DoH 真实 IP（CIDR 过滤）；
     * - HTTPS/SVCB → 严格 Wire DoH 原样响应，让原生 ECH/H3 能力留在纯直连路径；
     * - Wire DoH 不可用时回 NODATA，促使客户端安全降级到已清洗的 A/AAAA，绝不采用明文 DNS 的
     *   HTTPS/SVCB 参数；
     * - 其他 qtype → rawForward。
     *
     * 需要候选中继/ClientHello 分片的 DIRECT_IP/TLS_FRAGMENT_RELAY 仍在 [handleRelay] 中抑制
     * HTTPS/SVCB，避免客户端先生成无法按真实 SNI 分类的 ECH/QUIC 流量。
     */
    private fun handleCleanDns(q: DnsQuestion, raw: ByteArray, domain: String, policy: DomainPolicy): ByteArray? {
        if (q.qtype == QTYPE_HTTPS || q.qtype == QTYPE_SVCB) {
            return wire.post(raw, wireTimeoutMs)
                ?: DnsPacketCodec.buildNodataResponse(raw, q.questionEnd)
        }
        if (q.qtype != 1 && q.qtype != 28) return rawForward(raw)

        val ips = resolveCleanIps(domain, policy, q.qtype)
        if (ips == null) {
            return DnsPacketCodec.buildServFailResponse(raw)
        }
        val addrs = when (q.qtype) {
            1 -> ips.v4
            28 -> ips.v6
            else -> emptyList()
        }
        if (addrs.isEmpty()) {
            return DnsPacketCodec.buildNodataResponse(raw, q.questionEnd)
        }
        return DnsPacketCodec.buildDnsResponse(raw, q.questionEnd, addrs, q.qtype, dnsTtlSec)
            ?: DnsPacketCodec.buildServFailResponse(raw)
    }

    private fun resolveCleanIps(domain: String, policy: DomainPolicy, qtype: Int): ResolvedIps? {
        val tableIps = relayTable.lookup(domain)
        if (!tableIps.isNullOrEmpty()) {
            val v4 = tableIps.mapNotNull { IpAddresses.parseIpv4(it) }
            val v6 = tableIps.mapNotNull { IpAddresses.parseIpv6(it) }
            if (qtype == 1 && v4.isNotEmpty() || qtype == 28 && v6.isNotEmpty()) {
                return ResolvedIps(v4, v6)
            }
        }
        if (policy.resolver == ResolverPolicy.PROVIDER_ONLY) return ResolvedIps(emptyList(), emptyList())
        return resolveViaDoh(domain, policy)
    }

    private fun resolveViaDoh(domain: String, policy: DomainPolicy): ResolvedIps? {
        val resolved = cache.resolve(domain) { d -> resolver.resolve(d, policy.cidr) } ?: return null
        // 精确域、短 TTL、仅内存：供同一次页面加载竞速多个实时地址，不提升为持久可信候选。
        relayTable.observeResolution(
            domain,
            (resolved.v4 + resolved.v6).map { raw ->
                if (raw.size == 4) IpAddresses.ipv4ToString(raw) else IpAddresses.ipv6ToString(raw)
            },
            ttlMs = dnsTtlSec * 1_000L,
        )
        return resolved
    }

    /**
     * 非目标/无法合成：raw 字节原样转发。wire DoH（对冲，~3s 有界）优先 → 明文 UDP 回退。
     * 自身发出的 DoH/UDP 流量按设计已被 iptables owner 排除（Root）或走物理网（VPN split tunnel）。
     */
    private fun rawForward(raw: ByteArray): ByteArray? {
        wire.post(raw, wireTimeoutMs)?.let { return it }
        return plain.query(raw, plainTimeoutMs)
    }

    companion object {
        private const val QTYPE_SVCB = 64
        private const val QTYPE_HTTPS = 65
    }
}

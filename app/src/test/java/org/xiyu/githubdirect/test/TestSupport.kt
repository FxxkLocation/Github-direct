package org.xiyu.githubdirect.test

import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.data.ScopeDefaults
import org.xiyu.githubdirect.core.data.Nat64FallbackConfig
import org.xiyu.githubdirect.core.dns.DnsPacketCodec
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode
import org.xiyu.githubdirect.core.rules.IndexedRule
import org.xiyu.githubdirect.core.rules.MatcherIndex
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.ServiceProfile
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/** 内存版 SettingsStore（测试用）。 */
class InMemorySettingsStore : SettingsStore {
    private val enabled = ConcurrentHashMap<String, Boolean>()
    private val hosts = ConcurrentHashMap<String, Pair<String, Long>>()

    private var backendMode: BackendMode = BackendMode.AUTO
    private var scopeMode: AppScopeMode = ScopeDefaults.MODE
    private var scopePackages: Set<String> = ScopeDefaults.PACKAGES
    private var embeddedTlsPackages: Set<String> = emptySet()
    private var adaptiveCandidates = true
    private var realIpRedirect = true
    private var tlsFragmentV2 = true
    private var tlsTermination = false
    private var nat64Fallback = Nat64FallbackConfig.DISABLED

    override fun isServiceEnabled(id: String, default: Boolean): Boolean = enabled[id] ?: default

    override fun setServiceEnabled(id: String, enabled: Boolean) {
        this.enabled[id] = enabled
    }

    override fun isDiagEnabled(): Boolean = false

    override fun setDiagEnabled(v: Boolean) {
    }

    override fun hostsData(providerId: String): Pair<String, Long>? = hosts[providerId]

    override fun saveHostsData(providerId: String, data: String, lastSync: Long) {
        hosts[providerId] = data to lastSync
    }

    override fun backendMode(): BackendMode = backendMode

    override fun setBackendMode(mode: BackendMode) {
        backendMode = mode
    }

    override fun appScopeMode(): AppScopeMode = scopeMode

    override fun setAppScopeMode(mode: AppScopeMode) {
        scopeMode = mode
    }

    override fun scopedPackages(): Set<String> = LinkedHashSet(scopePackages)

    override fun setScopedPackages(packages: Set<String>) {
        scopePackages = LinkedHashSet(packages)
    }

    override fun embeddedTlsCapturePackages(): Set<String> = LinkedHashSet(embeddedTlsPackages)

    override fun setEmbeddedTlsCapturePackages(packages: Set<String>) {
        embeddedTlsPackages = LinkedHashSet(packages)
    }

    override fun isAdaptiveCandidatesEnabled(): Boolean = adaptiveCandidates

    override fun setAdaptiveCandidatesEnabled(enabled: Boolean) {
        adaptiveCandidates = enabled
    }

    override fun isRealIpRedirectEnabled(): Boolean = realIpRedirect

    override fun setRealIpRedirectEnabled(enabled: Boolean) {
        realIpRedirect = enabled
    }

    override fun isTlsFragmentV2Enabled(): Boolean = tlsFragmentV2

    override fun setTlsFragmentV2Enabled(enabled: Boolean) {
        tlsFragmentV2 = enabled
    }

    override fun isTlsTerminationEnabled(): Boolean = tlsTermination

    override fun setTlsTerminationEnabled(enabled: Boolean) {
        tlsTermination = enabled
    }

    override fun nat64FallbackConfig(): Nat64FallbackConfig = nat64Fallback.copy()

    override fun setNat64FallbackConfig(config: Nat64FallbackConfig) {
        nat64Fallback = config.normalized().copy()
    }
}

/** 假 NetworkBinder：responder 按 URL 返回响应体，null = 网络失败。 */
class FakeBinder(private val responder: (String) -> String?) : NetworkBinder {
    override var protect: ((Socket) -> Boolean)? = null

    override fun httpGet(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): String? =
        responder(url)

    override fun bindSocket(socket: Socket) {
    }
}

/** 标准 DoH 假响应：A 查询返回 v4，AAAA 查询返回 v6。 */
fun dohResponder(v4: String = "140.82.112.3", v6: String = "2606:50c0::1"): (String) -> String? {
    return { url ->
        if (url.contains("type=AAAA")) {
            """{"Status":0,"Answer":[{"type":28,"data":"$v6"}]}"""
        } else {
            """{"Status":0,"Answer":[{"type":1,"data":"$v4"}]}"""
        }
    }
}

/** 从 profiles 构建 RuleRegistry + MatcherIndex（全部 enabledByDefault 生效）。 */
fun buildRegistry(store: SettingsStore, vararg profiles: ServiceProfile): RuleRegistry {
    val index = MatcherIndex()
    for (p in profiles) {
        for (r in p.domains) {
            index.add(IndexedRule(r, p.id, p.priority))
        }
    }
    index.build()
    return RuleRegistry(store, profiles.associateBy { it.id }, index)
}

/** 构造完整 DNS 查询 IP 包（20 字节 IPv4 头 + 8 字节 UDP 头 + DNS 查询）。 */
fun buildDnsQueryPacket(domain: String, qtype: Int, id: Int = 0x1234): ByteArray {
    val qname = ByteArrayOutputStream().apply {
        for (label in domain.split(".")) {
            write(label.length)
            write(label.toByteArray(Charsets.US_ASCII))
        }
        write(0)
    }.toByteArray()

    val dns = ByteArrayOutputStream().apply {
        write(id ushr 8); write(id and 0xFF)
        write(0x01); write(0x00) // RD
        write(0); write(1)       // QDCOUNT=1
        write(0); write(0)       // ANCOUNT=0
        write(0); write(0)       // NSCOUNT=0
        write(0); write(0)       // ARCOUNT=0
        write(qname)
        write(qtype ushr 8); write(qtype and 0xFF)
        write(0); write(1)       // QCLASS=IN
    }.toByteArray()

    val udpLen = 8 + dns.size
    val total = 20 + udpLen
    val pkt = ByteArray(total)
    pkt[0] = 0x45
    pkt[2] = (total ushr 8).toByte(); pkt[3] = total.toByte()
    pkt[9] = 17 // UDP
    pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 2     // src 10.0.0.2
    pkt[16] = 10; pkt[17] = 0; pkt[18] = 0; pkt[19] = 53    // dst 10.0.0.53
    // UDP header: src port 12345 → dst port 53
    pkt[20] = (12345 ushr 8).toByte(); pkt[21] = 12345.toByte()
    pkt[22] = 0; pkt[23] = 53
    pkt[24] = (udpLen ushr 8).toByte(); pkt[25] = udpLen.toByte()
    pkt[26] = 0; pkt[27] = 0
    System.arraycopy(dns, 0, pkt, 28, dns.size)
    return pkt
}

/** 从响应 IP 包中提取 DNS payload（固定 20 字节 IPv4 头 + 8 字节 UDP 头）。 */
fun extractDnsResponse(pkt: ByteArray): ByteArray {
    val udpLen = DnsPacketCodec.readU16(pkt, 24)
    return pkt.copyOfRange(28, 28 + udpLen - 8)
}

/** 从 DNS 响应取 RCODE（低 4 位）。 */
fun dnsRcode(resp: ByteArray): Int = resp[3].toInt() and 0x0F

/** ANCOUNT。 */
fun dnsAncount(resp: ByteArray): Int = DnsPacketCodec.readU16(resp, 6)

/** 第一条 A 记录的 RDATA 起点（questionEnd 之后 12 字节）。 */
fun answerRdata(resp: ByteArray, questionEnd: Int): ByteArray =
    resp.copyOfRange(questionEnd + 12, questionEnd + 16)

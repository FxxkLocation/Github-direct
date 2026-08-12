package org.xiyu.githubdirect.vpn

import org.xiyu.githubdirect.core.dns.DnsPacketCodec
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.PlainDnsClient
import org.xiyu.githubdirect.core.dns.SelectiveDnsEngine
import org.xiyu.githubdirect.core.dns.WireDohClient
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.VirtualIpPool
import org.xiyu.githubdirect.core.rules.RuleRegistry

/**
 * VPN DNS 处理薄壳（Phase 2，设计 §25）。
 *
 * 职责只剩：
 * - 解析 UDP/IP 封装（现有 handle 的前半部分）
 * - 调 SelectiveDnsEngine.handleQuery（策略分发全部在引擎）
 * - constructIpPacket 封装回 IP 包
 *
 * 引擎无法处理（解析失败 / 上游全失败）→ SERVFAIL 应答（§29：绝不 NXDOMAIN）。
 * 构造签名向后兼容：未注入引擎时由组件自建（wire/plain 默认端点）。
 */
class VpnDnsHandler @JvmOverloads constructor(
    private val registry: RuleRegistry,
    private val resolver: EndpointResolver,
    private val cache: EndpointCache,
    private val pool: VirtualIpPool,
    private val relayTable: RelayIpTable,
    private val engine: SelectiveDnsEngine? = null,
) {

    private val dnsEngine: SelectiveDnsEngine = engine ?: SelectiveDnsEngine(
        registry, resolver, cache, pool, relayTable, WireDohClient(), PlainDnsClient(),
    )

    /**
     * 入参为完整 IP 包，返回完整 IP 包（含 UDP/DNS 封装）；无法处理返回 null。
     */
    fun handle(packet: ByteArray, ipHeaderLen: Int): ByteArray? {
        if (packet.size < ipHeaderLen + 8 + 12) return null
        val udpLen = DnsPacketCodec.readU16(packet, ipHeaderLen + 4)
        val dnsOffset = ipHeaderLen + 8
        val dnsLen = udpLen - 8
        if (dnsLen < 12 || dnsOffset + dnsLen > packet.size) return null

        val dnsQuery = packet.copyOfRange(dnsOffset, dnsOffset + dnsLen)
        val response = dnsEngine.handleQuery(dnsQuery)
            ?: DnsPacketCodec.buildServFailResponse(dnsQuery)
        return DnsPacketCodec.constructIpPacket(packet, ipHeaderLen, response)
    }
}

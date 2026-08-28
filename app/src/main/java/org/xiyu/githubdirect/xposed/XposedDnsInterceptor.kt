package org.xiyu.githubdirect.xposed

import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.dns.ResolutionDecision
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.ResolverPolicy
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.TransportPolicy

/**
 * Xposed DNS 拦截（设计 §2.3）。
 *
 * 纯 JVM，不依赖 Xposed API（ModuleMain 负责 hook 桥接），可单测。
 *
 * Hook 热路径只读 RelayIpTable / EndpointCache 的不可变快照，绝不执行 DoH、TCP 探测或等待 Future。
 * 缓存尚未就绪时保护性放行，由 Root DNS/透明中继或系统解析继续处理。
 */
class XposedDnsInterceptor(
    private val registry: RuleRegistry,
    private val cache: EndpointCache,
    private val relayTable: RelayIpTable,
) {

    fun decide(host: String?): ResolutionDecision {
        val domain = host?.let { DnsNames.normalize(it) } ?: return ResolutionDecision.Passthrough
        val match = registry.match(domain) ?: return ResolutionDecision.Passthrough
        val policy = match.policy

        when (policy.transport) {
            TransportPolicy.NXDOMAIN -> return ResolutionDecision.Nxdomain
            TransportPolicy.PASSTHROUGH -> return ResolutionDecision.Passthrough
            else -> Unit
        }

        policy.fixedIp?.let { fixed ->
            val raw = IpAddresses.parseIpAddress(fixed)
            if (raw != null && (!policy.aaaaSuppress || raw.size == 4)) {
                return ResolutionDecision.Addresses(listOf(fixed))
            }
        }

        // 模块服务进程发布的是已经过 TLS SNI/系统信任链验证的不可变快照；即使旧 profile
        // 仍标为 DOH，也优先使用该安全缓存，使 Chromium/WebView 的 Java DNS Hook 不需要联网。
        val tableIps = relayTable.lookup(domain)
        if (!tableIps.isNullOrEmpty()) {
            val valid = tableIps.filter { address ->
                val raw = IpAddresses.parseIpAddress(address)
                raw != null && (!policy.aaaaSuppress || raw.size == 4)
            }
            if (valid.isNotEmpty()) {
                return ResolutionDecision.Addresses(valid)
            }
        }
        if (policy.resolver == ResolverPolicy.PROVIDER_ONLY) return ResolutionDecision.Passthrough

        // 只读缓存，不触发 fetch；该类型没有持有任何 resolver，结构上禁止热路径发起网络。
        val resolved = cache.get(domain) ?: return ResolutionDecision.Passthrough
        val v4 = resolved.v4.map { IpAddresses.ipv4ToString(it) }
        val v6 = if (policy.aaaaSuppress) emptyList() else {
            resolved.v6.map { IpAddresses.ipv6ToString(it) }
        }
        val addresses = v4 + v6
        return if (addresses.isEmpty()) {
            ResolutionDecision.Passthrough
        } else {
            ResolutionDecision.Addresses(addresses)
        }
    }

    /**
     * Typed DnsResolver 的 AAAA 语义辅助：匹配规则明确要求 aaaaSuppress 时返回 NODATA。
     * 只查不可变规则索引，不解析网络；NXDOMAIN 仍由 [decide] 优先处理。
     */
    fun shouldSuppressAaaa(host: String?): Boolean {
        val domain = host?.let { DnsNames.normalize(it) } ?: return false
        val policy = registry.match(domain)?.policy ?: return false
        return policy.aaaaSuppress
            && policy.transport != TransportPolicy.NXDOMAIN
            && policy.transport != TransportPolicy.PASSTHROUGH
    }

    /** 旧调用兼容层；新 Hook 应使用 [decide]。 */
    fun resolve(host: String?): List<String>? = when (val decision = decide(host)) {
        ResolutionDecision.Passthrough -> null
        ResolutionDecision.Nxdomain -> emptyList()
        is ResolutionDecision.Addresses -> decision.addresses
    }
}

package org.xiyu.githubdirect.xposed

import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.IpAddresses
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
 * 语义：
 * - normalize 失败 / 未命中启用规则 / PASSTHROUGH → null（不拦截，chain.proceed()）
 * - NXDOMAIN 屏蔽域 → emptyList（调用方返回空数组，令解析失败/屏蔽）
 * - 其余命中 → 统一 CLEAN_DNS 语义：真实 IP + CIDR 过滤，走 EndpointCache
 *   （PROVIDER_FIRST/PROVIDER_ONLY 先查 hosts 表；全失败 → null 放行，Xposed 下解析照常）
 */
class XposedDnsInterceptor(
    private val registry: RuleRegistry,
    private val resolver: EndpointResolver,
    private val cache: EndpointCache,
    private val relayTable: RelayIpTable,
) {

    /** 返回 IP 字符串列表；null = 不拦截；emptyList = NX 屏蔽。 */
    fun resolve(host: String?): List<String>? {
        val domain = host?.let { DnsNames.normalize(it) } ?: return null
        val match = registry.match(domain) ?: return null
        val policy = match.policy

        when (policy.transport) {
            TransportPolicy.NXDOMAIN -> return emptyList()
            TransportPolicy.PASSTHROUGH -> return null
            else -> { /* 其余统一 CLEAN_DNS 语义 */ }
        }

        // providers 链（Xposed 进程未启动 hosts 同步，表为空时自然落到 DoH）
        if (policy.resolver == ResolverPolicy.PROVIDER_FIRST
            || policy.resolver == ResolverPolicy.PROVIDER_ONLY
        ) {
            val tableIps = relayTable.lookup(domain)
            if (!tableIps.isNullOrEmpty()) {
                val v4 = tableIps.mapNotNull { IpAddresses.parseIpv4(it) }
                if (v4.isNotEmpty()) {
                    return v4.map { IpAddresses.ipv4ToString(it) }
                }
            }
        }

        val resolved = cache.resolve(domain) { d -> resolver.resolve(d, policy.cidr) }
            ?: return null
        val v4 = resolved.v4.map { IpAddresses.ipv4ToString(it) }
        val v6 = resolved.v6.map { IpAddresses.ipv6ToString(it) }
        if (v4.isEmpty() && v6.isEmpty()) return null
        return v4 + v6
    }
}

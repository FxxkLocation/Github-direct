package org.xiyu.githubdirect.core.rules

import org.xiyu.githubdirect.core.dns.CidrFilter

/**
 * 单条域名规则。
 *
 * - matcher      : 匹配器（ExactMatcher | SuffixMatcher）
 * - transport    : 传输策略
 * - resolver     : IP 来源策略（默认 DOH）
 * - aaaaSuppress : null = 继承 profile
 * - fragmentTls  : null = 由 transport 派生（TLS_FRAGMENT_RELAY → true）
 * - cidr         : null = 继承 profile（已编译）
 * - fixedIp      : 固定真实 IP（解析后优先使用，不再 DoH）
 */
data class DomainRule(
    val id: String,
    val matcher: DomainMatcher,
    val transport: TransportPolicy,
    val resolver: ResolverPolicy = ResolverPolicy.DOH,
    val aaaaSuppress: Boolean? = null,
    val fragmentTls: Boolean? = null,
    val cidr: CidrFilter? = null,
    val fixedIp: String? = null,
)

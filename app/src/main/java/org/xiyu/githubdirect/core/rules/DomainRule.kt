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
 * - endpointGroup: SNI/原目的 IP 唯一归类使用的稳定端点组
 * - cidrRef      : 动态 CIDR 集合引用；旧的内联 [cidr] 继续兼容
 * - candidatePool: 允许同 endpointGroup 共享“已验证 IP 种子”；每个目标域仍须独立 TLS 验证
 * - echConfigDomain: 可选 ECH 公共配置名；只声明预检策略，不携带固定上游地址
 * - nat64FallbackEligible: 该规则是否允许进入用户显式开启的第三方 NAT64 ECH 兜底
 * - semanticProbe: 可选 HTTPS 业务探测；避免证书兼容但虚拟主机返回错误内容的 CDN 地址
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
    val endpointGroup: String? = null,
    val cidrRef: String? = null,
    val candidatePool: String? = null,
    val echConfigDomain: String? = null,
    val nat64FallbackEligible: Boolean = false,
    val semanticProbe: HttpSemanticProbePolicy? = null,
)

/**
 * 在已经完成系统信任链与主机名校验的同一 TLS 连接上执行一个有界 HTTP/1.1 GET。
 * 只允许 origin-form 路径，Host 永远由规则域名生成，避免 profile 注入任意目标。
 */
class HttpSemanticProbePolicy private constructor(
    val path: String,
    val statusMin: Int,
    val statusMax: Int,
) {
    fun accepts(status: Int): Boolean = status in statusMin..statusMax

    companion object {
        fun create(path: String, statusMin: Int, statusMax: Int): HttpSemanticProbePolicy? {
            if (path.length !in 1..MAX_PATH_LENGTH || !path.startsWith('/') || path.startsWith("//")) {
                return null
            }
            if ('\\' in path || '#' in path || path.any { it.code !in 0x21..0x7e }) return null
            if (statusMin !in 100..599 || statusMax !in statusMin..599) return null
            return HttpSemanticProbePolicy(path, statusMin, statusMax)
        }

        private const val MAX_PATH_LENGTH = 256
    }
}

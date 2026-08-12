package org.xiyu.githubdirect.core.dns

/**
 * 全局 DoH 服务器配置（基础设施，不进 profile）。
 * 合并原 DnsVpnService.FORWARD_DOH_SERVERS 与 DohResolver.DOH_SERVERS 并去重。
 */
object DoHServers {

    /** 国内 DoH 优先（响应快）；海外作为兜底（核心域名被污染时返回正确 IP）。 */
    val DEFAULT: List<String> = listOf(
        "https://223.5.5.5/dns-query", // Alidns
        "https://1.12.12.12/dns-query", // DNSPod
        "https://120.53.53.53/dns-query", // DNSPod 备用
        "https://1.1.1.1/dns-query", // Cloudflare (海外)
        "https://8.8.8.8/dns-query", // Google (海外)
        "https://9.9.9.9/dns-query", // Quad9 (海外, 不同 Anycast)
    )
}

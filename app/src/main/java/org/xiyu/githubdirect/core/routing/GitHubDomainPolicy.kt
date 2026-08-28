package org.xiyu.githubdirect.core.routing

import org.xiyu.githubdirect.core.rules.DnsNames

/**
 * Root 真实 IP 中继可安全识别的 GitHub SNI 白名单。
 *
 * 这里只决定“是否允许对原目的地址应用 GitHub TLS 分片/候选逻辑”，不会放宽证书校验，
 * 也不会扩大防火墙目标集合。后缀匹配必须经过 DNS 名规范化并要求标签边界。
 */
object GitHubDomainPolicy {
    private val suffixRoots = setOf(
        "github.com",
        "githubusercontent.com",
        "githubassets.com",
        "github.io",
    )

    @JvmStatic
    fun isTrustedSni(rawDomain: String?): Boolean {
        val domain = rawDomain?.let(DnsNames::normalize) ?: return false
        if (domain == "github.blog") return true
        return suffixRoots.any { root -> domain == root || domain.endsWith(".$root") }
    }
}

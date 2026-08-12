package org.xiyu.githubdirect.core.rules

/**
 * 域名匹配器。入参必须是 DnsNames.normalize() 之后的值（小写、无尾点、ASCII punycode）。
 */
interface DomainMatcher {
    fun matches(normalizedDomain: String): Boolean
}

/** 精确匹配。 */
class ExactMatcher(val domain: String) : DomainMatcher {
    override fun matches(normalizedDomain: String): Boolean = normalizedDomain == domain
}

/**
 * 后缀匹配。suffix 必须形如 ".githubusercontent.com"（含前导点 = 显式标签边界，
 * 保证 evilgithub.com 不会命中 ".github.com"）。
 * 语义：匹配子域 + 裸域本身（旧 GithubDomains 特判语义，规则数据由其保证）。
 */
class SuffixMatcher(val suffix: String) : DomainMatcher {
    init {
        require(suffix.startsWith(".") && suffix.length > 1) { "suffix 必须形如 '.example.com'" }
    }

    private val bareDomain: String = suffix.removePrefix(".")

    override fun matches(normalizedDomain: String): Boolean =
        normalizedDomain == bareDomain || normalizedDomain.endsWith(suffix)
}

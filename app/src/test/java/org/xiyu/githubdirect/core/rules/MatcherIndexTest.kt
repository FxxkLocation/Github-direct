package org.xiyu.githubdirect.core.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MatcherIndexTest {

    private fun rule(domain: String, transport: TransportPolicy, serviceId: String = "s") =
        IndexedRule(DomainRule("r-$domain", ExactMatcher(domain), transport), serviceId, 0)

    @Test
    fun `exact命中`() {
        val index = MatcherIndex()
        index.add(rule("github.com", TransportPolicy.CLEAN_DNS))
        index.build()
        assertEquals(1, index.matchAll("github.com").size)
        assertTrue(index.matchAll("api.github.com").isEmpty())
    }

    @Test
    fun `suffix命中子域`() {
        val index = MatcherIndex()
        index.add(IndexedRule(
            DomainRule("s", SuffixMatcher(".github.com"), TransportPolicy.CLEAN_DNS), "s", 0))
        index.build()
        assertEquals(1, index.matchAll("api.github.com").size)
        assertEquals(1, index.matchAll("a.b.github.com").size)
    }

    @Test
    fun `suffix不命中相似域名`() {
        val index = MatcherIndex()
        index.add(IndexedRule(
            DomainRule("s", SuffixMatcher(".github.com"), TransportPolicy.CLEAN_DNS), "s", 0))
        index.build()
        // 反例：evilgithub.com 不以 .github.com 结尾
        assertTrue(index.matchAll("evilgithub.com").isEmpty())
        assertTrue(index.matchAll("github.com.evil.com").isEmpty())
    }

    @Test
    fun `exact与suffix同时命中返回全部`() {
        val index = MatcherIndex()
        index.add(rule("github.com", TransportPolicy.CLEAN_DNS, "a"))
        index.add(IndexedRule(
            DomainRule("s", SuffixMatcher(".github.com"), TransportPolicy.CLEAN_DNS), "b", 0))
        index.build()
        assertEquals(2, index.matchAll("github.com").size)
    }

    @Test
    fun `构建后add被拒绝`() {
        val index = MatcherIndex()
        index.add(rule("github.com", TransportPolicy.CLEAN_DNS))
        index.build()
        try {
            index.add(rule("api.github.com", TransportPolicy.CLEAN_DNS))
            throw AssertionError("add after build 应抛 IllegalStateException")
        } catch (e: IllegalStateException) {
            // expected
        }
    }
}

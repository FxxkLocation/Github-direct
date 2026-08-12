package org.xiyu.githubdirect.xposed

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.SuffixMatcher
import org.xiyu.githubdirect.core.rules.TransportPolicy.CLEAN_DNS
import org.xiyu.githubdirect.core.rules.TransportPolicy.NXDOMAIN
import org.xiyu.githubdirect.test.FakeBinder
import org.xiyu.githubdirect.test.InMemorySettingsStore
import org.xiyu.githubdirect.test.buildRegistry
import org.xiyu.githubdirect.test.dohResponder

/**
 * Xposed 路径验证（设计 §2.3）：NX 域返回空数组（屏蔽），其余统一 CLEAN_DNS 语义。
 */
class XposedDnsInterceptorTest {

    private fun interceptor(responder: (String) -> String?, vararg profiles: ServiceProfile): XposedDnsInterceptor {
        val registry = buildRegistry(InMemorySettingsStore(), *profiles)
        val resolver = EndpointResolver(FakeBinder(responder), servers = listOf("http://fake.doh/"))
        return XposedDnsInterceptor(registry, resolver, EndpointCache(), RelayIpTable())
    }

    private fun profile(id: String, priority: Int = 5, vararg rules: DomainRule) = ServiceProfile(
        id = id,
        displayName = id,
        category = "test",
        enabledByDefault = true,
        priority = priority,
        domains = rules.toList(),
    )

    /** NX 语义：suffix allow 命中 + exact NX 命中 → 返回空数组（屏蔽）。 */
    @Test
    fun `NX域返回空列表`() {
        val it = interceptor(
            dohResponder(),
            profile("ads", 5, DomainRule("nx", ExactMatcher("tracking.example.com"), NXDOMAIN)),
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        val result = it.resolve("tracking.example.com")
        assertTrue(result != null && result.isEmpty())
    }

    @Test
    fun `未命中返回null放行`() {
        val it = interceptor(
            dohResponder(),
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        assertNull(it.resolve("example.org"))
    }

    @Test
    fun `规范化失败的输入放行`() {
        val it = interceptor(
            dohResponder(),
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        assertNull(it.resolve("not a domain!"))
        assertNull(it.resolve(null))
    }

    /** 非 NX 命中：CLEAN_DNS 语义返回真实 IP（走 DoH + 缓存）。 */
    @Test
    fun `CLEAN_DNS命中返回真实IP`() {
        val it = interceptor(
            dohResponder(v4 = "1.2.3.4"),
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        val result = it.resolve("api.example.com")
        // ipv6ToString 契约：冒号分隔、不缩写
        assertEquals(listOf("1.2.3.4", "2606:50c0:0:0:0:0:0:1"), result)
    }

    /** 全部解析失败 → null（Xposed 下解析照常，不阻断）。 */
    @Test
    fun `DoH全失败时放行`() {
        val it = interceptor(
            { null },
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        assertNull(it.resolve("api.example.com"))
    }

    /** 命中但 CIDR 过滤后为空 → 放行。 */
    @Test
    fun `CIDR过滤后为空放行`() {
        val responder: (String) -> String? = {
            """{"Status":0,"Answer":[{"type":1,"data":"8.8.8.8"}]}"""
        }
        val cidr = org.xiyu.githubdirect.core.dns.CidrFilter.parse(listOf("140.82.112.0/24"), emptyList())
        val it = interceptor(
            responder,
            ServiceProfile(
                id = "corp", displayName = "corp", category = "test", enabledByDefault = true,
                priority = 5, cidr = cidr,
                domains = listOf(DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
            ),
        )
        assertNull(it.resolve("api.example.com"))
    }
}

package org.xiyu.githubdirect.xposed

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.data.ResolvedIps
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.SuffixMatcher
import org.xiyu.githubdirect.core.rules.TransportPolicy.CLEAN_DNS
import org.xiyu.githubdirect.core.rules.TransportPolicy.NXDOMAIN
import org.xiyu.githubdirect.core.rules.TransportPolicy.TLS_FRAGMENT_RELAY
import org.xiyu.githubdirect.test.InMemorySettingsStore
import org.xiyu.githubdirect.test.buildRegistry

/**
 * Xposed 路径验证（设计 §2.3）：NX 显式决策、其余只读本地路由表/缓存并保护性放行。
 */
class XposedDnsInterceptorTest {

    private fun interceptor(
        vararg profiles: ServiceProfile,
        cache: EndpointCache = EndpointCache(),
        table: RelayIpTable = RelayIpTable(),
    ): XposedDnsInterceptor {
        val registry = buildRegistry(InMemorySettingsStore(), *profiles)
        return XposedDnsInterceptor(registry, cache, table)
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
            profile("ads", 5, DomainRule("nx", ExactMatcher("tracking.example.com"), NXDOMAIN)),
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        val result = it.resolve("tracking.example.com")
        assertTrue(result != null && result.isEmpty())
    }

    @Test
    fun `未命中返回null放行`() {
        val it = interceptor(
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        assertNull(it.resolve("example.org"))
    }

    @Test
    fun `规范化失败的输入放行`() {
        val it = interceptor(
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        assertNull(it.resolve("not a domain!"))
        assertNull(it.resolve(null))
    }

    /** 非 NX 命中：只读后台已填充的缓存，不在 Hook 热路径发起 DoH。 */
    @Test
    fun `CLEAN_DNS命中返回缓存真实IP`() {
        val cache = EndpointCache()
        cache.resolve("api.example.com") {
            ResolvedIps(
                v4 = listOf(IpAddresses.parseIpv4("1.2.3.4")!!),
                v6 = listOf(IpAddresses.parseIpv6("2606:50c0::1")!!),
            )
        }
        val it = interceptor(
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
            cache = cache,
        )
        val result = it.resolve("api.example.com")
        // ipv6ToString 契约：冒号分隔、不缩写
        assertEquals(listOf("1.2.3.4", "2606:50c0:0:0:0:0:0:1"), result)
    }

    /** 缓存未就绪 → null（Xposed 下调用原解析，不阻断）。 */
    @Test
    fun `缓存未就绪时放行`() {
        val it = interceptor(
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        assertNull(it.resolve("api.example.com"))
    }

    @Test
    fun `旧DOH规则也优先读取服务进程发布的多平台安全快照`() {
        val table = RelayIpTable().apply {
            update(
                mapOf(
                    "chatgpt.com" to listOf("104.18.32.47", "2606:4700:4400::6812:202f"),
                ),
            )
        }
        val interceptor = interceptor(
            profile(
                "openai", 5,
                DomainRule("chatgpt", SuffixMatcher(".chatgpt.com"), TLS_FRAGMENT_RELAY),
            ),
            table = table,
        )
        assertEquals(
            listOf("104.18.32.47", "2606:4700:4400::6812:202f"),
            interceptor.resolve("chatgpt.com"),
        )
    }

    /** 命中但 CIDR 过滤后为空 → 放行。 */
    @Test
    fun `CIDR过滤后为空放行`() {
        val cidr = org.xiyu.githubdirect.core.dns.CidrFilter.parse(listOf("140.82.112.0/24"), emptyList())
        val it = interceptor(
            ServiceProfile(
                id = "corp", displayName = "corp", category = "test", enabledByDefault = true,
                priority = 5, cidr = cidr,
                domains = listOf(DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
            ),
        )
        assertNull(it.resolve("api.example.com"))
    }

    @Test
    fun `typed AAAA命中抑制规则返回NODATA辅助信号`() {
        val it = interceptor(
            ServiceProfile(
                id = "github",
                displayName = "github",
                category = "test",
                enabledByDefault = true,
                priority = 5,
                aaaaSuppress = true,
                domains = listOf(
                    DomainRule("allow", ExactMatcher("github.com"), CLEAN_DNS),
                    DomainRule("block", ExactMatcher("blocked.github.com"), NXDOMAIN),
                ),
            ),
        )

        assertTrue(it.shouldSuppressAaaa("github.com"))
        assertFalse("NXDOMAIN 必须保持更高优先级", it.shouldSuppressAaaa("blocked.github.com"))
        assertFalse(it.shouldSuppressAaaa("example.org"))
    }

    @Test
    fun `AAAA抑制同时过滤普通Hook与合并地址查询中的IPv6`() {
        val cache = EndpointCache()
        cache.resolve("github.com") {
            ResolvedIps(
                v4 = listOf(IpAddresses.parseIpv4("140.82.112.4")!!),
                v6 = listOf(IpAddresses.parseIpv6("2606:50c0::1")!!),
            )
        }
        val interceptor = interceptor(
            ServiceProfile(
                id = "github",
                displayName = "github",
                category = "test",
                enabledByDefault = true,
                aaaaSuppress = true,
                domains = listOf(DomainRule("allow", ExactMatcher("github.com"), CLEAN_DNS)),
            ),
            cache = cache,
        )

        assertEquals(listOf("140.82.112.4"), interceptor.resolve("github.com"))
    }

    @Test
    fun `缓存Hook热路径P95低于10毫秒`() {
        val cache = EndpointCache()
        cache.resolve("api.example.com") {
            ResolvedIps(v4 = listOf(IpAddresses.parseIpv4("1.2.3.4")!!), v6 = emptyList())
        }
        val interceptor = interceptor(
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
            cache = cache,
        )
        repeat(500) { interceptor.decide("api.example.com") }
        val samples = LongArray(5_000)
        for (i in samples.indices) {
            val start = System.nanoTime()
            interceptor.decide("api.example.com")
            samples[i] = System.nanoTime() - start
        }
        samples.sort()
        val p95 = samples[(samples.size * 95) / 100]
        assertTrue("P95=${p95 / 1_000_000.0}ms", p95 < 10_000_000L)
    }
}

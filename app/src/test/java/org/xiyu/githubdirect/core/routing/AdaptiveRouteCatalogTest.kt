package org.xiyu.githubdirect.core.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.HttpSemanticProbePolicy
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.SuffixMatcher
import org.xiyu.githubdirect.core.rules.TransportPolicy

class AdaptiveRouteCatalogTest {

    private fun profile(id: String, vararg rules: DomainRule) = ServiceProfile(
        id = id,
        displayName = id,
        category = "test",
        enabledByDefault = false,
        domains = rules.toList(),
    )

    @Test
    fun `只从启用服务生成目标且后缀候选不跨SNI复用`() {
        val profiles = listOf(
            profile(
                "google",
                DomainRule("exact", ExactMatcher("google.com"), TransportPolicy.TLS_FRAGMENT_RELAY),
                DomainRule("suffix", SuffixMatcher(".google.com"), TransportPolicy.TLS_FRAGMENT_RELAY),
            ),
            profile(
                "openai",
                DomainRule(
                    "chatgpt",
                    SuffixMatcher(".chatgpt.com"),
                    TransportPolicy.TLS_FRAGMENT_RELAY,
                    echConfigDomain = "cloudflare-ech.com",
                ),
            ),
        )
        val targets = AdaptiveRouteCatalog.fromProfiles(profiles) { it == "openai" }
        assertEquals(listOf("chatgpt.com"), targets.map { it.domain })
        assertFalse(targets.single().includeSubdomains)
        assertEquals("openai:chatgpt.com", targets.single().endpointGroup)
        assertEquals("ghd-probe.chatgpt.com", targets.single().probeDomain)
        assertEquals("cloudflare-ech.com", targets.single().echConfigDomain)
    }

    @Test
    fun `同域exact与suffix去重且保持精确候选边界`() {
        val targets = AdaptiveRouteCatalog.fromProfiles(
            listOf(
                profile(
                    "google",
                    DomainRule("exact", ExactMatcher("google.com"), TransportPolicy.CLEAN_DNS),
                    DomainRule("suffix", SuffixMatcher(".google.com"), TransportPolicy.TLS_FRAGMENT_RELAY),
                ),
            ),
        ) { true }
        assertEquals(1, targets.size)
        assertFalse(targets.single().includeSubdomains)
        assertEquals("ghd-probe.google.com", targets.single().probeDomain)
    }

    @Test
    fun `规则显式候选池进入目标但不扩大后缀复用边界`() {
        val semantic = requireNotNull(HttpSemanticProbePolicy.create("/", 200, 399))
        val targets = AdaptiveRouteCatalog.fromProfiles(
            listOf(
                profile(
                    "youtube",
                    DomainRule(
                        "web",
                        ExactMatcher("www.youtube.com"),
                        TransportPolicy.TLS_FRAGMENT_RELAY,
                        candidatePool = "google-edge",
                        semanticProbe = semantic,
                    ),
                ),
            ),
        ) { true }

        assertEquals("google-edge", targets.single().candidatePool)
        assertFalse(targets.single().includeSubdomains)
        assertEquals("www.youtube.com", targets.single().probeDomain)
        assertEquals("/", targets.single().semanticProbe?.path)
    }

    @Test
    fun `前置SNI生成优先控制面锚点但不扩大业务规则`() {
        val targets = AdaptiveRouteCatalog.fromProfiles(
            listOf(
                profile(
                    "youtube",
                    DomainRule(
                        "images",
                        SuffixMatcher(".ytimg.com"),
                        TransportPolicy.TLS_FRAGMENT_RELAY,
                        candidatePool = "google-edge",
                        tlsFrontSni = "g.cn",
                        nat64FallbackEligible = true,
                    ),
                ),
            ),
        ) { true }

        assertEquals(listOf("g.cn", "ytimg.com"), targets.map { it.domain })
        val anchor = targets.first()
        assertEquals("front-sni:g.cn", anchor.endpointGroup)
        assertEquals("g.cn", anchor.probeDomain)
        assertEquals("google-edge", anchor.candidatePool)
        assertFalse(anchor.includeSubdomains)
    }

    @Test
    fun `NXDOMAIN与PASSTHROUGH不扩大真实IP防火墙目标`() {
        val targets = AdaptiveRouteCatalog.fromProfiles(
            listOf(
                profile(
                    "mixed",
                    DomainRule("blocked", SuffixMatcher(".blocked.example"), TransportPolicy.NXDOMAIN),
                    DomainRule("pass", SuffixMatcher(".pass.example"), TransportPolicy.PASSTHROUGH),
                    DomainRule("direct", SuffixMatcher(".direct.example"), TransportPolicy.DIRECT_IP),
                ),
            ),
        ) { true }
        assertEquals(listOf("direct.example"), targets.map { it.domain })
    }

    @Test
    fun `禁用GitHub时过滤旧计划并清除GitHub Meta CIDR`() {
        val snapshot = RouteSnapshot(
            generation = 9,
            createdAt = 1,
            expiresAt = 0,
            plans = mapOf(
                "github.com" to EndpointPlan("github.com", "web", candidates = emptyList()),
                "chatgpt.com" to EndpointPlan("chatgpt.com", "chatgpt", true, emptyList()),
            ),
            metaCidrs = setOf("140.82.112.0/20"),
        )
        val filtered = AdaptiveRouteCatalog.filterSnapshot(
            snapshot,
            listOf(AdaptiveRouteTarget("openai", "chatgpt.com", "chatgpt", false)),
            generation = 10,
        )
        assertEquals(10, filtered.generation)
        assertEquals(setOf("chatgpt.com"), filtered.plans.keys)
        assertTrue(filtered.metaCidrs.isEmpty())
        assertTrue(filtered.planFor("sub.chatgpt.com") == null)
    }
}

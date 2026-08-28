package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.rules.IndexedRule
import org.xiyu.githubdirect.core.rules.MatcherIndex
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.TransportPolicy
import org.xiyu.githubdirect.core.rules.VerifyStatus
import java.io.File

/**
 * profiles.json 资产 golden 测试（Agent G 审查 C 节缺口）。
 * 单元测试 cwd = 模块目录（app/），直接读 src/main/assets。
 * 断言不依赖具体域名数据（数据变动时通过枚举规则动态验证，不硬编码域名）。
 */
class RuleCatalogGoldenTest {

    private fun loadCatalog(): Map<String, org.xiyu.githubdirect.core.rules.ServiceProfile> {
        val f = File("src/main/assets/rules/profiles.json")
        assertTrue("profiles.json 资产缺失: ${f.absolutePath}", f.exists())
        val profiles = RuleCatalog.load(f.readText(Charsets.UTF_8))
        assertTrue("profiles.json 解析为空", profiles.isNotEmpty())
        return profiles
    }

    private fun buildRegistry(
        profiles: Map<String, org.xiyu.githubdirect.core.rules.ServiceProfile>,
    ): RuleRegistry {
        val index = MatcherIndex()
        for (p in profiles.values) {
            for (r in p.domains) {
                index.add(IndexedRule(r, p.id, p.priority))
            }
        }
        index.build()
        val settings = object : SettingsStore {
            private val map = HashMap<String, Boolean>()
            // golden 测试默认启用全部服务（真实默认值由 enabledByDefault 决定，此处显式全开以测规则行为）
            override fun isServiceEnabled(id: String, default: Boolean): Boolean =
                map[id] ?: true
            override fun setServiceEnabled(id: String, enabled: Boolean) { map[id] = enabled }
            override fun isDiagEnabled(): Boolean = false
            override fun setDiagEnabled(v: Boolean) {}
            override fun hostsData(providerId: String): Pair<String, Long>? = null
            override fun saveHostsData(providerId: String, data: String, lastSync: Long) {}
            override fun backendMode(): org.xiyu.githubdirect.core.rules.BackendMode =
                org.xiyu.githubdirect.core.rules.BackendMode.AUTO
            override fun setBackendMode(mode: org.xiyu.githubdirect.core.rules.BackendMode) {}
            override fun appScopeMode(): org.xiyu.githubdirect.core.rules.AppScopeMode =
                org.xiyu.githubdirect.core.rules.AppScopeMode.ALL_APPS
            override fun setAppScopeMode(mode: org.xiyu.githubdirect.core.rules.AppScopeMode) {}
            override fun scopedPackages(): Set<String> = emptySet()
            override fun setScopedPackages(packages: Set<String>) {}
        }
        return RuleRegistry(settings, profiles, index)
    }

    @Test
    fun `profile 目录结构完整且 id 唯一`() {
        val profiles = loadCatalog()
        assertTrue("至少 60 个 profile", profiles.size >= 60)
        // id 唯一由 Map 保证；校验非空 displayName 与至少 1 条规则
        for (p in profiles.values) {
            assertTrue("profile ${p.id} displayName 为空", p.displayName.isNotBlank())
            assertTrue("profile ${p.id} 无规则", p.domains.isNotEmpty())
        }
    }

    @Test
    fun `github 为回归基线：默认启用、VERIFIED、高优先级、带 CIDR 与 provider`() {
        val profiles = loadCatalog()
        val github = profiles["github"]
        assertNotNull("github profile 缺失", github)
        github!!
        assertTrue("github 必须默认启用", github.enabledByDefault)
        assertEquals(VerifyStatus.VERIFIED, github.verifyStatus)
        assertEquals("github priority 必须为 10", 10, github.priority)
        assertNotNull("github 必须带 CIDR 白名单", github.cidr)
        assertTrue(
            "github IPv6 白名单必须包含官方 2a0a:a440::/29",
            github.cidr!!.allowsIpv6(org.xiyu.githubdirect.core.dns.IpAddresses.parseIpv6("2a0a:a447::1")!!),
        )
        assertFalse(
            "github 白名单不得包含 Google 2001:4860::/32",
            github.cidr!!.allowsIpv6(org.xiyu.githubdirect.core.dns.IpAddresses.parseIpv6("2001:4860::1")!!),
        )
        assertTrue("github 必须声明 github-hosts provider", github.providers.any { it.providerId == "github-hosts" })
        val web = github.domains.first { it.id == "github.com" }
        assertEquals("web", web.endpointGroup)
        assertEquals("github-meta", web.cidrRef)
    }

    @Test
    fun `NEEDS_VERIFY 服务不得默认启用`() {
        val profiles = loadCatalog()
        for (p in profiles.values) {
            if (p.verifyStatus == VerifyStatus.NEEDS_VERIFY) {
                assertFalse("NEEDS_VERIFY 服务 ${p.id} 不得默认启用", p.enabledByDefault)
            }
        }
    }

    @Test
    fun `OpenAI官方核心域与WebSocket已建模且默认关闭`() {
        val openai = loadCatalog()["openai"] ?: error("openai profile 缺失")
        assertFalse(openai.enabledByDefault)
        assertEquals(VerifyStatus.NEEDS_VERIFY, openai.verifyStatus)
        assertFalse("OpenAI 流式连接应保留 IPv6", openai.aaaaSuppress)
        val suffixes = openai.domains.mapNotNull { rule ->
            (rule.matcher as? org.xiyu.githubdirect.core.rules.SuffixMatcher)
                ?.suffix?.removePrefix(".")
        }.toSet()
        listOf("openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "oaistatsig.com")
            .forEach { assertTrue("OpenAI 官方核心域缺失: $it", it in suffixes) }
        val echRoots = openai.domains.asSequence()
            .filter { it.echConfigDomain == "cloudflare-ech.com" }
            .mapNotNull { rule ->
                when (val matcher = rule.matcher) {
                    is org.xiyu.githubdirect.core.rules.ExactMatcher -> matcher.domain
                    is org.xiyu.githubdirect.core.rules.SuffixMatcher -> matcher.suffix.removePrefix(".")
                    else -> null
                }
            }
            .toSet()
        listOf("chatgpt.com", "api.openai.com", "ws.chatgpt.com", "oaistatic.com")
            .forEach { assertTrue("OpenAI ECH 预检策略缺失: $it", it in echRoots) }
        val nat64Rules = openai.domains.filter { it.nat64FallbackEligible }
        assertTrue("OpenAI NAT64 资格不得为空", nat64Rules.isNotEmpty())
        assertTrue("NAT64 资格必须同时要求 ECH", nat64Rules.all { it.echConfigDomain != null })
        assertTrue(
            "其他 profile 不得隐式取得第三方 NAT64 资格",
            loadCatalog().filterKeys { it != "openai" }.values
                .flatMap { it.domains }
                .none { it.nat64FallbackEligible },
        )
        assertTrue(openai.idleTimeoutSec >= 86_400)
    }

    @Test
    fun `Google YouTube Discord与OpenAI均保留IPv6且实机验收前保持待验证`() {
        val catalog = loadCatalog()
        val expectedExact = mapOf(
            "youtube" to setOf(
                "www.youtube.com",
                "youtubei.googleapis.com",
                "i.ytimg.com",
                "redirector.googlevideo.com",
            ),
            "google-llc" to setOf(
                "www.google.com",
                "accounts.google.com",
                "play.googleapis.com",
                "www.gstatic.com",
            ),
            "discord" to setOf(
                "gateway.discord.gg",
                "cdn.discordapp.com",
                "media.discordapp.net",
            ),
            "openai" to setOf(
                "api.openai.com",
                "ws.chatgpt.com",
                "android.chat.openai.com",
                "auth.openai.com",
            ),
        )
        for ((id, expected) in expectedExact) {
            val profile = catalog[id] ?: error("$id profile 缺失")
            assertFalse("$id 不得默认启用", profile.enabledByDefault)
            assertEquals("$id 尚未通过当前设备全链路", VerifyStatus.NEEDS_VERIFY, profile.verifyStatus)
            assertFalse("$id 应保留 IPv6", profile.aaaaSuppress)
            val actual = profile.domains.mapNotNull { rule ->
                (rule.matcher as? org.xiyu.githubdirect.core.rules.ExactMatcher)?.domain
            }.toSet()
            assertTrue("$id 缺少精确入口: ${expected - actual}", actual.containsAll(expected))
        }
        assertTrue((catalog["discord"]?.idleTimeoutSec ?: 0) >= 86_400)
        assertTrue((catalog["openai"]?.idleTimeoutSec ?: 0) >= 86_400)
    }

    @Test
    fun `Google与YouTube规则显式加入同池但其他平台不被隐式合并`() {
        val catalog = loadCatalog()
        for (id in listOf("google-llc", "youtube")) {
            val profile = catalog.getValue(id)
            assertTrue(profile.domains.isNotEmpty())
            assertTrue("$id 存在未声明候选池的规则", profile.domains.all {
                it.candidatePool == "google-edge"
            })
        }
        assertTrue(catalog.getValue("discord").domains.all { it.candidatePool == null })
    }

    @Test
    fun `规则引擎端到端：github 域命中 relay 策略、仿冒域不误匹配`() {
        val profiles = loadCatalog()
        val registry = buildRegistry(profiles)

        val m = registry.match("github.com")
        assertNotNull("github.com 必须命中", m)
        assertEquals(TransportPolicy.TLS_FRAGMENT_RELAY, m!!.policy.transport)
        assertEquals("github", m.serviceId)

        // suffix 规则命中子域
        val sub = registry.match("raw.githubusercontent.com")
        assertNotNull("raw.githubusercontent.com 必须命中", sub)
        assertEquals("github", sub!!.serviceId)

        // label 边界：evilgithub.com 不得命中 github.com 的 suffix 规则
        val evil = registry.match("evilgithub.com")
        assertNull("evilgithub.com 不得命中 github 规则", evil)
    }

    @Test
    fun `NXDOMAIN 规则在任何平台数据下都支配 allow 规则`() {
        val profiles = loadCatalog()
        val registry = buildRegistry(profiles)

        // 动态找出所有 NX 规则并逐一验证 match 返回 NXDOMAIN（不硬编码域名）
        var nxCount = 0
        for (p in profiles.values) {
            for (r in p.domains) {
                if (r.transport == TransportPolicy.NXDOMAIN) {
                    nxCount++
                    val domain = when (val matcher = r.matcher) {
                        is org.xiyu.githubdirect.core.rules.ExactMatcher -> matcher.domain
                        is org.xiyu.githubdirect.core.rules.SuffixMatcher ->
                            "tracker" + matcher.suffix // 构造合法子域触发 suffix 匹配
                        else -> error("未知 matcher 类型")
                    }
                    val m = registry.match(domain)
                    assertNotNull("NX 规则 ${p.id}/${r.id} ($domain) 未命中", m)
                    assertEquals("NX 规则 ${p.id}/${r.id} 必须返回 NXDOMAIN（block 支配 allow）",
                        TransportPolicy.NXDOMAIN, m!!.policy.transport)
                }
            }
        }
        assertTrue("规则数据中应存在 NXDOMAIN 规则", nxCount > 0)
    }

    @Test
    fun `fixedIp 规则必须声明 PROVIDER_ONLY 解析策略`() {
        val profiles = loadCatalog()
        for (p in profiles.values) {
            for (r in p.domains) {
                if (r.fixedIp != null) {
                    assertEquals(
                        "fixedIp 规则 ${p.id}/${r.id} 必须用 PROVIDER_ONLY",
                        org.xiyu.githubdirect.core.rules.ResolverPolicy.PROVIDER_ONLY,
                        r.resolver,
                    )
                }
            }
        }
    }

    @Test
    fun `所有规则ID均非空（RuleCatalog 已过滤非法条目）`() {
        val profiles = loadCatalog()
        for (p in profiles.values) {
            for (r in p.domains) {
                assertTrue("规则 ${p.id} 含空 ID", r.id.isNotBlank())
            }
        }
    }
}

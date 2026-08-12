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
        assertTrue("github 必须声明 github-hosts provider", github.providers.any { it.providerId == "github-hosts" })
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
    fun `所有 transport 均属于已知枚举（RuleCatalog 已过滤非法值）`() {
        val profiles = loadCatalog()
        for (p in profiles.values) {
            for (r in p.domains) {
                assertTrue("规则 ${p.id}/${r.id} transport 非法", r.transport != null)
            }
        }
    }
}

package org.xiyu.githubdirect.core.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.test.InMemorySettingsStore
import org.xiyu.githubdirect.test.buildRegistry

/**
 * 仲裁规则测试（含 Agent E 域名验证仲裁需求）：
 * 同 priority 下 NXDOMAIN（block）支配任何其他 transport（block 必须支配 allow），
 * 然后按 priority，再按 profile id 字典序稳定排序。
 */
class RuleRegistryTest {

    private fun profile(id: String, priority: Int = 5, vararg rules: DomainRule) = ServiceProfile(
        id = id,
        displayName = id,
        category = "test",
        enabledByDefault = true,
        priority = priority,
        domains = rules.toList(),
    )

    private fun exactRule(domain: String, transport: TransportPolicy) =
        DomainRule(id = "r-$domain", matcher = ExactMatcher(domain), transport = transport)

    private fun suffixRule(suffix: String, transport: TransportPolicy) =
        DomainRule(id = "r-$suffix", matcher = SuffixMatcher(suffix), transport = transport)

    /** 核心仲裁：suffix allow 命中 + exact NX 命中 → NX 胜出。 */
    @Test
    fun `同priority下NXDOMAIN支配CLEAN_DNS`() {
        val registry = buildRegistry(
            InMemorySettingsStore(),
            profile("ads", 5, exactRule("tracking.example.com", TransportPolicy.NXDOMAIN)),
            profile("corp", 5, suffixRule(".example.com", TransportPolicy.CLEAN_DNS)),
        )
        val match = registry.match("tracking.example.com")
        assertEquals(TransportPolicy.NXDOMAIN, match!!.policy.transport)
        assertEquals("ads", match.serviceId)
    }

    /** 高 priority 非 NX 规则优先于低 priority NX 规则（NX 支配只在同 priority 内）。 */
    @Test
    fun `高priority非NX胜过优先级低的NX`() {
        val registry = buildRegistry(
            InMemorySettingsStore(),
            profile("ads", 5, exactRule("tracking.example.com", TransportPolicy.NXDOMAIN)),
            profile("corp", 10, suffixRule(".example.com", TransportPolicy.CLEAN_DNS)),
        )
        val match = registry.match("tracking.example.com")
        assertEquals(TransportPolicy.CLEAN_DNS, match!!.policy.transport)
        assertEquals("corp", match.serviceId)
    }

    /** 同 priority 同为 NX：profile id 字典序小者胜。 */
    @Test
    fun `同priority同NX按profileId字典序`() {
        val registry = buildRegistry(
            InMemorySettingsStore(),
            profile("zz-block", 5, exactRule("blocked.example.com", TransportPolicy.NXDOMAIN)),
            profile("aa-block", 5, exactRule("blocked.example.com", TransportPolicy.NXDOMAIN)),
        )
        assertEquals("aa-block", registry.match("blocked.example.com")!!.serviceId)
    }

    /** NX 规则被禁用后不参与仲裁 → allow 规则胜出。 */
    @Test
    fun `禁用的NX规则不参与仲裁`() {
        val store = InMemorySettingsStore()
        val registry = buildRegistry(
            store,
            profile("ads", 5, exactRule("tracking.example.com", TransportPolicy.NXDOMAIN)),
            profile("corp", 5, suffixRule(".example.com", TransportPolicy.CLEAN_DNS)),
        )
        registry.setEnabled("ads", false)
        val match = registry.match("tracking.example.com")
        assertEquals(TransportPolicy.CLEAN_DNS, match!!.policy.transport)
        assertEquals("corp", match.serviceId)
    }

    /** 仅 suffix 命中（exact 不命中）→ allow 规则正常返回。 */
    @Test
    fun `纯suffix命中返回allow规则`() {
        val registry = buildRegistry(
            InMemorySettingsStore(),
            profile("ads", 5, exactRule("tracking.example.com", TransportPolicy.NXDOMAIN)),
            profile("corp", 5, suffixRule(".example.com", TransportPolicy.CLEAN_DNS)),
        )
        val match = registry.match("other.example.com")
        assertEquals(TransportPolicy.CLEAN_DNS, match!!.policy.transport)
        assertEquals("corp", match.serviceId)
    }


    @Test
    fun `全部开启关闭批量事件只通知一次`() {
        val store = InMemorySettingsStore()
        val registry = buildRegistry(
            store,
            profile("a", 5, exactRule("a.example.com", TransportPolicy.CLEAN_DNS)),
            profile("b", 5, exactRule("b.example.com", TransportPolicy.CLEAN_DNS)),
        )
        val events = ArrayList<Pair<String, Boolean>>()
        registry.addChangeListener { id, enabled -> events.add(id to enabled) }

        registry.setAllEnabled(false)
        assertTrue(registry.enabledProfiles().isEmpty())
        assertEquals(listOf(RuleRegistry.BATCH_CHANGE_ID to false), events)

        events.clear()
        registry.setAllEnabled(true)
        assertEquals(2, registry.enabledProfiles().size)
        assertEquals(listOf(RuleRegistry.BATCH_CHANGE_ID to true), events)
    }

    @Test
    fun `未命中返回null`() {
        val registry = buildRegistry(
            InMemorySettingsStore(),
            profile("corp", 5, suffixRule(".example.com", TransportPolicy.CLEAN_DNS)),
        )
        assertNull(registry.match("example.org"))
    }
}

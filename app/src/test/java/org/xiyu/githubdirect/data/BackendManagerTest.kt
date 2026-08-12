package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.PlainDnsClient
import org.xiyu.githubdirect.core.dns.SelectiveDnsEngine
import org.xiyu.githubdirect.core.dns.WireDohClient
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.VirtualIpPool
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode
import org.xiyu.githubdirect.core.rules.MatcherIndex
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.root.BackendState
import org.xiyu.githubdirect.root.CapabilityProber
import org.xiyu.githubdirect.root.FirewallRules
import org.xiyu.githubdirect.root.RootCapabilities
import org.xiyu.githubdirect.test.FakeBinder
import org.xiyu.githubdirect.test.InMemorySettingsStore

/** 能力齐全的假探测结果（uid 由调用方指定）。 */
private fun goodCaps(uid: Int = 10123) = RootCapabilities(
    suAvailable = true, uid = uid,
    iptables = true, iptablesSave = true, iptablesRestore = true,
    natOutput = true, ownerUidMatch = true, redirectTarget = true,
    ipv6Netfilter = false, nft = false, tproxy = false, selinuxEnforcing = true,
)

/**
 * BackendManager 集成测试：fake RootBackendControl / fake 探测器 / fake scope resolver，
 * 不执行任何真实 su / iptables / PackageManager（watchdog 线程关闭，直接调 watchdogTick）。
 */
class BackendManagerTest {

    // ---------- fakes ----------

    private class FakeRootControl : RootBackendControl {
        var startResult = true
        var healthResult = true
        var startCount = 0
        var stopCount = 0
        override var state: BackendState = BackendState.STOPPED
        var lastRulesBuilder: ((Int) -> FirewallRules)? = null
        var lastHandler: ((ByteArray) -> ByteArray?)? = null

        override fun configureScope(rulesBuilder: (Int) -> FirewallRules) {
            lastRulesBuilder = rulesBuilder
        }

        override fun start(
            dnsHandler: (ByteArray) -> ByteArray?,
            resolveRealIp: (Int) -> ByteArray?,
        ): Boolean {
            startCount++
            lastHandler = dnsHandler
            state = if (startResult) BackendState.ACTIVE else BackendState.FAILED
            return startResult
        }

        override fun stop(): Boolean {
            stopCount++
            state = BackendState.STOPPED
            return true
        }

        override fun healthCheck(): Boolean = healthResult && state == BackendState.ACTIVE
    }

    private class FakeProber(var caps: RootCapabilities = goodCaps()) : CapabilityProber {
        var calls = 0
        override fun probe(): RootCapabilities {
            calls++
            return caps
        }
    }

    private class FakeScopeResolver(var result: ResolvedScope = ResolvedScope(emptySet(), false)) :
        ScopeUidResolver {
        var lastMode: AppScopeMode? = null
        override fun resolveUids(mode: AppScopeMode, packages: Set<String>): ResolvedScope {
            lastMode = mode
            return result
        }
    }

    private class Notifications {
        val list = mutableListOf<Triple<BackendMode?, Boolean, String>>()
    }

    private class Harness(
        val store: InMemorySettingsStore = InMemorySettingsStore(),
        val root: FakeRootControl = FakeRootControl(),
        val prober: FakeProber = FakeProber(),
        val resolver: FakeScopeResolver = FakeScopeResolver(),
    ) {
        var vpnActive = false
        var vpnStopRequested = 0
        var now = 0L
        val notifications = Notifications()

        /** 假引擎/假池：fake root 从不调用 handler，仅需非空引用满足 BackendManager 门控。 */
        private val dummyEngine: SelectiveDnsEngine = SelectiveDnsEngine(
            RuleRegistry(InMemorySettingsStore(), emptyMap(), MatcherIndex()),
            EndpointResolver(FakeBinder { null }),
            EndpointCache(),
            VirtualIpPool(),
            RelayIpTable(),
            WireDohClient(),
            PlainDnsClient(),
        )
        private val dummyPool: VirtualIpPool = VirtualIpPool()

        /** 组件注入点：置 null 可模拟组件缺失。 */
        var engineAvailable: SelectiveDnsEngine? = dummyEngine
        var poolAvailable: VirtualIpPool? = dummyPool

        val manager: BackendManager = BackendManager(
            settings = store,
            rootBackend = root,
            capProbe = prober,
            scopeResolver = resolver,
            dnsEngine = { engineAvailable },
            pool = { poolAvailable },
            vpnActiveCheck = { vpnActive },
            vpnStopRequest = { vpnStopRequested++ },
            clock = { now },
            watchdogEnabled = false,
        ).also { it.addBackendListener { mode, active, msg ->
            notifications.list += Triple(mode, active, msg)
        } }
    }

    // ---------- AUTO 解析 ----------

    @Test
    fun `AUTO 解析 root 可用 → ROOT_TRANSPARENT`() {
        val h = Harness()
        assertEquals(BackendMode.ROOT_TRANSPARENT, h.manager.resolveAuto())
        assertEquals(1, h.prober.calls)
        // rootCapabilities 返回最近探测结果（缓存命中）
        assertEquals(goodCaps(), h.manager.rootCapabilities())
    }

    @Test
    fun `AUTO 解析缓存 60s：缓存期内不重复探测`() {
        val h = Harness()
        h.manager.resolveAuto()
        assertEquals(1, h.prober.calls)
        h.manager.resolveAuto() // 同刻：命中缓存
        assertEquals(1, h.prober.calls)
        h.now += 61_000 // 过期 → 重新探测
        h.manager.resolveAuto()
        assertEquals(2, h.prober.calls)
    }

    @Test
    fun `AUTO 解析 root 不可用 → VPN`() {
        val h = Harness()
        h.prober.caps = goodCaps().copy(suAvailable = false)
        assertEquals(BackendMode.VPN, h.manager.resolveAuto())
    }

    @Test
    fun `start(AUTO) 内部先解析再启动对应 backend`() {
        val h = Harness()
        h.prober.caps = goodCaps()
        assertTrue(h.manager.start(BackendMode.AUTO))
        assertEquals(BackendMode.ROOT_TRANSPARENT, h.manager.currentMode())
        assertEquals(1, h.root.startCount)
    }

    // ---------- Root 启动 ----------

    @Test
    fun `start ROOT 成功 → ACTIVE 通知 + watchdog 启动条件满足`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertEquals(BackendMode.ROOT_TRANSPARENT, h.manager.currentMode())
        assertTrue(h.manager.isBackendActive())
        assertEquals(1, h.root.startCount)
        assertEquals(BackendState.ACTIVE, h.root.state)
        val last = h.notifications.list.last()
        assertEquals(BackendMode.ROOT_TRANSPARENT, last.first)
        assertEquals(true, last.second)
        // dns handler 已注入（raw→raw 语义由引擎保证；此处仅验证非空接线）
        assertTrue(h.root.lastHandler != null)
    }

    @Test
    fun `start ROOT 失败 → false + FAILED 通知 + 模式清空`() {
        val h = Harness()
        h.root.startResult = false
        assertFalse(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertNull(h.manager.currentMode())
        assertFalse(h.manager.isBackendActive())
        val last = h.notifications.list.last()
        assertEquals(BackendMode.ROOT_TRANSPARENT, last.first)
        assertEquals(false, last.second)
    }

    @Test
    fun `引擎不可用时 ROOT 启动失败且不触碰 backend`() {
        val h = Harness()
        h.engineAvailable = null // 模拟 DirectEngine 未初始化
        assertFalse(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertEquals(0, h.root.startCount)
        assertEquals(0, h.root.stopCount)
    }

    // ---------- 互斥 ----------

    @Test
    fun `切 VPN 前 root 被 stop`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertEquals(1, h.root.startCount)

        assertTrue(h.manager.start(BackendMode.VPN))
        assertEquals("root 应先被 stop", 1, h.root.stopCount)
        assertEquals(BackendMode.VPN, h.manager.currentMode())
        assertFalse("root 已停，VPN 未激活", h.manager.isBackendActive())
    }

    @Test
    fun `VPN 激活时切 root 前发停止请求`() {
        val h = Harness()
        h.vpnActive = true
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertEquals(1, h.vpnStopRequested)
    }

    @Test
    fun `root 激活时切 XPOSED 先停 root`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertTrue(h.manager.start(BackendMode.XPOSED_ONLY))
        assertEquals(1, h.root.stopCount)
        assertEquals(1, h.root.startCount) // 仅最初一次启动
    }

    // ---------- XPOSED_ONLY ----------

    @Test
    fun `XPOSED_ONLY 不启动任何 backend 且状态直接 ACTIVE`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.XPOSED_ONLY))
        assertEquals(0, h.root.startCount)
        assertEquals(0, h.root.stopCount)
        assertEquals(0, h.vpnStopRequested)
        assertEquals(BackendMode.XPOSED_ONLY, h.manager.currentMode())
        assertTrue(h.manager.isBackendActive())
        val last = h.notifications.list.last()
        assertEquals(BackendMode.XPOSED_ONLY, last.first)
        assertEquals(true, last.second)
    }

    // ---------- watchdog ----------

    @Test
    fun `watchdog 健康时不做任何动作`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        h.manager.watchdogTick()
        assertEquals(1, h.root.startCount) // 无修复
        assertEquals(BackendMode.ROOT_TRANSPARENT, h.manager.currentMode())
    }

    @Test
    fun `watchdog 失联 → 修复一次成功 → 通知修复`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        h.root.healthResult = false // 监听/规则链失联
        h.manager.watchdogTick()
        assertEquals("修复应再次 start", 2, h.root.startCount)
        assertTrue(h.notifications.list.any { it.second && it.third.contains("修复成功") })
        assertEquals(BackendMode.ROOT_TRANSPARENT, h.manager.currentMode())
    }

    @Test
    fun `watchdog 修复失败 → rollback + FAILED 通知 + 模式清空`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        h.root.healthResult = false
        h.root.startResult = false // 修复时的 start 也失败
        h.manager.watchdogTick()
        assertEquals("修复尝试一次", 2, h.root.startCount)
        assertEquals("rollback 应 stop", 2, h.root.stopCount)
        assertNull(h.manager.currentMode())
        assertFalse(h.manager.isBackendActive())
        val last = h.notifications.list.last()
        assertNull(last.first)
        assertFalse(last.second)
        assertTrue(last.third.contains("FAILED"))
    }

    @Test
    fun `watchdog 仅在 ROOT 模式生效`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.XPOSED_ONLY))
        h.manager.watchdogTick()
        assertEquals(0, h.root.startCount)
        assertEquals(BackendMode.XPOSED_ONLY, h.manager.currentMode())
    }

    // ---------- stop ----------

    @Test
    fun `stop 停 root 并请求 VPN 停止`() {
        val h = Harness()
        h.vpnActive = true
        h.manager.stop()
        assertEquals(1, h.root.stopCount)
        assertEquals(1, h.vpnStopRequested)
        assertNull(h.manager.currentMode())
        // VPN 服务停止是异步的：停止请求发出后、服务未退出前仍视为激活
        assertTrue(h.manager.isBackendActive())
        h.vpnActive = false // 服务已退出
        assertFalse(h.manager.isBackendActive())
    }

    // ---------- scope 接线（§40/§41） ----------

    @Test
    fun `SELECTED_APPS 构造带 UID 子链的规则`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        h.resolver.result = ResolvedScope(setOf(10001, 10002), degraded = false)

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))

        val builder = h.root.lastRulesBuilder
        assertTrue(builder != null)
        val rules = builder!!.invoke(10123)
        val (nat, _) = rules.ownedChainNames()
        assertTrue("应含选中 UID 子链", nat.contains("GHD_TCP_UID_10001"))
        assertTrue(nat.contains("GHD_TCP_UID_10002"))
    }

    @Test
    fun `scope 解析为空 → 降级 ALL_APPS 规则（无 UID 子链）`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        h.resolver.result = ResolvedScope(emptySet(), degraded = true)

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))

        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        val (nat, filter) = rules.ownedChainNames()
        assertTrue(nat.none { it.contains("_UID_") })
        assertTrue(filter.none { it.contains("_UID_") })
    }

    @Test
    fun `EXCLUDED 超出上限截断不抛异常`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.EXCLUDED_APPS)
        h.resolver.result = ResolvedScope((20001..20012).toSet(), degraded = false)

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))

        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        val (nat, _) = rules.ownedChainNames()
        val uidChains = nat.count { it.contains("_UID_") }
        assertTrue("截断到上限", uidChains <= FirewallRules.MAX_EXCLUDED_UIDS)
    }
}

package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.data.Nat64FallbackConfig
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
import org.xiyu.githubdirect.core.routing.CandidateSource
import org.xiyu.githubdirect.core.routing.EndpointCandidate
import org.xiyu.githubdirect.core.routing.EndpointPlan
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.routing.RouteSnapshot
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
        var refreshCount = 0
        var refreshResult = true
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

        override fun refreshRules(): Boolean {
            refreshCount++
            state = if (refreshResult) BackendState.ACTIVE else BackendState.FAILED
            return refreshResult
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
        val store: InMemorySettingsStore = InMemorySettingsStore().apply {
            // 本夹具的非 scope 用例显式验证全应用规则；安全默认值由 ScopeSettingsTest 单独覆盖。
            setAppScopeMode(AppScopeMode.ALL_APPS)
        },
        val root: FakeRootControl = FakeRootControl(),
        val prober: FakeProber = FakeProber(),
        val resolver: FakeScopeResolver = FakeScopeResolver(),
    ) {
        var vpnActive = false
        var vpnStopRequested = 0
        var now = 0L
        var routeSnapshot: RouteSnapshot = RouteSnapshot.EMPTY
        var originalDestinationAvailable = false
        var nat64FallbackDomains: Set<String> = emptySet()
        var nat64FallbackActive = false
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
            routeSnapshotProvider = { routeSnapshot },
            originalDestinationAvailable = { originalDestinationAvailable },
            nat64FallbackDomainsProvider = { nat64FallbackDomains },
            nat64FallbackActiveProvider = { nat64FallbackActive },
        ).also { it.addBackendListener { mode, active, msg ->
            notifications.list += Triple(mode, active, msg)
        } }
    }

    // ---------- AUTO 解析 ----------

    @Test
    fun `规则刷新保持监听生命周期并只调用原位 refresh`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))

        assertTrue(h.manager.refreshRootDataPlane())

        assertEquals(1, h.root.startCount)
        assertEquals(1, h.root.refreshCount)
        assertEquals(0, h.root.stopCount)
        assertEquals(BackendState.ACTIVE, h.root.state)
        assertEquals(BackendMode.ROOT_TRANSPARENT, h.manager.currentMode())
    }

    @Test
    fun `刷新前发现guardian已清链则完整重建而不生成无入口孤儿链`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        h.root.healthResult = false

        assertTrue(h.manager.refreshRootDataPlane())

        assertEquals(1, h.root.stopCount)
        assertEquals(2, h.root.startCount)
        assertEquals(0, h.root.refreshCount)
        assertEquals(BackendState.ACTIVE, h.root.state)
        assertEquals(BackendMode.ROOT_TRANSPARENT, h.manager.currentMode())
    }

    @Test
    fun `原位规则刷新失败进入 fail-open 而不回退成第二次 start`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        h.root.refreshResult = false

        assertFalse(h.manager.refreshRootDataPlane())

        assertEquals(1, h.root.startCount)
        assertEquals(1, h.root.refreshCount)
        assertNull(h.manager.currentMode())
        assertEquals(false, h.notifications.list.last().second)
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
    fun `root 激活时切 XPOSED 先停再拉起中继`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertTrue(h.manager.start(BackendMode.XPOSED_ONLY))
        assertEquals(1, h.root.stopCount)
        assertEquals(2, h.root.startCount)
        assertEquals(BackendMode.XPOSED_ONLY, h.manager.currentMode())
        assertTrue(h.manager.isRootBackendActive())
    }

    // ---------- XPOSED_ONLY ----------

    @Test
    fun `XPOSED_ONLY Root 可用时启动透明中继`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.XPOSED_ONLY))
        assertEquals(1, h.root.startCount)
        assertEquals(0, h.vpnStopRequested)
        assertEquals(BackendMode.XPOSED_ONLY, h.manager.currentMode())
        assertTrue(h.manager.isBackendActive())
        assertTrue(h.manager.isRootBackendActive())
        val last = h.notifications.list.last()
        assertEquals(BackendMode.XPOSED_ONLY, last.first)
        assertEquals(true, last.second)
        assertTrue(last.third.contains("Root"))
    }

    @Test
    fun `XPOSED_ONLY 引擎不可用时退化为纯 DNS`() {
        val h = Harness()
        h.engineAvailable = null
        assertTrue(h.manager.start(BackendMode.XPOSED_ONLY))
        assertEquals(0, h.root.startCount)
        assertEquals(BackendMode.XPOSED_ONLY, h.manager.currentMode())
        assertTrue(h.manager.isBackendActive())
        assertFalse(h.manager.isRootBackendActive())
        val last = h.notifications.list.last()
        assertTrue(last.third.contains("无 SNI"))
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
    fun `watchdog 在 Xposed+Root 辅助时生效`() {
        val h = Harness()
        assertTrue(h.manager.start(BackendMode.XPOSED_ONLY))
        h.root.healthResult = false
        h.manager.watchdogTick()
        assertEquals("修复应再次 start", 2, h.root.startCount)
        assertEquals(BackendMode.XPOSED_ONLY, h.manager.currentMode())
    }

    @Test
    fun `watchdog 纯 DNS Xposed 不碰 root`() {
        val h = Harness()
        h.engineAvailable = null
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
    fun `SELECTED_APPS 构造每 UID 入口与单一共享载荷链`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        h.resolver.result = ResolvedScope(setOf(10001, 10002), degraded = false)

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))

        val builder = h.root.lastRulesBuilder
        assertTrue(builder != null)
        val rules = builder!!.invoke(10123)
        val script = rules.buildInstallScript()
        assertEquals(1, script.lines().count { it == ":GHD_TCP_SEL - [0:0]" })
        assertTrue(script.contains("--uid-owner 10001 -j GHD_TCP_SEL"))
        assertTrue(script.contains("--uid-owner 10002 -j GHD_TCP_SEL"))
        assertEquals(245, script.lines().count { it.startsWith("-A GHD_TCP_SEL ") && it.contains("-j REDIRECT") })
    }

    @Test
    fun `SELECTED scope解析为空拒绝启动且不退化到全部应用`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        h.resolver.result = ResolvedScope(emptySet(), degraded = true)

        assertFalse(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertEquals(0, h.root.startCount)
        assertTrue(h.root.lastRulesBuilder == null)
        assertTrue(h.notifications.list.last().third.contains("作用域为空"))
    }

    @Test
    fun `Electron-like宿主二次授权解析为scope子集并接入全TLS规则`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        h.store.setScopedPackages(setOf("com.discord"))
        h.store.setEmbeddedTlsCapturePackages(setOf("com.discord"))
        h.resolver.result = ResolvedScope(setOf(10001), degraded = false)
        h.originalDestinationAvailable = true

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))

        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        assertEquals(setOf(10001), h.manager.embeddedCaptureUids())
        assertEquals(1, rules.fullTlsCaptureUidCount())
        assertTrue(
            rules.buildInstallScript().contains(
                "--uid-owner 10001 -p tcp --dport 443 -j REDIRECT --to-ports 7443",
            ),
        )
    }

    @Test
    fun `非scope包的全TLS授权被忽略`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        h.store.setScopedPackages(setOf("com.discord"))
        h.store.setEmbeddedTlsCapturePackages(setOf("com.openai.chatgpt"))
        h.resolver.result = ResolvedScope(setOf(10001), degraded = false)
        h.originalDestinationAvailable = true

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        assertTrue(h.manager.embeddedCaptureUids().isEmpty())
        assertEquals(0, rules.fullTlsCaptureUidCount())
    }

    @Test
    fun `EXCLUDED 超出上限截断不抛异常`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.EXCLUDED_APPS)
        h.resolver.result = ResolvedScope((20001..20012).toSet(), degraded = false)

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))

        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        val sample = rules.buildInstallScript().lines()
            .first { it.startsWith("-A GHD_TCP ") && it.contains("-j REDIRECT") }
        assertEquals(
            "自身排除加最多 8 个应用排除",
            1 + FirewallRules.MAX_EXCLUDED_UIDS,
            Regex("! --uid-owner").findAll(sample).count(),
        )
        assertFalse(sample.contains("--uid-owner 20009"))
    }

    @Test
    fun `JNI可用时把路由快照与Root能力接入真实IP规则`() {
        val h = Harness()
        h.originalDestinationAvailable = true
        h.prober.caps = goodCaps().copy(ipset = true, rejectTarget = true)
        val candidate = EndpointCandidate(
            domain = "github.com",
            address = "20.205.243.166",
            source = CandidateSource.WIRE_DOH,
            fetchedAt = 1,
            expiresAt = 0,
            latencyMs = 20,
            capability = RouteCapability.FRAGMENTED_TLS,
        )
        h.routeSnapshot = RouteSnapshot(
            generation = 88,
            createdAt = 1,
            expiresAt = 0,
            plans = mapOf(
                "github.com" to EndpointPlan(
                    domain = "github.com",
                    endpointGroup = "web",
                    candidates = listOf(candidate),
                ),
            ),
            metaCidrs = setOf("140.82.112.0/20"),
        )

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        assertTrue(rules.usesRealIpRedirect())
        assertTrue(rules.usesIpSet())
        assertEquals(88, rules.generation)
        assertTrue(rules.buildInstallScript().contains("--match-set GHD_DST dst"))
        assertTrue(rules.buildInstallScript().contains("-j REJECT"))
    }

    @Test
    fun `关闭real_ip_redirect会移除真实IP和QUIC目标但保留vIP链`() {
        val h = Harness()
        h.originalDestinationAvailable = true
        h.store.setRealIpRedirectEnabled(false)
        h.routeSnapshot = RouteSnapshot(
            generation = 90,
            createdAt = 1,
            expiresAt = 0,
            plans = emptyMap(),
            metaCidrs = setOf("140.82.112.0/20", "2606:50c0::/32"),
        )

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        assertFalse(rules.usesRealIpRedirect())
        assertEquals(0, rules.directDestinationCount())
        assertEquals(0, rules.directIpv6DestinationCount())
        assertTrue("关闭真实IP层仍须保留DNS/vIP回滚路径", rules.buildInstallScript().contains("10.0.0.10/32"))
        assertFalse(rules.buildInstallScript().contains("140.82.112.0/20"))
        assertEquals("", rules.buildIpv6InstallScript())
    }

    @Test
    fun `完整IPv6能力把AAAA目标接入独立ip6tables规则`() {
        val h = Harness()
        h.originalDestinationAvailable = true
        h.prober.caps = goodCaps().copy(
            ipv6Netfilter = true,
            ipv6RejectTarget = true,
        )
        h.routeSnapshot = RouteSnapshot(
            generation = 89,
            createdAt = 1,
            expiresAt = 0,
            plans = emptyMap(),
            metaCidrs = setOf("2606:50c0::/32"),
        )

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        val script = rules.buildIpv6InstallScript()
        assertTrue(rules.usesIpv6RealIpRedirect())
        assertEquals(1, rules.directIpv6DestinationCount())
        assertTrue(script.contains("-d 2606:50c0::/32 -p tcp --dport 443 -j REDIRECT"))
        assertTrue(script.contains("--reject-with icmp6-port-unreachable"))
    }

    @Test
    fun `已验证NAT64仅为所选应用和OpenAI实时AAAA启用策略回落`() {
        val h = Harness()
        h.store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        h.resolver.result = ResolvedScope(setOf(10311), degraded = false)
        h.originalDestinationAvailable = true
        h.prober.caps = goodCaps().copy(ipv6UidPolicyRouting = true)
        h.store.setNat64FallbackConfig(
            Nat64FallbackConfig(
                enabled = true,
                prefix = "2a01:4f9:c010:3f02:64::/96",
                operator = "nat64.net-Helsinki",
                expectedAsn = "AS24940",
                expectedRegion = "FI/HEL",
                riskAccepted = true,
            ),
        )
        h.nat64FallbackDomains = setOf("openai.com")
        h.nat64FallbackActive = true
        fun candidate(domain: String, address: String) = EndpointCandidate(
            domain = domain,
            address = address,
            source = CandidateSource.WIRE_DOH,
            fetchedAt = 1,
            expiresAt = 0,
            latencyMs = 20,
            capability = RouteCapability.DIRECT_TLS,
        )
        h.routeSnapshot = RouteSnapshot(
            generation = 91,
            createdAt = 1,
            expiresAt = 0,
            plans = mapOf(
                "auth.openai.com" to EndpointPlan(
                    "auth.openai.com",
                    "openai-auth",
                    candidates = listOf(
                        candidate("auth.openai.com", "104.18.41.241"),
                        candidate("auth.openai.com", "2606:4700:4400::6812:29f1"),
                    ),
                ),
                "www.google.com" to EndpointPlan(
                    "www.google.com",
                    "google-web",
                    candidates = listOf(candidate("www.google.com", "2607:f8b0:4007:80e::2004")),
                ),
            ),
            metaCidrs = emptySet(),
        )

        assertTrue(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        val rules = h.root.lastRulesBuilder!!.invoke(10123)
        assertTrue(rules.usesNat64Ipv6Fallback())
        assertEquals(1, rules.nat64Ipv6FallbackDestinationCount())
        val commands = rules.buildNat64Ipv6FallbackInstallCommands().joinToString("\n")
        assertTrue(commands.contains("2606:4700:4400::6812:29f1/128"))
        assertTrue(commands.contains("uidrange 10311-10311"))
        assertFalse(commands.contains("2607:f8b0"))

        h.nat64FallbackActive = false
        assertFalse(h.root.lastRulesBuilder!!.invoke(10123).usesNat64Ipv6Fallback())
    }

    @Test
    fun `start ROOT 探测失败则不调用 root start 并给出缺项`() {
        val h = Harness()
        h.prober.caps = goodCaps().copy(suAvailable = false)
        assertFalse(h.manager.start(BackendMode.ROOT_TRANSPARENT))
        assertEquals(0, h.root.startCount)
        assertNull(h.manager.currentMode())
        val last = h.notifications.list.last()
        assertEquals(false, last.second)
        assertTrue(last.third.contains("缺少"))
        assertTrue(last.third.contains("su"))
    }

    @Test
    fun `探测失败只短缓存 失败后很快会重探`() {
        val h = Harness()
        h.prober.caps = goodCaps().copy(suAvailable = false)
        h.manager.resolveAuto()
        assertEquals(1, h.prober.calls)
        h.now += 1_000
        h.manager.resolveAuto()
        assertEquals(1, h.prober.calls)
        h.now += 5_000
        h.manager.resolveAuto()
        assertEquals(2, h.prober.calls)
    }

    @Test
    fun `rootCapabilities force 忽略成功缓存`() {
        val h = Harness()
        h.manager.rootCapabilities()
        assertEquals(1, h.prober.calls)
        h.manager.rootCapabilities(force = true)
        assertEquals(2, h.prober.calls)
    }
}

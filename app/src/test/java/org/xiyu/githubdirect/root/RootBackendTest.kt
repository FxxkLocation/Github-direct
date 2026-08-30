package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RootBackend 事务化生命周期测试：fake shell / fake probe / fake listeners，
 * 不执行任何真实 root 命令。
 */
class RootBackendTest {

    // ---------- fakes ----------

    /** 按最近配置优先匹配子串的假执行器；记录全部脚本。 */
    private class ScriptedExecutor(
        var default: RootShell.Result = RootShell.Result(0, "", "", false),
    ) : ShellExecutor {
        val scripts = mutableListOf<String>()
        val timeouts = mutableListOf<Int>()
        private val responses = mutableListOf<Pair<String, RootShell.Result>>()
        var ipv6RestoreResult: RootShell.Result? = null

        fun on(contains: String, result: RootShell.Result) {
            responses.removeAll { it.first == contains } // 同键替换（测试中途改脚本）
            responses += contains to result
        }

        override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
            scripts += script
            timeouts += timeoutSec
            return responseFor(script)
        }

        override fun execIpv6Restore(
            suPath: String,
            restoreScript: String,
            timeoutSec: Int,
        ): RootShell.Result {
            scripts += restoreScript
            timeouts += timeoutSec
            return ipv6RestoreResult ?: responseFor(restoreScript)
        }

        private fun responseFor(script: String): RootShell.Result {
            for ((key, r) in responses.asReversed()) {
                if (script.contains(key)) return r
            }
            return default
        }
    }

    private class FakeDnsListener : DnsListener {
        var startResult = true
        var startCount = 0
        var stopCount = 0
        var aliveResult = true
        private var started = false
        override fun start(handler: (ByteArray) -> ByteArray?): Boolean {
            startCount++
            started = startResult
            return startResult
        }

        override fun stop() {
            stopCount++
            started = false
        }

        override fun alive(): Boolean = aliveResult && started
    }

    private class FakeTcpListener : TcpListener {
        var startResult = true
        var startCount = 0
        var stopCount = 0
        var aliveResult = true
        private var started = false
        var stats = ListenerStats(0, 0, 0, 0)
        override fun start(resolveRealIp: (Int) -> ByteArray?): Boolean {
            startCount++
            started = startResult
            return startResult
        }

        override fun stop() {
            stopCount++
            started = false
        }

        override fun alive(): Boolean = aliveResult && started

        override fun stats(): ListenerStats = stats

        var ipv6Active = false
        override fun ipv6DirectActive(): Boolean = ipv6Active
    }

    private class FakeProbe(var caps: RootCapabilities) : CapabilityProber {
        var probeCount = 0
        override fun probe(): RootCapabilities {
            probeCount++
            return caps
        }
    }

    private fun goodCaps(uid: Int = 10123) = RootCapabilities(
        suAvailable = true, uid = uid,
        iptables = true, iptablesSave = true, iptablesRestore = true,
        natOutput = true, ownerUidMatch = true, redirectTarget = true,
        ipv6Netfilter = false, nft = false, tproxy = false, selinuxEnforcing = true,
    )

    private fun backend(
        executor: ScriptedExecutor,
        probe: FakeProbe,
        dns: FakeDnsListener = FakeDnsListener(),
        tcp: FakeTcpListener = FakeTcpListener(),
        rulesBuilder: (Int) -> FirewallRules = { uid -> FirewallRules(selfUid = uid) },
    ): RootBackend = RootBackend(
        shell = RootShell(suPath = "su", executor = executor),
        capabilities = probe,
        dnsListener = dns,
        tcpListener = tcp,
        rulesBuilder = rulesBuilder,
    )

    /** verify 阶段 fake 返回自有链的 `iptables -S` 输出（特征行必然在其中）。 */
    private fun ScriptedExecutor.fakeVerificationWith(script: String) {
        on("iptables -t nat -S OUTPUT", RootShell.Result(0, script, "", false))
    }

    // ---------- 成功路径 ----------

    @Test
    fun `成功路径 state ACTIVE 且 restore 安装后 verify`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener()
        val script = FirewallRules(selfUid = 10123).buildInstallScript()
        executor.fakeVerificationWith(script)
        // healthCheck 用 `iptables -S` 校验特征行；start 内的清扫探测拿到同样输出也无害（无 -N GHD_* 行）
        executor.on("-S", RootShell.Result(0, script, "", false))

        val backend = backend(executor, probe, dns, tcp)
        val ok = backend.start({ null }, { null })

        assertTrue(ok)
        assertEquals(BackendState.ACTIVE, backend.state)
        assertEquals(1, executor.scripts.count { it.startsWith("*nat") }) // restore 恰好一次
        assertTrue(
            "verify 应仅查询 OUTPUT 与自有链",
            executor.scripts.any {
                it.contains("iptables -t nat -S OUTPUT") &&
                    it.contains("iptables -t filter -S GHD_UDP_DROP")
            },
        )
        val guardianStart = executor.scripts.indexOfFirst { it.contains("nohup sh -c") }
        val restore = executor.scripts.indexOfFirst { it.startsWith("*nat") }
        val verify = executor.scripts.indexOfFirst { it.contains("iptables -t nat -S OUTPUT") }
        val guardianHeartbeats = executor.scripts.withIndex().filter {
            it.value.contains(
                "guardian_pid_alive \"\$(cat /data/local/tmp/ghd_guard_10123.pid)\"",
            ) && it.value.contains("ghd_guard_10123.hb")
        }
        assertTrue("guardian 必须先于 restore，覆盖安装窗口的进程死亡", guardianStart in 0 until restore)
        assertTrue("restore 前必须续租 guardian", guardianHeartbeats.any { it.index in (guardianStart + 1) until restore })
        assertTrue("restore 后、verify 前必须续租 guardian", guardianHeartbeats.any { it.index in (restore + 1) until verify })
        assertTrue("提交 ACTIVE 前必须再次续租 guardian", guardianHeartbeats.any { it.index > verify })
        assertEquals("单次 restore 不得越过 13 秒 guardian 阈值", 10, executor.timeouts[restore])
        assertEquals("单次 verify 不得越过 13 秒 guardian 阈值", 10, executor.timeouts[verify])
        assertEquals(1, dns.startCount)
        assertEquals(1, tcp.startCount)
        assertTrue("全部 Root 数据面都必须有 guardian", backend.failOpenGuardianActive)
        assertTrue("guardian 心跳应可刷新", backend.refreshFailOpenLease())
        assertTrue(backend.healthCheck())
    }

    @Test
    fun `原位刷新切换规则代次但不重启监听器或活动会话`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener().apply {
            stats = ListenerStats(3, 0, 1, activeSessions = 2)
        }
        var generation = 1L
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(selfUid = uid, generation = generation)
        }
        executor.fakeVerificationWith(configured(10123).buildInstallScript())
        val backend = backend(executor, probe, dns, tcp, configured)
        assertTrue(backend.start({ null }, { null }))

        generation = 2L
        executor.fakeVerificationWith(configured(10123).buildInstallScript())
        assertTrue(backend.refreshRules())

        assertEquals(BackendState.ACTIVE, backend.state)
        assertEquals(2L, backend.activeGeneration)
        assertEquals(2, backend.activeTcpSessions)
        assertEquals("DNS listener 不得重启", 1, dns.startCount)
        assertEquals("TCP listener 不得重启", 1, tcp.startCount)
        assertEquals("正常刷新不得停止 DNS listener", 0, dns.stopCount)
        assertEquals("正常刷新不得关闭活动 TCP 会话", 0, tcp.stopCount)
        assertEquals("初次安装与下一代安装各一次", 2, executor.scripts.count { it.startsWith("*nat") })
        assertEquals("每代规则都必须有独立 guardian", 2, executor.scripts.count { it.contains("nohup sh -c") })

        val restoreIndexes = executor.scripts.withIndex().filter { it.value.startsWith("*nat") }.map { it.index }
        val refreshRestore = restoreIndexes.last()
        assertFalse("刷新 restore 不得重复追加 OUTPUT jump", executor.scripts[refreshRestore].contains("-A OUTPUT -j GHD_"))
        assertFalse(
            "正常刷新不得在原子 restore 前删除活动链",
            executor.scripts.subList(restoreIndexes.first() + 1, refreshRestore).any {
                !it.contains("nohup sh -c") && it.contains("iptables -t nat -X GHD_TCP")
            },
        )
    }

    @Test
    fun `NAT64 IPv6策略回落参与事务安装校验与guardian清理`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(ipv6UidPolicyRouting = true))
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                scopeUids = setOf(10311),
                scopeInclude = true,
                directDestinations = setOf("104.18.41.241/32"),
                enableRealIpRedirect = true,
                nat64Ipv6FallbackDestinations = setOf("2606:4700:4400::6812:29f1/128"),
                enableIpv6UidPolicyFallback = true,
            )
        }
        val rules = configured(10123)
        val verification = rules.buildInstallScript() + "\n" +
            "10500: from all uidrange 10311-10311 lookup 52123\n" +
            "unreachable 2606:4700:4400::6812:29f1 dev lo metric 1024\n"
        executor.fakeVerificationWith(verification)

        val backend = backend(executor, probe, rulesBuilder = configured)
        assertTrue(backend.start({ null }, { null }))

        assertTrue(backend.nat64Ipv6FallbackActive)
        assertEquals(1, backend.nat64Ipv6FallbackDestinationCount)
        assertTrue(
            executor.scripts.any {
                it.startsWith("set -e\nip -6 route add unreachable") &&
                    it.contains("uidrange 10311-10311 lookup 52123")
            },
        )
        val guardian = executor.scripts.first { it.contains("nohup sh -c") }
        assertTrue(guardian.contains("ip -6 rule del priority 10500 table 52123"))
        assertTrue(guardian.contains("ip -6 route flush table 52123"))
        assertTrue(backend.healthCheck())
    }

    @Test
    fun `scope切换在原子提交后才清理旧共享子链`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        var selectedScope = true
        var generation = 1L
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                scopeUids = if (selectedScope) setOf(10001) else null,
                scopeInclude = true,
                generation = generation,
            )
        }
        executor.fakeVerificationWith(configured(10123).buildInstallScript())
        val backend = backend(executor, probe, rulesBuilder = configured)
        assertTrue(backend.start({ null }, { null }))

        selectedScope = false
        generation = 2L
        executor.fakeVerificationWith(configured(10123).buildInstallScript())
        assertTrue(backend.refreshRules())

        val restoreIndexes = executor.scripts.withIndex().filter { it.value.startsWith("*nat") }.map { it.index }
        val refreshRestore = restoreIndexes.last()
        val obsoleteCleanup = executor.scripts.withIndex().firstOrNull {
            it.index > refreshRestore &&
                !it.value.contains("nohup sh -c") &&
                it.value.contains("iptables -t nat -X GHD_TCP_SEL")
        }?.index ?: -1
        assertTrue("旧子链只能在新规则提交后清理", obsoleteCleanup > refreshRestore)
        assertEquals(BackendState.ACTIVE, backend.state)
        assertEquals(2L, backend.activeGeneration)
    }

    @Test
    fun `原位刷新安装失败清理规则并停止监听保持fail-open`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener()
        var generation = 1L
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(selfUid = uid, generation = generation)
        }
        executor.fakeVerificationWith(configured(10123).buildInstallScript())
        val backend = backend(executor, probe, dns, tcp, configured)
        assertTrue(backend.start({ null }, { null }))

        generation = 2L
        executor.on("*nat", RootShell.Result(1, "", "refresh restore failed", false))
        assertFalse(backend.refreshRules())

        assertEquals(BackendState.FAILED, backend.state)
        assertEquals(0L, backend.activeGeneration)
        assertEquals("firewall.restore.v4", backend.lastFailure?.stage)
        assertTrue(backend.lastFailure?.detail.orEmpty().contains("refresh restore failed"))
        assertEquals(1, dns.stopCount)
        assertEquals(1, tcp.stopCount)
        assertFalse(backend.failOpenGuardianActive)
        assertTrue(executor.scripts.any { it.contains("iptables -t nat -X GHD_TCP") })
    }

    @Test
    fun `verify 接受 legacy iptables S 移动协议并补协议模块的规范化输出`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val rules = FirewallRules(
            selfUid = 10123,
            scopeUids = setOf(10001),
            scopeInclude = true,
            fullTlsCaptureUids = setOf(10001),
            directDestinations = setOf("140.82.112.0/20"),
            enableRealIpRedirect = true,
            rejectUdp443 = true,
        )
        val normalized = rules.buildInstallScript()
            .replace(Regex(" +"), " ")
            .replace("-p tcp ", "-p tcp -m tcp ")
            .replace("-p udp ", "-p udp -m udp ")
            .replace(
                "-A GHD_TCP -m owner ! --uid-owner 10123 -m owner --uid-owner 10001 " +
                    "-p tcp -m tcp --dport 443",
                "-A GHD_TCP -p tcp -m owner ! --uid-owner 10123 -m owner --uid-owner 10001 " +
                    "-m tcp --dport 443",
            )
            .replace(
                "-A GHD_UDP_DROP -m owner ! --uid-owner 10123 -m owner --uid-owner 10001 " +
                    "-p udp -m udp --dport 443",
                "-A GHD_UDP_DROP -p udp -m owner ! --uid-owner 10123 -m owner --uid-owner 10001 " +
                    "-m udp --dport 443",
            )
        executor.fakeVerificationWith(normalized)

        val backend = backend(executor, probe, rulesBuilder = { rules })

        assertTrue(backend.start({ null }, { null }))
        assertEquals(BackendState.ACTIVE, backend.state)
    }

    @Test
    fun `verify 接受 legacy iptables S 把目标地址移到 owner 之前`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val rules = FirewallRules(
            selfUid = 10123,
            directDestinations = setOf("140.82.112.0/20"),
            enableRealIpRedirect = true,
            rejectUdp443 = true,
        )
        // Oplus/legacy 设备实测会把 destination 与 protocol 输出到 owner 匹配之前，
        // 并补充 `-m tcp`；规则语义与生成脚本相同。
        val legacy = rules.buildInstallScript().replace(
            "-A GHD_TCP -m owner ! --uid-owner 10123 -d 10.0.0.10/32 " +
                "-p tcp --dport 443 -j REDIRECT --to-ports 7010",
            "-A GHD_TCP -d 10.0.0.10/32 -p tcp -m owner ! --uid-owner 10123 " +
                "-m tcp --dport 443 -j REDIRECT --to-ports 7010",
        )
        executor.fakeVerificationWith(legacy)

        val backend = backend(executor, probe, rulesBuilder = { rules })

        assertTrue(backend.start({ null }, { null }))
        assertEquals(BackendState.ACTIVE, backend.state)
    }

    @Test
    fun `verify 规范化后仍拒绝全TLS规则协议被替换`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val rules = FirewallRules(
            selfUid = 10123,
            scopeUids = setOf(10001),
            scopeInclude = true,
            fullTlsCaptureUids = setOf(10001),
            enableRealIpRedirect = true,
            rejectUdp443 = true,
        )
        val expected = rules.buildInstallScript()
        val wrongProtocol = expected.replace(
            "-A GHD_TCP -m owner ! --uid-owner 10123 -m owner --uid-owner 10001 " +
                "-p tcp --dport 443 -j REDIRECT --to-ports 7443",
            "-A GHD_TCP -p udp -m owner ! --uid-owner 10123 -m owner --uid-owner 10001 " +
                "--dport 443 -j REDIRECT --to-ports 7443",
        )
        executor.fakeVerificationWith(wrongProtocol)

        val backend = backend(executor, probe, rulesBuilder = { rules })

        assertFalse(backend.start({ null }, { null }))
        assertEquals("firewall.verify.markers", backend.lastFailure?.stage)
    }

    @Test
    fun `IPv6规则独立restore并在双栈监听就绪后激活`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(ipv6Netfilter = true))
        val tcp = FakeTcpListener().apply { ipv6Active = true }
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                directDestinations = setOf("140.82.112.0/20", "2606:50c0::/32"),
                enableRealIpRedirect = true,
                enableIpv6Redirect = true,
            )
        }
        val rules = configured(10123)
        val verification = rules.buildInstallScript() + "\n" + rules.buildIpv6InstallScript()
        executor.fakeVerificationWith(verification)
        executor.on("-S", RootShell.Result(0, verification, "", false))

        val backend = backend(executor, probe, tcp = tcp, rulesBuilder = configured)

        assertTrue(backend.start({ null }, { null }))
        assertEquals(BackendState.ACTIVE, backend.state)
        assertTrue(executor.scripts.any { it.contains(":GHD_6_TCP - [0:0]") })
        assertTrue(executor.scripts.any { it.contains("ip6tables -t nat -S GHD_6_TCP") })
    }

    @Test
    fun `IPv6监听未就绪时不安装任何规则并fail-open`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(ipv6Netfilter = true))
        val tcp = FakeTcpListener().apply { ipv6Active = false }
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                directDestinations = setOf("2606:50c0::/32"),
                enableRealIpRedirect = true,
                enableIpv6Redirect = true,
            )
        }

        val backend = backend(executor, probe, tcp = tcp, rulesBuilder = configured)

        assertFalse(backend.start({ null }, { null }))
        assertEquals(BackendState.FAILED, backend.state)
        assertFalse(executor.scripts.any { it.startsWith("*nat") })
        assertTrue(tcp.stopCount >= 1)
    }

    @Test
    fun `仅Electron-like全TLS捕获需要IPv6监听未就绪时fail-open`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(ipv6Netfilter = true))
        val tcp = FakeTcpListener().apply { ipv6Active = false }
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                scopeUids = setOf(10001),
                scopeInclude = true,
                directDestinations = setOf("140.82.112.0/20"),
                fullTlsCaptureUids = setOf(10001),
                enableRealIpRedirect = true,
                enableIpv6Redirect = true,
            )
        }

        assertTrue(configured(10123).usesIpv6RealIpRedirect())

        val backend = backend(executor, probe, tcp = tcp, rulesBuilder = configured)

        assertFalse(backend.start({ null }, { null }))
        assertEquals(BackendState.FAILED, backend.state)
        assertEquals("listener.tcp.direct.v6", backend.lastFailure?.stage)
        assertFalse(executor.scripts.any { it.startsWith("*nat") })
        assertTrue(tcp.stopCount >= 1)
    }

    @Test
    fun `IPv6 restore失败时整体回滚`() {
        val executor = ScriptedExecutor().apply {
            ipv6RestoreResult = RootShell.Result(1, "", "ip6 restore failed", false)
        }
        val probe = FakeProbe(goodCaps().copy(ipv6Netfilter = true))
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener().apply { ipv6Active = true }
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                directDestinations = setOf("2606:50c0::/32"),
                enableRealIpRedirect = true,
                enableIpv6Redirect = true,
            )
        }

        val backend = backend(executor, probe, dns, tcp, configured)

        assertFalse(backend.start({ null }, { null }))
        assertEquals(BackendState.FAILED, backend.state)
        assertTrue(executor.scripts.any { it.contains(":GHD_6_TCP - [0:0]") })
        assertTrue(executor.scripts.any { it.contains("ip6tables -t nat -X GHD_6_TCP") })
        assertTrue(dns.stopCount >= 1)
        assertTrue(tcp.stopCount >= 1)
    }

    @Test
    fun `cleanupStale 在 start 前置执行（先清残留再 restore）`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val script = FirewallRules(selfUid = 10123).buildInstallScript()
        executor.fakeVerificationWith(script)

        backend(executor, probe).start({ null }, { null })

        val scripts = executor.scripts
        val firstRestore = scripts.indexOfFirst { it.startsWith("*nat") }
        assertTrue("restore 应存在", firstRestore > 0)
        // cleanup 命令（-D/-F/-X 自有 chain）必须先于 restore 出现
        assertTrue(scripts.take(firstRestore).any { it.contains("-X GHD_DNS") })
        // 清扫探测（-S）也先于 restore
        assertTrue(scripts.take(firstRestore).any { it.contains("-t nat -S") })
    }

    @Test
    fun `ipset运行失败自动回退内联规则并启用guardian心跳`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(ipset = true, rejectTarget = true))
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                directDestinations = setOf("140.82.112.0/20"),
                enableRealIpRedirect = true,
                useIpSet = true,
                rejectUdp443 = true,
                generation = 9,
            )
        }
        val fallback = configured(10123).withoutIpSet()
        executor.on("ipset create GHD_DST", RootShell.Result(1, "", "ipset failed", false))
        executor.fakeVerificationWith(fallback.buildInstallScript())

        val backend = backend(executor, probe, rulesBuilder = configured)
        assertTrue(backend.start({ null }, { null }))
        assertTrue(backend.realIpRedirectActive)
        assertFalse(backend.ipSetLeaseActive)
        assertEquals(9, backend.activeGeneration)
        assertTrue(executor.scripts.any { it.contains("-d 140.82.112.0/20") && it.startsWith("*nat") })
        assertTrue("guardian 心跳应可刷新", backend.refreshFailOpenLease())
    }

    @Test
    fun `ipset模式同时刷新严格租约与guardian心跳`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(ipset = true))
        val configured: (Int) -> FirewallRules = { uid ->
            FirewallRules(
                selfUid = uid,
                directDestinations = setOf("140.82.112.0/20"),
                enableRealIpRedirect = true,
                useIpSet = true,
                generation = 10,
            )
        }
        executor.fakeVerificationWith(configured(10123).buildInstallScript())

        val backend = backend(executor, probe, rulesBuilder = configured)
        assertTrue(backend.start({ null }, { null }))
        assertTrue(backend.ipSetLeaseActive)
        assertTrue(backend.failOpenGuardianActive)
        assertTrue(backend.refreshFailOpenLease())

        assertTrue(executor.scripts.any { it.startsWith("set -e\nipset create GHD_DST") })
        assertTrue(executor.scripts.any { it.startsWith("set -e\nipset add GHD_DST") })
        assertTrue(executor.scripts.any { it.startsWith("set -e\n") && it.contains("kill -0") })
    }

    @Test
    fun `残留清扫移除上次 scope 的孤儿 chain`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.on("-t nat -S", RootShell.Result(0, "-N GHD_DNS\n-N GHD_OLD_UID_999\n", "", false))
        executor.fakeVerificationWith(FirewallRules(selfUid = 10123).buildInstallScript())

        assertTrue(backend(executor, probe).start({ null }, { null }))

        val cleanups = executor.scripts.filter { it.contains("-X GHD_") }
        assertTrue("应删除孤儿链 GHD_OLD_UID_999", cleanups.any { it.contains("-X GHD_OLD_UID_999") })
        assertTrue("应 flush 孤儿链", executor.scripts.any { it.contains("-F GHD_OLD_UID_999") })
        // 同一脚本内 先 flush 再删除（孤儿链也走同序）
        val script = executor.scripts.first { it.contains("-F GHD_OLD_UID_999") && it.contains("-X GHD_OLD_UID_999") }
        val oldF = script.indexOf("-F GHD_OLD_UID_999")
        val oldX = script.indexOf("-X GHD_OLD_UID_999")
        assertTrue(oldF in 0 until oldX)
    }

    @Test
    fun `残留清扫忽略包含shell元字符或超长名称的伪GHD链`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.on(
            "-t nat -S",
            RootShell.Result(
                0,
                "-N GHD_DNS\n-N GHD_BAD|reboot\n-N GHD_${"A".repeat(40)}\n",
                "",
                false,
            ),
        )
        executor.fakeVerificationWith(FirewallRules(selfUid = 10123).buildInstallScript())

        assertTrue(backend(executor, probe).start({ null }, { null }))
        val scripts = executor.scripts.joinToString("\n")
        assertFalse(scripts.contains("GHD_BAD|reboot"))
        assertFalse(scripts.contains("GHD_${"A".repeat(40)}"))
    }

    // ---------- 失败路径与回滚 ----------

    @Test
    fun `restore 安装失败 → rollback 被调用 → FAILED`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener()
        executor.on("*nat", RootShell.Result(1, "", "line 1 failed", false))

        val backend = backend(executor, probe, dns, tcp)
        assertFalse(backend.start({ null }, { null }))

        assertEquals(BackendState.FAILED, backend.state)
        assertEquals("firewall.restore.v4", backend.lastFailure?.stage)
        assertTrue(backend.lastFailure?.detail.orEmpty().contains("line 1 failed"))
        assertTrue("rollback 应执行清理命令", executor.scripts.any { it.contains("-X GHD_DNS") })
        assertEquals("监听应停止", 1, dns.stopCount)
        assertEquals("监听应停止", 1, tcp.stopCount)
        assertFalse(backend.healthCheck())
    }

    @Test
    fun `verify 失败（特征行缺失）→ FAILED`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeVerificationWith("") // 自有链输出不含任何特征行

        val backend = backend(executor, probe)
        assertFalse(backend.start({ null }, { null }))

        assertEquals(BackendState.FAILED, backend.state)
        assertEquals("firewall.verify.markers", backend.lastFailure?.stage)
        assertTrue(backend.lastFailure?.detail.orEmpty().contains("missing="))
        assertTrue(executor.scripts.any { it.contains("-X GHD_DNS") })
    }

    @Test
    fun `probe 失败 → 不安装规则也不起监听`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(suAvailable = false))
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener()

        val backend = backend(executor, probe, dns, tcp)
        assertFalse(backend.start({ null }, { null }))

        assertEquals(BackendState.FAILED, backend.state)
        assertEquals("capabilities.required", backend.lastFailure?.stage)
        assertTrue(backend.lastFailure?.detail.orEmpty().contains("su"))
        assertEquals("不应执行任何命令", 0, executor.scripts.size)
        assertEquals(0, dns.startCount)
        assertEquals(0, tcp.startCount)
    }

    @Test
    fun `能力缺失（ownerUidMatch false）→ 不安装`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps().copy(ownerUidMatch = false))

        assertFalse(backend(executor, probe).start({ null }, { null }))

        assertEquals(0, executor.scripts.count { it.startsWith("*nat") })
        assertEquals(0, executor.scripts.size)
    }

    @Test
    fun `TCP 监听绑定失败 → rollback 停止 DNS 监听 → FAILED`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener().apply { startResult = false }

        val backend = backend(executor, probe, dns, tcp)
        assertFalse(backend.start({ null }, { null }))

        assertEquals(BackendState.FAILED, backend.state)
        assertEquals("listener.tcp", backend.lastFailure?.stage)
        assertEquals(1, dns.stopCount)
        assertTrue(executor.scripts.any { it.contains("-X GHD_DNS") })
    }

    // ---------- 生命周期 ----------

    @Test
    fun `stop 幂等且清理规则停监听`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeVerificationWith(FirewallRules(selfUid = 10123).buildInstallScript())

        val backend = backend(executor, probe)
        assertTrue(backend.start({ null }, { null }))
        val stopSignalsBefore = executor.scripts.count {
            it.contains("touch /data/local/tmp/ghd_guard_10123.stop")
        }
        assertTrue(backend.stop())
        assertEquals(BackendState.STOPPED, backend.state)
        assertTrue("stop 应执行清理", executor.scripts.last().contains("-X GHD_DNS"))
        assertEquals(
            "同步清理前不得让 guardian 提前退出",
            stopSignalsBefore,
            executor.scripts.count { it.contains("touch /data/local/tmp/ghd_guard_10123.stop") },
        )

        assertTrue("stop 幂等", backend.stop())
        assertEquals(BackendState.STOPPED, backend.state)
    }

    @Test
    fun `跨进程清理在STOPPED状态仍探测UID并清理崩溃残留`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val backend = backend(executor, probe)

        assertTrue(backend.cleanupStaleInstallation())

        assertEquals(1, probe.probeCount)
        assertFalse(
            "跨进程清扫不能先终止可能仍在兜底的旧 guardian",
            executor.scripts.any { it.contains("touch /data/local/tmp/ghd_guard_10123.stop") },
        )
        assertTrue(executor.scripts.any { it.contains("iptables -t nat -X GHD_DNS") })
        assertEquals(BackendState.STOPPED, backend.state)
    }

    @Test
    fun `普通STOPPED停止幂等且不触发su探测`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val backend = backend(executor, probe)

        assertTrue(backend.stop())

        assertEquals(0, probe.probeCount)
        assertTrue(executor.scripts.isEmpty())
    }

    @Test
    fun `ACTIVE 时重复 start 不重复安装`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeVerificationWith(FirewallRules(selfUid = 10123).buildInstallScript())

        val backend = backend(executor, probe)
        assertTrue(backend.start({ null }, { null }))
        assertTrue(backend.start({ null }, { null })) // ACTIVE → 直接 true

        assertEquals(1, executor.scripts.count { it.startsWith("*nat") })
    }

    @Test
    fun `失败后 stop 再 start 可恢复`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.on("*nat", RootShell.Result(1, "", "", false)) // 首次安装失败

        val backend = backend(executor, probe)
        assertFalse(backend.start({ null }, { null }))
        assertEquals(BackendState.FAILED, backend.state)

        assertTrue(backend.stop())
        executor.on("*nat", RootShell.Result(0, "", "", false)) // 恢复后安装成功
        executor.fakeVerificationWith(FirewallRules(selfUid = 10123).buildInstallScript())

        assertTrue(backend.start({ null }, { null }))
        assertEquals(BackendState.ACTIVE, backend.state)
    }

    // ---------- healthCheck ----------

    @Test
    fun `healthCheck 监听死亡返回 false`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        executor.fakeVerificationWith(FirewallRules(selfUid = 10123).buildInstallScript())

        val backend = backend(executor, probe, dns)
        assertTrue(backend.start({ null }, { null }))

        dns.aliveResult = false
        assertFalse(backend.healthCheck())
    }

    @Test
    fun `healthCheck 规则链丢失返回 false`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeVerificationWith(FirewallRules(selfUid = 10123).buildInstallScript())

        val backend = backend(executor, probe)
        assertTrue(backend.start({ null }, { null }))

        // -S 输出不再含特征行（链被删）
        executor.on("-S", RootShell.Result(0, "", "", false))
        assertFalse(backend.healthCheck())
    }
}

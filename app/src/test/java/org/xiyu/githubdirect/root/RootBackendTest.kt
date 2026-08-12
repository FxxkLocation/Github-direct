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

    /** 按子串顺序匹配的假执行器；记录全部脚本。 */
    private class ScriptedExecutor(
        var default: RootShell.Result = RootShell.Result(0, "", "", false),
    ) : ShellExecutor {
        val scripts = mutableListOf<String>()
        private val responses = mutableListOf<Pair<String, RootShell.Result>>()

        fun on(contains: String, result: RootShell.Result) {
            responses.removeAll { it.first == contains } // 同键替换（测试中途改脚本）
            responses += contains to result
        }

        override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
            scripts += script
            for ((key, r) in responses) {
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
    ): RootBackend = RootBackend(
        shell = RootShell(suPath = "su", executor = executor),
        capabilities = probe,
        dnsListener = dns,
        tcpListener = tcp,
        rulesBuilder = { uid -> FirewallRules(selfUid = uid) },
    )

    /** verify 阶段 fake 返回的 iptables-save 输出 = 安装脚本本身（特征行必然在其中）。 */
    private fun ScriptedExecutor.fakeSaveWith(script: String) {
        on("iptables-save", RootShell.Result(0, script, "", false))
    }

    // ---------- 成功路径 ----------

    @Test
    fun `成功路径 state ACTIVE 且 restore 安装后 verify`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        val tcp = FakeTcpListener()
        val script = FirewallRules(selfUid = 10123).buildInstallScript()
        executor.fakeSaveWith(script)
        // healthCheck 用 `iptables -S` 校验特征行；start 内的清扫探测拿到同样输出也无害（无 -N GHD_* 行）
        executor.on("-S", RootShell.Result(0, script, "", false))

        val backend = backend(executor, probe, dns, tcp)
        val ok = backend.start({ null }, { null })

        assertTrue(ok)
        assertEquals(BackendState.ACTIVE, backend.state)
        assertEquals(1, executor.scripts.count { it.startsWith("*nat") }) // restore 恰好一次
        assertTrue("verify 应调 iptables-save", executor.scripts.any { it.contains("iptables-save") })
        assertEquals(1, dns.startCount)
        assertEquals(1, tcp.startCount)
        assertTrue(backend.healthCheck())
    }

    @Test
    fun `cleanupStale 在 start 前置执行（先清残留再 restore）`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val script = FirewallRules(selfUid = 10123).buildInstallScript()
        executor.fakeSaveWith(script)

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
    fun `残留清扫移除上次 scope 的孤儿 chain`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.on("-t nat -S", RootShell.Result(0, "-N GHD_DNS\n-N GHD_OLD_UID_999\n", "", false))
        executor.fakeSaveWith(FirewallRules(selfUid = 10123).buildInstallScript())

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
        assertTrue("rollback 应执行清理命令", executor.scripts.any { it.contains("-X GHD_DNS") })
        assertEquals("监听应停止", 1, dns.stopCount)
        assertEquals("监听应停止", 1, tcp.stopCount)
        assertFalse(backend.healthCheck())
    }

    @Test
    fun `verify 失败（特征行缺失）→ FAILED`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeSaveWith("") // iptables-save 输出不含任何特征行

        val backend = backend(executor, probe)
        assertFalse(backend.start({ null }, { null }))

        assertEquals(BackendState.FAILED, backend.state)
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
        assertEquals(1, dns.stopCount)
        assertTrue(executor.scripts.any { it.contains("-X GHD_DNS") })
    }

    // ---------- 生命周期 ----------

    @Test
    fun `stop 幂等且清理规则停监听`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeSaveWith(FirewallRules(selfUid = 10123).buildInstallScript())

        val backend = backend(executor, probe)
        assertTrue(backend.start({ null }, { null }))
        assertTrue(backend.stop())
        assertEquals(BackendState.STOPPED, backend.state)
        assertTrue("stop 应执行清理", executor.scripts.last().contains("-X GHD_DNS"))

        assertTrue("stop 幂等", backend.stop())
        assertEquals(BackendState.STOPPED, backend.state)
    }

    @Test
    fun `ACTIVE 时重复 start 不重复安装`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeSaveWith(FirewallRules(selfUid = 10123).buildInstallScript())

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
        executor.fakeSaveWith(FirewallRules(selfUid = 10123).buildInstallScript())

        assertTrue(backend.start({ null }, { null }))
        assertEquals(BackendState.ACTIVE, backend.state)
    }

    // ---------- healthCheck ----------

    @Test
    fun `healthCheck 监听死亡返回 false`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        val dns = FakeDnsListener()
        executor.fakeSaveWith(FirewallRules(selfUid = 10123).buildInstallScript())

        val backend = backend(executor, probe, dns)
        assertTrue(backend.start({ null }, { null }))

        dns.aliveResult = false
        assertFalse(backend.healthCheck())
    }

    @Test
    fun `healthCheck 规则链丢失返回 false`() {
        val executor = ScriptedExecutor()
        val probe = FakeProbe(goodCaps())
        executor.fakeSaveWith(FirewallRules(selfUid = 10123).buildInstallScript())

        val backend = backend(executor, probe)
        assertTrue(backend.start({ null }, { null }))

        // -S 输出不再含特征行（链被删）
        executor.on("-S", RootShell.Result(0, "", "", false))
        assertFalse(backend.healthCheck())
    }
}

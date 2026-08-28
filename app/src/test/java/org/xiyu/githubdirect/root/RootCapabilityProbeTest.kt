package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Root 能力探测：KernelSU `id -u` 返回 0 时必须使用应用 UID；
 * iptables --help 写在 stderr 且非 0 退出码时仍应识别 owner/REDIRECT。
 */
class RootCapabilityProbeTest {

    private class ScriptExecutor : ShellExecutor {
        val scripts = mutableListOf<String>()
        override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
            scripts += script
            return reply(script)
        }

        var idOut: String = "0"
        var idCode: Int = 0
        var ownerErr: String = "uid-owner"
        var ownerCode: Int = 1
        var redirectErr: String = "REDIRECT"
        var redirectCode: Int = 1
        var iptablesVersionOk: Boolean = true
        var saveExists: Boolean = true
        var restoreExists: Boolean = true
        var natOk: Boolean = true
        var ipsetExists: Boolean = false
        var rejectAvailable: Boolean = false
        var ownerProbeAvailable: Boolean = false
        var redirectProbeAvailable: Boolean = false
        var rejectProbeAvailable: Boolean = false
        var ip6tablesVersionOk: Boolean = false
        var ip6SaveExists: Boolean = false
        var ip6RestoreExists: Boolean = false
        var ip6NatOk: Boolean = false
        var ip6RejectAvailable: Boolean = false
        var ip6OwnerProbeAvailable: Boolean = false
        var ip6RedirectProbeAvailable: Boolean = false
        var ip6RejectProbeAvailable: Boolean = false

        private fun reply(script: String): RootShell.Result {
            when {
                script == "id -u" -> return RootShell.Result(idCode, idOut, "", false)
                script == "ip6tables -t filter -j REJECT --help" ->
                    return RootShell.Result(
                        if (ip6RejectAvailable) 0 else 1,
                        "",
                        if (ip6RejectAvailable) "REJECT" else "no",
                        false,
                    )
                "owner --help" in script ->
                    return RootShell.Result(ownerCode, "", ownerErr, false)
                "REDIRECT --help" in script ->
                    return RootShell.Result(redirectCode, "", redirectErr, false)
                "REJECT --help" in script ->
                    return RootShell.Result(if (rejectAvailable) 0 else 1, "", if (rejectAvailable) "REJECT" else "no", false)
                "iptables --version" in script ->
                    return if (iptablesVersionOk) {
                        RootShell.Result(0, "iptables v1.8.7", "", false)
                    } else {
                        RootShell.Result(1, "", "not found", false)
                    }
                "ip6tables --version" in script ->
                    return if (ip6tablesVersionOk) {
                        RootShell.Result(0, "ip6tables v1.8.7", "", false)
                    } else {
                        RootShell.Result(1, "", "not found", false)
                    }
                script.startsWith("test -x") && script.endsWith("iptables-save") ->
                    return RootShell.Result(if (saveExists) 0 else 1, "", "", false)
                script.startsWith("test -x") && script.endsWith("iptables-restore") ->
                    return RootShell.Result(if (restoreExists) 0 else 1, "", "", false)
                script.startsWith("test -x") && script.endsWith("ip6tables-save") ->
                    return RootShell.Result(if (ip6SaveExists) 0 else 1, "", "", false)
                script.startsWith("test -x") && script.endsWith("ip6tables-restore") ->
                    return RootShell.Result(if (ip6RestoreExists) 0 else 1, "", "", false)
                script.startsWith("test -x") && script.endsWith("ipset") ->
                    return RootShell.Result(if (ipsetExists) 0 else 1, "", "", false)
                script.startsWith("ip6tables -t nat -L OUTPUT") ->
                    return RootShell.Result(if (ip6NatOk) 0 else 1, "", "", false)
                "nat -L OUTPUT" in script ->
                    return RootShell.Result(if (natOk) 0 else 1, "", "", false)
                script.startsWith("set -e\nip6tables -t nat -N GHD_PROBE_OWNER6") ->
                    return RootShell.Result(if (ip6OwnerProbeAvailable) 0 else 1, "", "", false)
                script.startsWith("set -e\niptables -t nat -N GHD_PROBE_OWNER") ->
                    return RootShell.Result(if (ownerProbeAvailable) 0 else 1, "", "", false)
                script.startsWith("set -e\nip6tables -t nat -N GHD_PROBE_REDIR6") ->
                    return RootShell.Result(if (ip6RedirectProbeAvailable) 0 else 1, "", "", false)
                script.startsWith("set -e\niptables -t nat -N GHD_PROBE_REDIR") ->
                    return RootShell.Result(if (redirectProbeAvailable) 0 else 1, "", "", false)
                script.startsWith("set -e\nip6tables -t filter -N GHD_PROBE_REJECT6") ->
                    return RootShell.Result(if (ip6RejectProbeAvailable) 0 else 1, "", "", false)
                script.startsWith("set -e\niptables -t filter -N GHD_PROBE_REJECT") ->
                    return RootShell.Result(if (rejectProbeAvailable) 0 else 1, "", "", false)
                else -> return RootShell.Result(1, "", "no", false)
            }
        }
    }

    private fun probe(exec: ScriptExecutor, appUid: Int = 10123): RootCapabilities =
        RootCapabilityProbe(RootShell(executor = exec), appUid).probe()

    @Test
    fun `id -u 为 0 时 suAvailable 且 uid 是应用 UID`() {
        val exec = ScriptExecutor()
        exec.idOut = "KernelSU: grant\n0\n"
        val caps = probe(exec, appUid = 10123)
        assertTrue(caps.suAvailable)
        assertEquals(10123, caps.uid)
        assertTrue(caps.requiredOk())
        assertTrue(caps.missingRequired().isEmpty())
    }

    @Test
    fun `应用 UID 非法时 requiredOk 失败（不能把 root 0 当 selfUid）`() {
        val caps = probe(ScriptExecutor(), appUid = 0)
        assertTrue(caps.suAvailable)
        assertEquals(-1, caps.uid)
        assertFalse(caps.requiredOk())
        assertTrue("app-uid" in caps.missingRequired())
    }

    @Test
    fun `owner 与 REDIRECT 的 help 在 stderr 且退出码非 0 仍识别`() {
        val exec = ScriptExecutor()
        exec.ownerCode = 1
        exec.ownerErr = "owner match uid-owner gid-owner"
        exec.redirectCode = 1
        exec.redirectErr = "REDIRECT --to-ports"
        val caps = probe(exec)
        assertTrue(caps.ownerUidMatch)
        assertTrue(caps.redirectTarget)
        assertTrue(caps.requiredOk())
    }

    @Test
    fun `id 命令失败时即使输出含0也不得视为root`() {
        val exec = ScriptExecutor().apply {
            idCode = 1
            idOut = "0"
        }
        val caps = probe(exec)
        assertFalse(caps.suAvailable)
        assertFalse(caps.requiredOk())
    }

    @Test
    fun `owner help 缺失时只在孤立自有链探测而不修改OUTPUT`() {
        val exec = ScriptExecutor().apply {
            ownerErr = ""
            ownerProbeAvailable = true
        }

        val caps = probe(exec)

        assertTrue(caps.ownerUidMatch)
        assertTrue(exec.scripts.any { it.contains("-N GHD_PROBE_OWNER") })
        assertTrue(exec.scripts.any { it.contains("-X GHD_PROBE_OWNER") })
        assertFalse(exec.scripts.any { it.contains("-I OUTPUT") || it.contains("-A OUTPUT") })
    }

    @Test
    fun `REDIRECT help 全空时通过孤立链实测而不假定nat必然支持`() {
        val exec = ScriptExecutor().apply { redirectProbeAvailable = true }
        exec.redirectErr = ""
        exec.redirectCode = 1
        val caps = probe(exec)
        assertTrue(caps.natOutput)
        assertTrue(caps.redirectTarget)
        assertTrue(caps.requiredOk())
        assertTrue(exec.scripts.any { it.contains("-N GHD_PROBE_REDIR") })
        assertFalse(exec.scripts.any { it.contains("GHD_PROBE_REDIR") && it.contains("OUTPUT") })
    }

    @Test
    fun `错误文本提到target名称也不能制造能力假阳性`() {
        val exec = ScriptExecutor().apply {
            redirectCode = 1
            redirectErr = "Couldn't load target REDIRECT: No such file"
            redirectProbeAvailable = false
            rejectAvailable = false
            rejectProbeAvailable = false
        }

        val caps = probe(exec)

        assertFalse(caps.redirectTarget)
        assertFalse(caps.rejectTarget)
        assertFalse(caps.requiredOk())
        assertTrue("REDIRECT" in caps.missingRequired())
    }

    @Test
    fun `ipset与REJECT为可选增强能力`() {
        val exec = ScriptExecutor().apply {
            ipsetExists = true
            rejectAvailable = true
        }
        val caps = probe(exec)
        assertTrue(caps.requiredOk())
        assertTrue(caps.ipset)
        assertTrue(caps.rejectTarget)
    }

    @Test
    fun `IPv6仅在完整nat owner redirect save restore能力齐全时启用`() {
        val exec = ScriptExecutor().apply {
            ip6tablesVersionOk = true
            ip6SaveExists = true
            ip6RestoreExists = true
            ip6NatOk = true
            ip6RejectAvailable = true
        }

        val caps = probe(exec)

        assertTrue(caps.ipv6Netfilter)
        assertTrue(caps.ipv6RejectTarget)
    }

    @Test
    fun `IPv6缺少restore时保持禁用而不影响IPv4后端`() {
        val exec = ScriptExecutor().apply {
            ip6tablesVersionOk = true
            ip6SaveExists = true
            ip6RestoreExists = false
            ip6NatOk = true
        }

        val caps = probe(exec)

        assertFalse(caps.ipv6Netfilter)
        assertFalse(caps.ipv6RejectTarget)
        assertTrue(caps.requiredOk())
    }

    @Test
    fun `save 二进制缺失但规则读取和PATH中的restore可用时仍过门`() {
        val inner = ScriptExecutor().also {
            it.saveExists = false
            it.restoreExists = false
        }
        val caps = RootCapabilityProbe(
            RootShell(executor = object : ShellExecutor {
                override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
                    if (
                        script == "iptables -S" || script == "iptables-save -t nat" ||
                        script == "iptables-restore --version"
                    ) {
                        return RootShell.Result(0, "-P OUTPUT ACCEPT", "", false)
                    }
                    return inner.exec(suPath, script, timeoutSec)
                }
            }),
            10123,
        ).probe()
        assertTrue(caps.iptablesSave)
        assertTrue(caps.iptablesRestore)
        assertTrue(caps.requiredOk())
    }

    @Test
    fun `规则读取可用不能掩盖restore缺失`() {
        val inner = ScriptExecutor().also {
            it.saveExists = false
            it.restoreExists = false
        }
        val caps = RootCapabilityProbe(
            RootShell(executor = object : ShellExecutor {
                override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
                    if (script == "iptables -S" || script == "iptables-save -t nat") {
                        return RootShell.Result(0, "-P OUTPUT ACCEPT", "", false)
                    }
                    return inner.exec(suPath, script, timeoutSec)
                }
            }),
            10123,
        ).probe()
        assertTrue(caps.iptablesSave)
        assertFalse(caps.iptablesRestore)
        assertFalse(caps.requiredOk())
        assertTrue("iptables-restore" in caps.missingRequired())
    }

    @Test
    fun `parseUid 兼容 KernelSU 日志与 uid 0 root 格式`() {
        assertEquals(0, RootCapabilityProbe.parseUid("0"))
        assertEquals(0, RootCapabilityProbe.parseUid("KernelSU: foo\n0\n"))
        assertEquals(0, RootCapabilityProbe.parseUid("uid=0(root) gid=0(root)"))
        assertEquals(10123, RootCapabilityProbe.parseUid("10123"))
        assertEquals(-1, RootCapabilityProbe.parseUid("Permission denied"))
    }

    @Test
    fun `isRootId 只在解析到 0 时成立`() {
        assertTrue(ProcessShellExecutor.isRootId(RootShell.Result(0, "0", "", false)))
        assertTrue(ProcessShellExecutor.isRootId(RootShell.Result(0, "uid=0(root)", "", false)))
        assertFalse(ProcessShellExecutor.isRootId(RootShell.Result(1, "", "denied", false)))
        assertFalse(ProcessShellExecutor.isRootId(RootShell.Result(1, "0", "denied", false)))
        assertFalse(ProcessShellExecutor.isRootId(RootShell.Result(0, "10123", "", false)))
    }
}

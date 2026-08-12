package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * RootShell 测试：sanitize 白名单（拒绝注入载体）+ exec 经注入 executor 的
 * 拼接/超时/失败路径（不执行真实 su）。
 */
class RootShellTest {

    // ---------- sanitize ----------

    @Test
    fun `sanitize 放行合法 iptables 命令`() {
        assertEquals(
            "iptables -t nat -A OUTPUT -j GHD_DNS",
            RootShell.sanitize("iptables -t nat -A OUTPUT -j GHD_DNS"),
        )
        // iptables 语法必需字符：!（owner 反匹配）、[ ]（restore 计数器）
        assertEquals(
            "iptables -t nat -A GHD_TCP -m owner ! --uid-owner 10123 -d 10.0.0.10/32 -p tcp --dport 443 -j REDIRECT --to-ports 7010",
            RootShell.sanitize("iptables -t nat -A GHD_TCP -m owner ! --uid-owner 10123 -d 10.0.0.10/32 -p tcp --dport 443 -j REDIRECT --to-ports 7010"),
        )
        assertEquals(":GHD_DNS - [0:0]", RootShell.sanitize(":GHD_DNS - [0:0]"))
    }

    @Test
    fun `sanitize 拒绝分号`() {
        assertRejected("iptables -L; rm -rf /")
        assertRejected(";")
    }

    @Test
    fun `sanitize 拒绝美元符与命令替换`() {
        assertRejected("cat \$HOME")
        assertRejected("iptables -L \$(rm -rf /)")
    }

    @Test
    fun `sanitize 拒绝反引号`() {
        assertRejected("""iptables -L `rm -rf /`""")
    }

    @Test
    fun `sanitize 拒绝换行（行注入）`() {
        assertRejected("iptables -A OUTPUT -j ACCEPT\nrm -rf /")
    }

    @Test
    fun `sanitize 拒绝与符号 管道竖线放行`() {
        assertRejected("cmd & cmd2")
        assertRejected("cmd && cmd2")
        // 竖线在白名单内（管道拼接本身可预期）
        RootShell.sanitize("iptables -t nat -S | head")
    }

    @Test
    fun `sanitize 拒绝小括号与重定向`() {
        assertRejected("(cmd)")
        assertRejected("cmd < /etc/shadow")
        assertRejected("cmd > /dev/null")
        assertRejected("cmd { }")
    }

    @Test
    fun `sanitize 拒绝空命令`() {
        assertRejected("")
    }

    private fun assertRejected(cmd: String) {
        try {
            RootShell.sanitize(cmd)
            fail("应拒绝: [$cmd]")
        } catch (e: IllegalArgumentException) {
            // 预期
        }
    }

    // ---------- exec 行为 ----------

    private class FakeExecutor(
        var result: RootShell.Result = RootShell.Result(0, "", "", false),
    ) : ShellExecutor {
        val calls = mutableListOf<Pair<String, String>>()
        var lastTimeout = -1
        override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
            calls += suPath to script
            lastTimeout = timeoutSec
            return result
        }
    }

    @Test
    fun `exec 以 su -c 拼接多条命令并透传超时`() {
        val fake = FakeExecutor()
        val shell = RootShell(suPath = "su", executor = fake)

        shell.exec("iptables -t nat -F GHD_DNS", "iptables -t nat -X GHD_DNS", timeoutSec = 7)

        assertEquals(1, fake.calls.size)
        assertEquals("su", fake.calls[0].first)
        assertEquals("iptables -t nat -F GHD_DNS\niptables -t nat -X GHD_DNS", fake.calls[0].second)
        assertEquals(7, fake.lastTimeout)
    }

    @Test
    fun `exec 超时结果透传`() {
        val fake = FakeExecutor(result = RootShell.Result(-1, "", "timeout", timedOut = true))
        val shell = RootShell(executor = fake)

        val r = shell.exec("true", timeoutSec = 1)

        assertTrue(r.timedOut)
        assertEquals(-1, r.code)
    }

    @Test
    fun `exec 非法命令不调用 executor`() {
        val fake = FakeExecutor()
        val shell = RootShell(executor = fake)

        try {
            shell.exec("iptables -L; rm -rf /")
            fail("应抛 IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
        }
        assertEquals(0, fake.calls.size)
    }

    @Test
    fun `execRestoreScript 跳过白名单执行 restore 脚本`() {
        val fake = FakeExecutor(result = RootShell.Result(0, "", "", false))
        val shell = RootShell(executor = fake)

        val script = "*nat\n:OUTPUT ACCEPT [0:0]\nCOMMIT"
        val r = shell.execRestoreScript(script, timeoutSec = 15)

        assertTrue(r.ok)
        assertEquals(1, fake.calls.size)
        assertEquals(script, fake.calls[0].second)
        assertEquals(15, fake.lastTimeout)
    }

    @Test
    fun `result ok 语义`() {
        assertTrue(RootShell.Result(0, "", "", false).ok)
        assertFalse(RootShell.Result(1, "", "", false).ok)
        assertFalse(RootShell.Result(0, "", "", true).ok)
        assertFalse(RootShell.Result(-1, "", "", false).ok)
    }
}

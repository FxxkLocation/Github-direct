package org.xiyu.githubdirect.root

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootFailOpenGuardianTest {

    private val token = "0123456789abcdef0123456789abcdef"

    private class RecordingExecutor : ShellExecutor {
        val scripts = mutableListOf<String>()

        override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
            scripts += script
            return RootShell.Result(0, "", "", false)
        }
    }

    @Test
    fun `守护脚本13秒失效且只包含明确GHD清理目标`() {
        val executor = RecordingExecutor()
        val guardian = RootFailOpenGuardian(RootShell(executor = executor), 10123, token)
        val started = guardian.start(
            listOf(
                "iptables -t nat -D OUTPUT -j GHD_TCP",
                "iptables -t nat -F GHD_TCP",
                "iptables -t nat -X GHD_TCP",
            ),
        )
        assertTrue(started)
        val launch = executor.scripts.last()
        assertTrue(launch.contains("-ge 13"))
        assertTrue(launch.contains("-ge 8"))
        assertTrue(launch.contains("sleep 2"))
        assertTrue(launch.contains("GHD_TCP"))
        assertTrue(launch.contains("/proc/uptime"))
        assertTrue(launch.contains("oldpid="))
        assertTrue(launch.contains("guardian_pid_alive \"\$oldpid\""))
        assertTrue(launch.contains("/proc/\$candidate/cmdline"))
        assertTrue(launch.contains("grep -F \"/data/local/tmp/ghd_guard_10123.owner\""))
        assertTrue(launch.contains("-lt 15"))
        assertTrue(launch.contains("ghd_guard_10123.owner"))
        assertTrue(launch.contains("echo $token > /data/local/tmp/ghd_guard_10123.owner"))
        assertTrue(launch.contains("owns || exit 0"))
        assertTrue(launch.contains("dumpsys package org.xiyu.githubdirect"))
        assertTrue(launch.contains("grep \"User 0:\""))
        assertTrue(launch.contains("*\"stopped=false\"*"))
        assertTrue(launch.contains("/data/user/0/org.xiyu.githubdirect/shared_prefs/direct_settings.xml"))
        assertTrue(launch.contains("name=\\\"root.service.enabled\\\""))
        assertTrue(launch.contains("value=\\\"true\\\""))
        assertTrue(launch.contains("ghd_guard_10123.restart"))
        assertTrue(launch.contains("-lt 60"))
        assertTrue(launch.contains("dumpsys activity services"))
        assertTrue(launch.contains("grep \"ServiceRecord{\""))
        assertTrue(launch.contains("app=ProcessRecord{"))
        assertTrue(launch.contains("isForeground=true"))
        assertTrue(launch.contains("ghd_guard_10123.recovery"))
        assertTrue(launch.contains("org.xiyu.githubdirect.action.ROOT_RESTORE"))
        assertFalse("Activity 进程不能代替 ServiceRecord 判定", launch.contains("pidof "))
        assertTrue(
            launch.contains(
                "am start-foreground-service --user 0 -n " +
                    "org.xiyu.githubdirect/org.xiyu.githubdirect.root.RootRelayService",
            ),
        )
        assertTrue(
            "新代 owner 必须在通知旧 guardian 前发布",
            launch.indexOf("echo $token >") < launch.indexOf("touch /data/local/tmp/ghd_guard_10123.stop"),
        )
        assertTrue(
            "执行清理前必须再次验证代际所有权",
            launch.lastIndexOf("owns || exit 0") < launch.indexOf("iptables -t nat -D OUTPUT -j GHD_TCP"),
        )
        assertFalse(launch.contains("date +%s"))
        assertFalse(launch.contains("stat -c %Y"))
        assertFalse("守护器不得用通配符删除链", launch.contains("GHD_*"))

        assertTrue(guardian.heartbeat())
        val heartbeat = executor.scripts.last()
        assertTrue(heartbeat.startsWith("set -e\n"))
        assertTrue(heartbeat.contains("guardian_pid_alive \"\$(cat /data/local/tmp/ghd_guard_10123.pid)\""))
        assertTrue(heartbeat.contains("/proc/\$candidate/cmdline"))
        assertTrue(heartbeat.contains("/proc/uptime"))
        assertTrue(heartbeat.contains("ghd_guard_10123.owner"))
        assertTrue(heartbeat.contains(token))
    }

    @Test
    fun `多用户UID恢复到对应Android用户`() {
        val executor = RecordingExecutor()
        val guardian = RootFailOpenGuardian(RootShell(executor = executor), 1_010_123, token)

        assertTrue(guardian.start(listOf("iptables -t nat -F GHD_TCP")))

        val launch = executor.scripts.single()
        assertTrue(launch.contains("ghd_guard_1010123.owner"))
        assertTrue(launch.contains("grep \"User 10:\""))
        assertTrue(launch.contains("/data/user/10/org.xiyu.githubdirect/shared_prefs/direct_settings.xml"))
        assertTrue(launch.contains("am start-foreground-service --user 10"))
    }

    @Test
    fun `非GHD命令拒绝进入守护器`() {
        val executor = RecordingExecutor()
        val guardian = RootFailOpenGuardian(RootShell(executor = executor), 10123, token)
        assertFalse(guardian.start(listOf("iptables -t nat -F OUTPUT")))
        assertFalse(guardian.start(listOf("echo injected GHD_TCP")))
        assertFalse(guardian.start(listOf("iptables -t nat -F GHD_TCP\nreboot")))
        assertTrue(executor.scripts.isEmpty())
    }

    @Test
    fun `守护器只接受模块保留范围内的IPv6策略路由清理`() {
        val executor = RecordingExecutor()
        val guardian = RootFailOpenGuardian(RootShell(executor = executor), 10123, token)

        assertTrue(
            guardian.start(
                listOf(
                    "ip -6 rule del table 52123",
                    "ip -6 route flush table 52123",
                ),
            ),
        )
        val launch = executor.scripts.single()
        assertTrue(launch.contains("ip -6 rule del table 52123"))
        assertTrue(launch.contains("ip -6 route flush table 52123"))

        val rejected = RootFailOpenGuardian(
            RootShell(executor = RecordingExecutor()),
            10123,
            token,
        )
        assertFalse(rejected.start(listOf("ip -6 route flush table 1019")))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `owner token拒绝shell元字符`() {
        RootFailOpenGuardian(RootShell(executor = RecordingExecutor()), 10123, "bad;reboot")
    }
}

package org.xiyu.githubdirect.root

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

/**
 * RootShell —— 安全执行 root 命令（设计 §66/§67）。
 *
 * - 通过 `su -c <script>` 一次执行多条命令（命令以换行拼接，逐条白名单校验）。
 * - 超时秒级必达：`waitFor(timeout)` 超时后 `destroyForcibly`，绝不无界等待。
 * - stdout/stderr 截断至 64KB。
 *
 * 执行器可注入（[ShellExecutor]），测试用假实现覆盖超时/失败路径。
 * 注意：本类不 import 任何 android.* 类，纯 JVM。
 */
class RootShell(
    private val suPath: String = "su",
    private val executor: ShellExecutor = ProcessShellExecutor(),
) {

    /**
     * 执行命令序列（每条命令被 [sanitize] 白名单校验，非法则抛 IllegalArgumentException，
     * 不发起任何进程）。返回 exit code + stdout + stderr + 是否超时。
     */
    fun exec(vararg cmds: String, timeoutSec: Int = 10): Result {
        require(timeoutSec > 0) { "timeoutSec 必须 > 0" }
        cmds.forEach { sanitize(it) }
        return executor.exec(suPath, cmds.joinToString("\n"), timeoutSec)
    }

    /**
     * 执行 iptables-restore 安装脚本（仅内部使用）。
     * 脚本由 [FirewallRules] 纯生成（含 `*nat`/`COMMIT` 等 restore 必需语法，
     * 字符集超出 [sanitize] 白名单），无任何外部输入，故跳过白名单校验。
     */
    internal fun execRestoreScript(script: String, timeoutSec: Int = 20): Result {
        require(timeoutSec > 0) { "timeoutSec 必须 > 0" }
        require(script.isNotBlank())
        return executor.exec(suPath, script, timeoutSec)
    }

    /** 单条命令的退出结果。code=-1 表示进程无法启动或已被超时强杀。 */
    data class Result(val code: Int, val out: String, val err: String, val timedOut: Boolean) {
        val ok: Boolean get() = code == 0 && !timedOut
    }

    companion object {
        /** 命令串白名单字符集：只允许这些字符，`; & $ ` \n ( )` 等注入载体全部拒绝。 */
        private const val ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .:/_-|'\"![]"

        /**
         * 命令串白名单校验：只允许 [a-zA-Z0-9 .:/_\-|"'] 字符集，禁止 `; & $ 反引号 \n ( )` 等注入载体。
         * 额外放行 `!`（iptables owner 反匹配 `! --uid-owner` 必需，非交互 sh 中参数内 `!` 为字面量）
         * 与 `[` `]`（iptables-restore 计数器语法 `[0:0]`）。
         * 校验通过原样返回；失败抛 IllegalArgumentException。
         */
        fun sanitize(cmd: String): String {
            if (cmd.isEmpty()) throw IllegalArgumentException("命令为空")
            val bad = cmd.firstOrNull { it !in ALLOWED_CHARS }
            if (bad != null) {
                throw IllegalArgumentException("命令包含非法字符 '$bad'（仅允许: $ALLOWED_CHARS）: $cmd")
            }
            return cmd
        }
    }
}

/**
 * 命令执行器抽象（测试注入点）。
 */
interface ShellExecutor {
    fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result
}

/**
 * 真实实现：ProcessBuilder 启动 su；stdout/stderr 各自独立线程读取；
 * waitFor(timeout) 秒级必达，超时 destroyForcibly。
 */
class ProcessShellExecutor : ShellExecutor {

    override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
        val pb = ProcessBuilder(suPath, "-c", script)
        val process = try {
            pb.start()
        } catch (e: IOException) {
            return RootShell.Result(-1, "", "无法启动 $suPath: ${e.message}", false)
        }

        val outBuf = ByteArrayOutputStream(8192)
        val errBuf = ByteArrayOutputStream(4096)
        val outThread = Thread {
            try {
                pump(process.inputStream, outBuf)
            } catch (_: IOException) {
            }
        }
        val errThread = Thread {
            try {
                pump(process.errorStream, errBuf)
            } catch (_: IOException) {
            }
        }
        outThread.isDaemon = true
        errThread.isDaemon = true
        outThread.start()
        errThread.start()

        val finished = try {
            process.waitFor(timeoutSec.toLong(), TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            process.destroyForcibly()
            false
        }

        if (!finished) {
            process.destroyForcibly()
            try {
                process.waitFor(2, TimeUnit.SECONDS)
            } catch (_: InterruptedException) {
            }
            joinQuietly(outThread, 500)
            joinQuietly(errThread, 500)
            return RootShell.Result(
                -1,
                truncate(outBuf.toString(StandardCharsets.UTF_8.name())),
                truncate(errBuf.toString(StandardCharsets.UTF_8.name())),
                timedOut = true,
            )
        }

        joinQuietly(outThread, 500)
        joinQuietly(errThread, 500)
        return RootShell.Result(
            process.exitValue(),
            truncate(outBuf.toString(StandardCharsets.UTF_8.name())),
            truncate(errBuf.toString(StandardCharsets.UTF_8.name())),
            timedOut = false,
        )
    }

    private fun pump(input: java.io.InputStream, out: ByteArrayOutputStream) {
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
        }
    }

    private fun truncate(s: String): String = if (s.length > MAX_CAPTURE) s.substring(0, MAX_CAPTURE) else s

    private fun joinQuietly(t: Thread, ms: Long) {
        try {
            t.join(ms)
        } catch (_: InterruptedException) {
        }
    }

    companion object {
        private const val MAX_CAPTURE = 64 * 1024
    }
}

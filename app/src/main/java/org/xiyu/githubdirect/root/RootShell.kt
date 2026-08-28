package org.xiyu.githubdirect.root

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

/**
 * RootShell —— 安全执行 root 命令（设计 §66/§67）。
 *
 * - 通过 `su -c <script>` 一次执行多条命令（命令以换行拼接，逐条白名单校验）。
 * - KernelSU / Magisk：自动尝试常见 su 绝对路径（`su` 经常不在 app 的 PATH 里）。
 * - iptables-restore 走 stdin，绝不把 restore 脚本当 `su -c` 的 shell 命令执行。
 * - 超时秒级必达：`waitFor(timeout)` 超时后 `destroyForcibly`。
 */
class RootShell(
    private val suPath: String = "su",
    private val executor: ShellExecutor = ProcessShellExecutor(),
) {
    fun exec(vararg cmds: String, timeoutSec: Int = 10): Result {
        require(timeoutSec > 0) { "timeoutSec 必须 > 0" }
        cmds.forEach { sanitize(it) }
        return executor.exec(suPath, cmds.joinToString("\n"), timeoutSec)
    }

    /**
     * 内部事务步骤使用：任一条白名单命令失败即返回失败，避免后续成功命令掩盖前序错误。
     * 清理路径仍使用 [exec]，以便某条不存在的规则不阻断其余幂等清理。
     */
    internal fun execStrict(vararg cmds: String, timeoutSec: Int = 10): Result {
        require(timeoutSec > 0) { "timeoutSec 必须 > 0" }
        require(cmds.isNotEmpty()) { "命令为空" }
        cmds.forEach { sanitize(it) }
        return executor.exec(suPath, "set -e\n" + cmds.joinToString("\n"), timeoutSec)
    }

    /**
     * 把 iptables-restore 脚本写进 `su -c iptables-restore --noflush` 的 stdin。
     * 脚本由 [FirewallRules] 生成（含 `*nat`/`COMMIT`），不能走 [sanitize] / `su -c <整份脚本>`。
     */
    internal fun execRestoreScript(script: String, timeoutSec: Int = 20): Result {
        require(timeoutSec > 0) { "timeoutSec 必须 > 0" }
        require(script.isNotBlank())
        return executor.execRestore(suPath, terminateRestoreScript(script), timeoutSec)
    }

    /** IPv6 规则必须走独立的 ip6tables-restore stdin，不能混入 IPv4 restore 事务。 */
    internal fun execIpv6RestoreScript(script: String, timeoutSec: Int = 20): Result {
        require(timeoutSec > 0) { "timeoutSec 必须 > 0" }
        require(script.isNotBlank())
        return executor.execIpv6Restore(suPath, terminateRestoreScript(script), timeoutSec)
    }

    /**
     * 仅供模块内部生成的守护脚本使用。与用户输入无关，并限制长度/NUL；普通命令仍必须走
     * [exec] 的严格字符白名单，避免扩大 shell 注入面。
     */
    internal fun execTrustedScript(script: String, timeoutSec: Int = 20): Result {
        require(timeoutSec > 0) { "timeoutSec 必须 > 0" }
        require(script.isNotBlank() && script.length <= MAX_TRUSTED_SCRIPT)
        require('\u0000' !in script)
        return executor.exec(suPath, script, timeoutSec)
    }

    /** 单条命令的退出结果。code=-1 表示进程无法启动或已被超时强杀。 */
    data class Result(val code: Int, val out: String, val err: String, val timedOut: Boolean) {
        val ok: Boolean get() = code == 0 && !timedOut
        /** stdout+stderr，iptables --help 常写在 stderr。 */
        fun text(): String = if (err.isEmpty()) out else "$out\n$err"

        /**
         * 面向状态页/日志的有界摘要。只包含退出状态和子进程输出，不包含调用命令或 restore 脚本。
         */
        fun diagnosticSummary(maxChars: Int = 512): String {
            require(maxChars > 0)
            val status = if (timedOut) "timeout" else "exit=$code"
            val output = (if (err.isNotBlank()) err else out)
                .replace(Regex("\\s+"), " ")
                .trim()
            if (output.isEmpty()) return status
            val available = (maxChars - status.length - 2).coerceAtLeast(0)
            return if (available == 0) status else "$status: ${output.take(available)}"
        }
    }

    companion object {
        /** 命令串白名单字符集：只允许内部命令实际需要的字符，shell 控制符与引号全部拒绝。 */
        private const val ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .:/_-![]"
        private const val MAX_TRUSTED_SCRIPT = 64 * 1024

        private fun terminateRestoreScript(script: String): String =
            if (script.endsWith('\n')) script else "$script\n"

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

    /** 默认把脚本当 shell 执行（测试 fake 够用）；生产实现必须改成 restore stdin。 */
    fun execRestore(suPath: String, restoreScript: String, timeoutSec: Int): RootShell.Result =
        exec(suPath, restoreScript, timeoutSec)

    /** 默认委托普通 fake 执行；生产实现覆盖为 ip6tables-restore stdin。 */
    fun execIpv6Restore(suPath: String, restoreScript: String, timeoutSec: Int): RootShell.Result =
        exec(suPath, restoreScript, timeoutSec)
}

internal data class SuHandle(val path: String, val insertUid0: Boolean) {
    fun args(command: String): List<String> =
        if (insertUid0) listOf(path, "0", "-c", command) else listOf(path, "-c", command)
}

/**
 * 真实实现：定位 KernelSU/Magisk 的 su，再 ProcessBuilder 启动。
 *
 * 关键坑：
 * - 不能把「文件存在但不是已授权 root」的 `/system/bin/su` 缓存下来（toybox/stub 会挡住 KernelSU）。
 * - `su -c` 经 sh 执行时若不关闭 stdin，会一直等输入直到超时，表现为「给了 ROOT 仍探测失败」。
 */
class ProcessShellExecutor(
    private val suCandidates: List<String> = SU_CANDIDATES,
) : ShellExecutor {

    @Volatile
    private var working: SuHandle? = null

    @Volatile
    private var lastSuMiss: RootShell.Result =
        RootShell.Result(-1, "", "未找到可用的 su（KernelSU/Magisk 未授权或 su 不在 PATH）", false)

    override fun exec(suPath: String, script: String, timeoutSec: Int): RootShell.Result {
        val handle = resolveSu(suPath, timeoutSec) ?: return lastSuMiss
        return runProcess(handle.args(script), timeoutSec, stdin = null)
    }

    override fun execRestore(suPath: String, restoreScript: String, timeoutSec: Int): RootShell.Result {
        return runRestore(suPath, restoreScript, timeoutSec, RESTORE_COMMANDS, "iptables-restore")
    }

    override fun execIpv6Restore(suPath: String, restoreScript: String, timeoutSec: Int): RootShell.Result {
        return runRestore(suPath, restoreScript, timeoutSec, RESTORE_COMMANDS_V6, "ip6tables-restore")
    }

    private fun runRestore(
        suPath: String,
        restoreScript: String,
        timeoutSec: Int,
        restoreCommands: List<String>,
        label: String,
    ): RootShell.Result {
        val handle = resolveSu(suPath, timeoutSec) ?: return lastSuMiss
        val payload = restoreScript.toByteArray(StandardCharsets.UTF_8)
        var last = RootShell.Result(-1, "", "$label 不可用", false)
        for (restoreCmd in restoreCommands) {
            val r = runProcess(handle.args(restoreCmd), timeoutSec, stdin = payload)
            last = r
            if (r.ok) return r
            if (r.timedOut) return r
            val text = r.text().lowercase()
            if ("not found" in text || "no such" in text || "can't exec" in text || "cannot" in text) {
                continue
            }
            return r
        }
        return last
    }

    @Synchronized
    private fun resolveSu(preferred: String, timeoutSec: Int): SuHandle? {
        working?.let { return it }

        val paths = LinkedHashSet<String>()
        paths.addAll(suCandidates)
        if (preferred.isNotBlank()) paths += preferred

        var last = lastSuMiss
        val probeTimeout = timeoutSec.coerceIn(5, 15)
        for (path in paths) {
            val plain = runProcess(listOf(path, "-c", "id -u"), probeTimeout, stdin = null)
            last = plain
            if (isMissingBinary(plain)) continue
            if (isRootId(plain)) {
                val handle = SuHandle(path, insertUid0 = false)
                working = handle
                return handle
            }
            val withUid = runProcess(listOf(path, "0", "-c", "id -u"), probeTimeout, stdin = null)
            last = withUid
            if (isRootId(withUid)) {
                val handle = SuHandle(path, insertUid0 = true)
                working = handle
                return handle
            }
        }
        lastSuMiss = last
        return null
    }

    private fun runProcess(cmd: List<String>, timeoutSec: Int, stdin: ByteArray?): RootShell.Result {
        val pb = ProcessBuilder(cmd)
        val path = pb.environment()["PATH"] ?: ""
        pb.environment()["PATH"] = "$EXTRA_PATH$path"
        val process = try {
            pb.start()
        } catch (e: IOException) {
            return RootShell.Result(-1, "", "无法启动 ${cmd.first()}: ${e.message}", false)
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

        // stdin 必须异步写入并关闭：su/sh 依赖 EOF；restore payload 若大于管道容量，
        // 同步 write 会在 waitFor 之前永久阻塞，使 timeoutSec 失效。
        val stdinThread = Thread {
            try {
                process.outputStream.use { out ->
                    if (stdin != null) out.write(stdin)
                }
            } catch (_: IOException) {
            }
        }.apply {
            isDaemon = true
            start()
        }

        var interrupted = false
        val finished = try {
            process.waitFor(timeoutSec.toLong(), TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            interrupted = true
            process.destroyForcibly()
            false
        }

        if (!finished) {
            runCatching { process.outputStream.close() }
            process.destroyForcibly()
            try {
                process.waitFor(2, TimeUnit.SECONDS)
            } catch (_: InterruptedException) {
                interrupted = true
            }
            joinQuietly(stdinThread, 500)
            joinQuietly(outThread, 500)
            joinQuietly(errThread, 500)
            if (interrupted) Thread.currentThread().interrupt()
            return RootShell.Result(
                -1,
                truncate(outBuf.toString(StandardCharsets.UTF_8.name())),
                truncate(errBuf.toString(StandardCharsets.UTF_8.name())),
                timedOut = true,
            )
        }

        joinQuietly(stdinThread, 500)
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
            val remaining = MAX_CAPTURE - out.size()
            if (remaining > 0) out.write(buf, 0, minOf(n, remaining))
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
        // 多 UID 的 iptables -S 可达到数百 KiB；继续读取并丢弃超限部分，避免子进程管道阻塞。
        private const val MAX_CAPTURE = 4 * 1024 * 1024
        private const val EXTRA_PATH =
            "/debug_ramdisk:/debug_ramdisk/bin:/data/adb/ksu/bin:/system/bin:/system/xbin:/sbin:/vendor/bin:"

        val SU_CANDIDATES: List<String> = listOf(
            "/debug_ramdisk/su",
            "/debug_ramdisk/bin/su",
            "/data/adb/ksu/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/system/bin/su",
            "su",
        )

        private val RESTORE_COMMANDS = listOf(
            "iptables-restore --noflush",
            "/system/bin/iptables-restore --noflush",
            "iptables-legacy-restore --noflush",
            "iptables-nft-restore --noflush",
        )

        private val RESTORE_COMMANDS_V6 = listOf(
            "ip6tables-restore --noflush",
            "/system/bin/ip6tables-restore --noflush",
            "ip6tables-legacy-restore --noflush",
            "ip6tables-nft-restore --noflush",
        )

        fun isMissingBinary(r: RootShell.Result): Boolean =
            r.code == -1 && !r.timedOut && r.err.startsWith("无法启动")

        fun isRootId(r: RootShell.Result): Boolean =
            r.ok && RootCapabilityProbe.parseUid(r.text()) == 0
    }
}

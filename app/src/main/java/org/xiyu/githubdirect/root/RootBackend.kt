package org.xiyu.githubdirect.root

/**
 * 后端生命周期状态机（fail-open 事务化，设计 §19-§22）。
 *
 * STOPPED → STARTING → probe → 启动监听 → 安装规则 → verify → self-test → ACTIVE
 * 任何失败：rollback（清理规则 + 停监听）→ FAILED。stop/崩溃恢复 = 清理自有 chain。
 *
 * 注意（§22 文档化限制）：self-test 无法从自身 UID 走 REDIRECT（所有规则带
 * `! --uid-owner self` 排除），因此自检只验证「监听存活 + 规则链存在」，
 * 真实流量路径由集成层/实机验证（NEEDS_DEVICE_VERIFICATION）。
 */
enum class BackendState { STOPPED, STARTING, ACTIVE, FAILED }

/**
 * Root Transparent 后端（核心网络部分；不涉及 UI 与集成）。
 *
 * @param shell          安全 shell（su 执行器，可注入）
 * @param capabilities   能力探测器（可注入）
 * @param dnsListener    DNS 拦截监听（可注入 fake）
 * @param tcpListener    TCP 透明中继监听（可注入 fake）
 * @param rulesBuilder   规则构造器：集成层注入 scope 配置，selfUid 由 start 时探测结果提供
 */
class RootBackend(
    private val shell: RootShell,
    private val capabilities: CapabilityProber,
    private val dnsListener: DnsListener,
    private val tcpListener: TcpListener,
    private val rulesBuilder: (selfUid: Int) -> FirewallRules,
) {

    @Volatile
    private var backendState: BackendState = BackendState.STOPPED
    private var lastSelfUid: Int = -1

    val state: BackendState get() = backendState

    /**
     * 启动（幂等：ACTIVE 时直接返回 true，不重复安装）。
     * 顺序：probe → cleanupStale（先清残留）→ dnsListener.start → tcpListener.start →
     * 生成规则 → iptables-restore --noflush 安装 → verify（iptables-save 含特征行）→ self-test → ACTIVE。
     * 任何失败：rollback → FAILED → false。
     */
    @Synchronized
    fun start(
        dnsHandler: (ByteArray) -> ByteArray?,
        resolveRealIp: (Int) -> ByteArray?,
    ): Boolean {
        if (backendState == BackendState.ACTIVE) return true
        backendState = BackendState.STARTING

        var dnsStarted = false
        var tcpStarted = false
        var rules: FirewallRules? = null
        try {
            val caps = capabilities.probe()
            if (!caps.requiredOk()) {
                backendState = BackendState.FAILED
                return false // probe 不通过：不安装任何规则
            }
            lastSelfUid = caps.uid
            rules = rulesBuilder(caps.uid)

            cleanupStale(caps.uid) // 无条件清上次崩溃残留（幂等）

            if (!dnsListener.start(dnsHandler)) return fail()
            dnsStarted = true
            if (!tcpListener.start(resolveRealIp)) return fail()
            tcpStarted = true

            if (!installRules(rules)) return fail()

            // self-test：监听已活 + 链存在（verify 已证）。自身 UID 被规则排除，无法自测 REDIRECT 数据面
            if (!dnsListener.alive() || !tcpListener.alive()) return fail()

            backendState = BackendState.ACTIVE
            return true
        } catch (t: Throwable) {
            backendState = BackendState.FAILED
            return false
        } finally {
            if (backendState != BackendState.ACTIVE) {
                rollback(rules, dnsStarted, tcpStarted)
            }
        }
    }

    /**
     * 停止：清理规则 + 停监听 → STOPPED。幂等（STOPPED 时直接 true）。
     */
    @Synchronized
    fun stop(): Boolean {
        if (backendState == BackendState.STOPPED) return true
        if (lastSelfUid > 0) {
            try {
                cleanupStale(lastSelfUid)
            } catch (t: Throwable) {
                // 清理失败不阻断停机
            }
        }
        try {
            dnsListener.stop()
        } catch (t: Throwable) {
        }
        try {
            tcpListener.stop()
        } catch (t: Throwable) {
        }
        backendState = BackendState.STOPPED
        return true
    }

    /**
     * 轻量 watchdog（§22）：ACTIVE 状态下 监听存活 && 自有 chain 特征行仍在。
     * 失败由调用方决策 repair（先 stop 再 start）。本阶段不建线程，由集成层定时调用。
     */
    @Synchronized
    fun healthCheck(): Boolean {
        if (backendState != BackendState.ACTIVE) return false
        if (!dnsListener.alive() || !tcpListener.alive()) return false
        if (lastSelfUid <= 0) return false
        return try {
            val r = shell.exec("iptables -t nat -S", "iptables -t filter -S", timeoutSec = 8)
            if (!r.ok) return false
            val markers = rulesBuilder(lastSelfUid).expectedMarkers()
            markers.all { r.out.contains(it) }
        } catch (t: Throwable) {
            false
        }
    }

    /** 安装规则：iptables-restore --noflush 原子安装 + iptables-save 特征行校验。 */
    private fun installRules(rules: FirewallRules): Boolean {
        val script = rules.buildInstallScript()
        // restore 脚本含 *nat/COMMIT 等 restore 语法，走免白名单路径（内部生成，无外部输入）
        val result = shell.execRestoreScript(script)
        if (!result.ok) return false
        return verifyRules(rules)
    }

    private fun verifyRules(rules: FirewallRules): Boolean {
        val r = shell.exec("iptables-save -t nat", "iptables-save -t filter", timeoutSec = 15)
        if (!r.ok) return false
        val markers = rules.expectedMarkers()
        return markers.all { r.out.contains(it) }
    }

    /**
     * 清理残留（start 前置，§21 幂等）：静态清理当前 scope 的 chain + 动态清扫
     * `iptables -S` 输出中所有 `-N GHD_*` chain（覆盖上次运行 scope 与本次不同的孤儿子链）。
     * 全程只动 GHD_* 自有 chain 及其 OUTPUT jump，绝不碰他人规则。
     */
    private fun cleanupStale(selfUid: Int) {
        val rules = rulesBuilder(selfUid)
        val dynamic = try {
            val r = shell.exec("iptables -t nat -S", "iptables -t filter -S", timeoutSec = 8)
            if (r.ok) collectOwnedChains(r.out) else emptySet()
        } catch (t: Throwable) {
            emptySet()
        }
        val (natStatic, filterStatic) = rules.ownedChainNames()
        val nat = (natStatic + dynamic).distinct()
        val filter = (filterStatic + dynamic).distinct()

        val cmds = mutableListOf<String>()
        // 1) 删 OUTPUT jump（主链与未知孤儿链都尝试；不存在报错可忽略）
        nat.forEach { cmds += "iptables -t nat -D OUTPUT -j $it" }
        filter.forEach { cmds += "iptables -t filter -D OUTPUT -j $it" }
        // 2) flush 自己 chain
        nat.forEach { cmds += "iptables -t nat -F $it" }
        filter.forEach { cmds += "iptables -t filter -F $it" }
        // 3) 删自己 chain
        nat.forEach { cmds += "iptables -t nat -X $it" }
        filter.forEach { cmds += "iptables -t filter -X $it" }

        try {
            shell.exec(*cmds.toTypedArray(), timeoutSec = 20)
        } catch (t: Throwable) {
            // best-effort：清理失败不阻断（后续 restore/verify 会兜底暴露问题）
        }
    }

    /** 从 `iptables -S` 输出解析自有 chain 名（`-N GHD_*` 行）。 */
    private fun collectOwnedChains(saveOutput: String): Set<String> =
        saveOutput.lines()
            .mapNotNull { line ->
                if (line.startsWith("-N GHD_")) line.removePrefix("-N ").trim().takeIf { it.isNotBlank() } else null
            }
            .toSet()

    /** 失败路径：置 FAILED（finally 中执行 rollback）。 */
    private fun fail(): Boolean {
        backendState = BackendState.FAILED
        return false
    }

    /** rollback：cleanup 命令 + 停已启动的监听（§21）。 */
    private fun rollback(rules: FirewallRules?, dnsStarted: Boolean, tcpStarted: Boolean) {
        if (rules != null && lastSelfUid > 0) {
            try {
                cleanupStale(lastSelfUid)
            } catch (t: Throwable) {
            }
        }
        if (dnsStarted) {
            try {
                dnsListener.stop()
            } catch (t: Throwable) {
            }
        }
        if (tcpStarted) {
            try {
                tcpListener.stop()
            } catch (t: Throwable) {
            }
        }
    }
}

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

/** Root 数据面最近一次失败；stage 稳定供状态机/采集脚本使用，detail 为有界诊断。 */
data class RootBackendFailure(val stage: String, val detail: String)

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
    @Volatile private var activeRules: FirewallRules? = null
    @Volatile private var guardian: RootFailOpenGuardian? = null
    @Volatile private var lastFailureInternal: RootBackendFailure? = null

    val state: BackendState get() = backendState
    val activeGeneration: Long get() = activeRules?.generation ?: 0L
    val realIpRedirectActive: Boolean get() = activeRules?.usesRealIpRedirect() == true
    val ipv6RealIpRedirectActive: Boolean get() = activeRules?.usesIpv6RealIpRedirect() == true
    val fullTlsCaptureUidCount: Int get() = activeRules?.fullTlsCaptureUidCount() ?: 0
    val ipSetLeaseActive: Boolean get() = activeRules?.usesIpSet() == true
    val failOpenGuardianActive: Boolean get() = guardian != null
    val lastFailure: RootBackendFailure? get() = lastFailureInternal
    val unclassifiedTlsTotal: Long get() = runCatching {
        tcpListener.stats().unclassifiedTlsTotal
    }.getOrDefault(0L)
    val activeTcpSessions: Int get() = runCatching {
        tcpListener.stats().activeSessions
    }.getOrDefault(0)

    /**
     * 启动（幂等：ACTIVE 时直接返回 true，不重复安装）。
     * 顺序：probe → cleanupStale（先清残留）→ dnsListener.start → tcpListener.start →
     * 生成规则 → iptables-restore --noflush 安装 → verify（自有链含特征行）→ self-test → ACTIVE。
     * 任何失败：rollback → FAILED → false。
     */
    @Synchronized
    fun start(
        dnsHandler: (ByteArray) -> ByteArray?,
        resolveRealIp: (Int) -> ByteArray?,
    ): Boolean {
        if (backendState == BackendState.ACTIVE) return true
        backendState = BackendState.STARTING
        lastFailureInternal = null

        var dnsStarted = false
        var tcpStarted = false
        var rules: FirewallRules? = null
        var currentStage = "capabilities.probe"
        try {
            val caps = capabilities.probe()
            if (!caps.requiredOk()) {
                return fail(
                    "capabilities.required",
                    "missing=${caps.missingRequired().joinToString(",")}",
                ) // probe 不通过：不安装任何规则
            }
            lastSelfUid = caps.uid
            currentStage = "rules.build"
            rules = rulesBuilder(caps.uid)
            val nextGuardian = RootFailOpenGuardian(shell, caps.uid)
            // 先清残留，期间让上次进程留下的 guardian 继续兜底。nextGuardian.start() 会在
            // 安装新规则前通知旧 guardian 退出并等待一个完整轮询窗口，避免旧代误删新链。
            currentStage = "cleanup.stale"
            cleanupStale(caps.uid) // 无条件清上次崩溃残留（幂等）

            if (rules.usesIpSet() && !prepareIpSet(rules)) {
                // 能力探测可能因厂商工具箱包装而假阳性；此时自动回退到有上限的 CIDR 规则。
                rules = rules.withoutIpSet()
            }

            currentStage = "listener.dns"
            if (!dnsListener.start(dnsHandler)) {
                return fail(currentStage, dnsListener.lastFailureDetail.ifBlank { "start returned false" })
            }
            dnsStarted = true
            currentStage = "listener.tcp"
            if (!tcpListener.start(resolveRealIp)) {
                return fail(currentStage, tcpListener.lastFailureDetail.ifBlank { "start returned false" })
            }
            tcpStarted = true
            if (rules.usesRealIpRedirect() && !tcpListener.directActive()) {
                return fail(
                    "listener.tcp.direct",
                    tcpListener.lastFailureDetail.ifBlank { "127.0.0.1 direct listener inactive" },
                )
            }
            if (rules.usesIpv6RealIpRedirect() && !tcpListener.ipv6DirectActive()) {
                // 绝不能安装会把 IPv6/443 导向无人监听端口的规则。
                return fail(
                    "listener.tcp.direct.v6",
                    tcpListener.lastFailureDetail.ifBlank { "[::1] direct listener inactive" },
                )
            }

            // 先启动独立 guardian，再提交规则；这样进程即使在 restore/verify 窗口被杀，
            // 已安装或部分提交的 GHD_* 链也会在心跳超时后被清理。
            val guardianCleanup = rules.buildCleanupCommands() + rules.buildIpSetCleanupCommands()
            currentStage = "guardian.start"
            if (!nextGuardian.start(guardianCleanup)) {
                return fail(currentStage, nextGuardian.lastFailureDetail.ifBlank { "start returned false" })
            }
            guardian = nextGuardian

            currentStage = "firewall.install"
            if (!installRules(rules)) return false

            currentStage = "guardian.heartbeat.commit"
            if (!refreshGuardian(currentStage)) return false

            // self-test：监听已活 + 链存在（verify 已证）。自身 UID 被规则排除，无法自测 REDIRECT 数据面
            if (!dnsListener.alive()) return fail("selftest.listener.dns", "listener not alive")
            if (!tcpListener.alive()) return fail("selftest.listener.tcp", "listener not alive")

            activeRules = rules
            backendState = BackendState.ACTIVE
            lastFailureInternal = null
            return true
        } catch (t: Throwable) {
            return fail(currentStage, throwableDetail(t))
        } finally {
            if (backendState != BackendState.ACTIVE) {
                rollback(rules, dnsStarted, tcpStarted)
            }
        }
    }

    /**
     * 原位切换下一代规则。监听器和已建立的 TCP 会话不停止；iptables 只影响后续新连接，
     * 已进入双向 pump 的 TLS socket 在正常刷新期间持续转发。
     *
     * 顺序：准备 ipset（旧规则仍生效）→ 新 guardian 接管 → 原子原位 restore/verify →
     * 清理孤儿资源 → 发布 activeRules。任何失败都清理自有规则并停止监听，保持 fail-open。
     */
    @Synchronized
    fun refreshRules(): Boolean {
        if (backendState != BackendState.ACTIVE) {
            return fail("refresh.state", "state=$backendState")
        }
        val previousRules = activeRules ?: return fail("refresh.rules", "active rules missing")
        if (!dnsListener.alive() || !tcpListener.alive()) {
            return fail("refresh.listeners", "listener not alive")
        }

        backendState = BackendState.STARTING
        lastFailureInternal = null
        var nextRules: FirewallRules? = null
        var currentStage = "refresh.rules.build"
        try {
            nextRules = rulesBuilder(lastSelfUid)
            if (nextRules.usesRealIpRedirect() && !tcpListener.directActive()) {
                return fail("refresh.listener.tcp.direct", "127.0.0.1 direct listener inactive")
            }
            if (nextRules.usesIpv6RealIpRedirect() && !tcpListener.ipv6DirectActive()) {
                return fail("refresh.listener.tcp.direct.v6", "[::1] direct listener inactive")
            }

            currentStage = "refresh.ipset.prepare"
            if (nextRules.usesIpSet() && !prepareIpSet(nextRules)) {
                nextRules = nextRules.withoutIpSet()
            }

            // 清理集合取旧代与新代并集，覆盖 scope/IPv6 能力改变时的所有自有链。
            val guardianCleanup = (
                previousRules.buildCleanupCommands() +
                    previousRules.buildIpSetCleanupCommands() +
                    nextRules.buildCleanupCommands() +
                    nextRules.buildIpSetCleanupCommands()
                ).distinct()
            val nextGuardian = RootFailOpenGuardian(shell, lastSelfUid)
            currentStage = "refresh.guardian.start"
            if (!nextGuardian.start(guardianCleanup)) {
                return fail(currentStage, nextGuardian.lastFailureDetail.ifBlank { "start returned false" })
            }
            guardian = nextGuardian

            currentStage = "refresh.firewall.install"
            if (!installRefreshRules(previousRules, nextRules)) return false
            currentStage = "refresh.cleanup.obsolete"
            if (!cleanupObsoleteAfterRefresh(previousRules, nextRules)) return false
            currentStage = "refresh.guardian.heartbeat.commit"
            if (!refreshGuardian(currentStage)) return false

            activeRules = nextRules
            backendState = BackendState.ACTIVE
            lastFailureInternal = null
            return true
        } catch (t: Throwable) {
            return fail(currentStage, throwableDetail(t))
        } finally {
            if (backendState != BackendState.ACTIVE) {
                // 刷新失败时不能保留可能只安装了一半的规则；关闭监听也会结束现有会话。
                rollback(nextRules, dnsStarted = true, tcpStarted = true)
            }
        }
    }

    /**
     * 停止：清理规则 + 停监听 → STOPPED。幂等（STOPPED 时直接 true）。
     */
    @Synchronized
    fun stop(): Boolean {
        if (backendState == BackendState.STOPPED) return true
        // 不提前通知 guardian 退出。停止刷新心跳后，它仍会在 15 秒内做一次幂等清理；
        // 即使下面的同步 cleanup 失败或进程中途死亡，也不会留下永久黑洞。
        guardian = null
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
        activeRules = null
        lastFailureInternal = null
        backendState = BackendState.STOPPED
        return true
    }

    /**
     * Root 服务跨进程停止专用：即使本进程状态为 STOPPED，也探测 app UID 并清理上个进程
     * 留下的 guardian/规则。普通 UI/VPN stop 不调用它，避免无关场景触发 su 授权。
     */
    @Synchronized
    fun cleanupStaleInstallation(): Boolean {
        if (backendState != BackendState.STOPPED) return stop()
        val caps = try {
            capabilities.probe()
        } catch (_: Throwable) {
            return false
        }
        if (!caps.suAvailable || caps.uid <= 0) return false
        lastSelfUid = caps.uid
        return try {
            cleanupStale(caps.uid)
            activeRules = null
            backendState = BackendState.STOPPED
            true
        } catch (_: Throwable) {
            false
        }
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
            val rules = activeRules ?: return false
            val r = shell.exec(*rules.verificationCommands().toTypedArray(), timeoutSec = 8)
            if (!r.ok) return false
            val canonicalOutput = canonicalizeFirewallText(r.out)
            rules.expectedMarkers().all { canonicalOutput.contains(canonicalizeFirewallText(it)) }
        } catch (t: Throwable) {
            false
        }
    }

    /** 安装规则：IPv4/IPv6 分别 restore；任一失败都由调用方整体 rollback。 */
    private fun installRules(rules: FirewallRules): Boolean {
        val script = rules.buildInstallScript()
        // restore 脚本含 *nat/COMMIT 等 restore 语法，走免白名单路径（内部生成，无外部输入）
        if (!refreshGuardian("guardian.heartbeat.pre-restore-v4")) return false
        val result = shell.execRestoreScript(script, timeoutSec = GUARDIAN_SAFE_COMMAND_TIMEOUT_SECONDS)
        if (!result.ok) return fail("firewall.restore.v4", result.diagnosticSummary())
        if (!refreshGuardian("guardian.heartbeat.post-restore-v4")) return false
        val scriptV6 = rules.buildIpv6InstallScript()
        if (scriptV6.isNotBlank()) {
            val resultV6 = shell.execIpv6RestoreScript(
                scriptV6,
                timeoutSec = GUARDIAN_SAFE_COMMAND_TIMEOUT_SECONDS,
            )
            if (!resultV6.ok) return fail("firewall.restore.v6", resultV6.diagnosticSummary())
            if (!refreshGuardian("guardian.heartbeat.post-restore-v6")) return false
        }
        return verifyRules(rules)
    }

    /**
     * ACTIVE 代次原位替换。IPv4 用户链在各自表的 COMMIT 瞬间清空并重建，OUTPUT jump
     * 始终保留；IPv6 根据启用状态执行安装、原位替换或原子摘除。
     */
    private fun installRefreshRules(previous: FirewallRules, next: FirewallRules): Boolean {
        if (!refreshGuardian("guardian.heartbeat.pre-refresh-restore-v4")) return false
        val result = shell.execRestoreScript(
            next.buildRefreshScript(),
            timeoutSec = GUARDIAN_SAFE_COMMAND_TIMEOUT_SECONDS,
        )
        if (!result.ok) return fail("firewall.restore.v4", result.diagnosticSummary())
        if (!refreshGuardian("guardian.heartbeat.post-refresh-restore-v4")) return false

        val scriptV6 = next.buildIpv6RefreshScript(previous)
        if (scriptV6.isNotBlank()) {
            val resultV6 = shell.execIpv6RestoreScript(
                scriptV6,
                timeoutSec = GUARDIAN_SAFE_COMMAND_TIMEOUT_SECONDS,
            )
            if (!resultV6.ok) return fail("firewall.restore.v6", resultV6.diagnosticSummary())
            if (!refreshGuardian("guardian.heartbeat.post-refresh-restore-v6")) return false
        }
        return verifyRules(next)
    }

    /** 新规则已验证后删除无引用的旧子链/集合；命令失败不影响已提交数据面。 */
    private fun cleanupObsoleteAfterRefresh(previous: FirewallRules, next: FirewallRules): Boolean {
        val commands = previous.buildPostRefreshCleanupCommands(next)
        if (commands.isEmpty()) return true
        if (!refreshGuardian("guardian.heartbeat.pre-obsolete-cleanup")) return false
        try {
            shell.exec(*commands.toTypedArray(), timeoutSec = 8)
        } catch (_: Throwable) {
            // best-effort：旧资源已无引用，后续 stop/guardian 仍会再次清理。
        }
        return refreshGuardian("guardian.heartbeat.post-obsolete-cleanup")
    }

    private fun prepareIpSet(rules: FirewallRules): Boolean {
        val commands = rules.buildIpSetInstallCommands()
        if (commands.isEmpty()) return true
        return try {
            shell.execStrict(*commands.toTypedArray(), timeoutSec = 20).ok
        } catch (_: Throwable) {
            false
        }
    }

    /** ipset 元素的 20 秒 fail-open 租约；应用/服务死亡后不再刷新，目标集合自动变空。 */
    @Synchronized
    fun refreshFailOpenLease(): Boolean {
        if (backendState != BackendState.ACTIVE) return false
        val rules = activeRules ?: return false
        val commands = rules.buildIpSetLeaseRefreshCommands()
        val leaseOk = if (commands.isEmpty()) true else try {
            shell.execStrict(*commands.toTypedArray(), timeoutSec = 8).ok
        } catch (_: Throwable) {
            false
        }
        val guardianOk = guardian?.heartbeat() == true
        return leaseOk && guardianOk
    }

    private fun verifyRules(rules: FirewallRules): Boolean {
        if (!refreshGuardian("guardian.heartbeat.pre-verify")) return false
        val r = shell.exec(
            *rules.verificationCommands().toTypedArray(),
            timeoutSec = GUARDIAN_SAFE_COMMAND_TIMEOUT_SECONDS,
        )
        if (!r.ok) return fail("firewall.verify.command", r.diagnosticSummary())
        val markers = rules.expectedMarkers()
        val canonicalOutput = canonicalizeFirewallText(r.out)
        val missing = markers.filterNot { canonicalOutput.contains(canonicalizeFirewallText(it)) }
        if (missing.isNotEmpty()) {
            return fail(
                "firewall.verify.markers",
                "missing=${missing.joinToString(",").take(MAX_FAILURE_DETAIL)}",
            )
        }
        return true
    }

    /**
     * guardian 的失效阈值是 13 秒；规则事务中的单次 root 命令限制在 10 秒，并在每个边界续租。
     * 这样应用进程死亡仍能在 15 秒内 fail-open，同时正常的大规则集安装不会误触发清理。
     */
    private fun refreshGuardian(stage: String): Boolean {
        val activeGuardian = guardian ?: return fail(stage, "guardian missing")
        if (activeGuardian.heartbeat()) return true
        return fail(stage, activeGuardian.lastFailureDetail.ifBlank { "heartbeat returned false" })
    }

    /**
     * 清理残留（start 前置，§21 幂等）：静态清理当前 scope 的 chain + 动态清扫
     * `iptables -S` 输出中所有 `-N GHD_*` chain（覆盖上次运行 scope 与本次不同的孤儿子链）。
     * 全程只动 GHD_* 自有 chain 及其 OUTPUT jump，绝不碰他人规则。
     */
    private fun cleanupStale(selfUid: Int) {
        val rules = rulesBuilder(selfUid)
        val dynamicV4 = try {
            val r = shell.exec("iptables -t nat -S", "iptables -t filter -S", timeoutSec = 8)
            if (r.ok) collectOwnedChains(r.out).filterNotTo(mutableSetOf()) { it.startsWith(IPV6_CHAIN_PREFIX) }
            else emptySet()
        } catch (t: Throwable) {
            emptySet()
        }
        val dynamicV6 = try {
            val r = shell.exec("ip6tables -t nat -S", "ip6tables -t filter -S", timeoutSec = 8)
            if (r.ok) collectOwnedChains(r.out).filterTo(mutableSetOf()) { it.startsWith(IPV6_CHAIN_PREFIX) }
            else emptySet()
        } catch (t: Throwable) {
            emptySet()
        }
        val (natStatic, filterStatic) = rules.ownedChainNames()
        val nat = (natStatic + dynamicV4).distinct()
        val filter = (filterStatic + dynamicV4).distinct()

        val cmds = mutableListOf<String>()
        appendCleanupCommands(cmds, "iptables", nat, filter)
        if (rules.usesIpv6RealIpRedirect() || dynamicV6.isNotEmpty()) {
            val (natStaticV6, filterStaticV6) = rules.ownedIpv6ChainNames()
            val natV6 = (natStaticV6 + dynamicV6).distinct()
            val filterV6 = (filterStaticV6 + dynamicV6).distinct()
            appendCleanupCommands(cmds, "ip6tables", natV6, filterV6)
        }
        // 4) chain 已无引用后清理可能由上次 generation 留下的集合。
        cmds += rules.buildIpSetCleanupCommands()

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
                if (!line.startsWith("-N GHD_")) return@mapNotNull null
                line.removePrefix("-N ").trim().takeIf(OWNED_CHAIN_NAME::matches)
            }
            .toSet()

    private fun appendCleanupCommands(
        commands: MutableList<String>,
        binary: String,
        nat: List<String>,
        filter: List<String>,
    ) {
        // 1) 删 OUTPUT jump（未知孤儿链也尝试；不存在报错可忽略）。
        nat.forEach { commands += "$binary -t nat -D OUTPUT -j $it" }
        filter.forEach { commands += "$binary -t filter -D OUTPUT -j $it" }
        // 2) flush 父链先解除对子链的引用；3) 再删除自有链。
        nat.forEach { commands += "$binary -t nat -F $it" }
        filter.forEach { commands += "$binary -t filter -F $it" }
        nat.forEach { commands += "$binary -t nat -X $it" }
        filter.forEach { commands += "$binary -t filter -X $it" }
    }

    /** 失败路径：置 FAILED（finally 中执行 rollback）。 */
    private fun fail(stage: String, detail: String): Boolean {
        lastFailureInternal = RootBackendFailure(
            stage = stage.take(MAX_FAILURE_STAGE),
            detail = detail.replace(Regex("\\s+"), " ").trim().take(MAX_FAILURE_DETAIL),
        )
        backendState = BackendState.FAILED
        return false
    }

    private fun throwableDetail(t: Throwable): String =
        "${t.javaClass.simpleName}: ${t.message.orEmpty()}".trim()

    /**
     * 消除 `iptables -S` 的等价序列化差异：legacy 实现可能把 `-p tcp/udp` 提到
     * owner/destination 之前，并补出冗余 `-m tcp/udp`。协议被提取成行尾语义标签，
     * 因此仍严格校验 TCP/UDP，同时保留 UID、地址、端口、否定符和 target 的原有顺序。
     */
    private fun canonicalizeFirewallText(text: String): String =
        text.lineSequence().joinToString("\n", transform = ::canonicalizeFirewallLine)

    private fun canonicalizeFirewallLine(raw: String): String {
        var line = raw.trim().replace(Regex("\\s+"), " ")
        val protocol = Regex("(?:^| )-p (tcp|udp)(?= |$)")
            .find(line)
            ?.groupValues
            ?.get(1)
        line = line
            .replace(Regex(" +-m (?:tcp|udp)(?= |$)"), "")
            .replace(Regex(" +-p (?:tcp|udp)(?= |$)"), "")
            .replace(Regex("\\s+"), " ")
            .trim()
        return if (protocol == null) line else "$line [protocol=$protocol]"
    }

    /** rollback：cleanup 命令 + 停已启动的监听（§21）。 */
    private fun rollback(rules: FirewallRules?, dnsStarted: Boolean, tcpStarted: Boolean) {
        // 与 stop() 相同：保留独立 guardian 直到心跳自然过期，覆盖回滚进程死亡窗口。
        guardian = null
        activeRules = null
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

    companion object {
        private const val IPV6_CHAIN_PREFIX = "GHD_6_"
        private const val MAX_FAILURE_STAGE = 64
        private const val MAX_FAILURE_DETAIL = 512
        private const val GUARDIAN_SAFE_COMMAND_TIMEOUT_SECONDS = 10
        private val OWNED_CHAIN_NAME = Regex("^GHD_[A-Za-z0-9_]{1,28}$")
    }
}

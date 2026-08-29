package org.xiyu.githubdirect.root

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import org.xiyu.githubdirect.MainActivity
import org.xiyu.githubdirect.R
import org.xiyu.githubdirect.core.rules.BackendMode
import org.xiyu.githubdirect.data.AndroidSettingsStore
import org.xiyu.githubdirect.data.BackendManager
import org.xiyu.githubdirect.data.DirectEngine
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

internal data class RootDataPlaneTransactionResult(
    val operationOk: Boolean,
    val backendActive: Boolean,
    val snapshotActivated: Boolean,
)

/**
 * TLS 路由、Root 规则和远程 Hook 快照必须在同一个 provider 屏障内完成。否则后台刷新可在
 * 三者之间发布新 generation，启动线程只能再跑一整轮昂贵的 TLS 验证与规则追赶。
 */
internal fun runRootDataPlaneTransaction(
    withBarrier: (() -> RootDataPlaneTransactionResult) -> RootDataPlaneTransactionResult,
    syncTlsTermination: () -> Unit,
    operation: () -> Boolean,
    isBackendActive: () -> Boolean,
    activateSnapshot: () -> Boolean,
): RootDataPlaneTransactionResult = withBarrier {
    syncTlsTermination()
    val operationOk = operation()
    val backendActive = operationOk && isBackendActive()
    RootDataPlaneTransactionResult(
        operationOk = operationOk,
        backendActive = backendActive,
        snapshotActivated = !backendActive || activateSnapshot(),
    )
}

/**
 * Root 数据面的唯一 Android 生命周期所有者。
 *
 * Activity 只发送命令；监听器、iptables、provider、watchdog 均由该前台服务持有。
 * 所有命令在单线程执行器中串行，避免 START/STOP/REFRESH 交错安装不同代次的规则。
 */
class RootRelayService : Service() {

    enum class Phase { STOPPED, STARTING, ACTIVE, FAILED }

    data class Status(
        val generation: Long,
        val phase: Phase,
        val mode: BackendMode?,
        val message: String,
        val updatedAt: Long,
        val ruleGeneration: Long = 0L,
        val scopeUids: List<Int> = emptyList(),
        val embeddedCaptureUids: List<Int> = emptyList(),
        val candidateCount: Int = 0,
        val lastError: String = "",
        val failureStage: String = "",
        val realIpRedirect: Boolean = false,
        val ipv6RealIpRedirect: Boolean = false,
        val failOpenMode: String = "disabled",
        val degradationReason: String = "",
        val unclassifiedTlsCount: Long = 0L,
        val tlsTerminationEnabled: Boolean = false,
        val tlsTerminationActive: Boolean = false,
        val tlsTerminationRoutes: Int = 0,
        val nat64FallbackActive: Boolean = false,
        val nat64FallbackRoutes: Int = 0,
        val nat64Operator: String = "",
        val nat64ExpectedAsn: String = "",
        val nat64ExpectedRegion: String = "",
        val nat64Verified: Boolean = false,
        val nat64ObservedIp: String = "",
        val nat64ObservedAsn: String = "",
        val nat64ObservedOperator: String = "",
        val nat64ObservedRegion: String = "",
        val nat64ObservedAt: Long = 0L,
        val nat64ProbeDetail: String = "",
        val caState: String = SystemCaState.NOT_GENERATED.name,
    )

    private val worker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "GHD-RootService").apply { isDaemon = true }
    }
    private val maintenance = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "GHD-RootLease").apply { isDaemon = true }
    }
    private val leaseFailures = AtomicInteger()
    private val leaseRepairQueued = AtomicBoolean()
    private lateinit var settings: AndroidSettingsStore
    private lateinit var sniGateRuntime: SniGateRuntime
    private lateinit var caInstaller: AndroidSystemCaInstaller
    private lateinit var oemFreezeLease: OemFreezeLease
    @Volatile private var tlsRuntimeStatus = SniGateRuntimeStatus(false)
    @Volatile private var systemCaStatus = SystemCaStatus(SystemCaState.NOT_GENERATED)

    override fun onCreate() {
        super.onCreate()
        settings = AndroidSettingsStore(this)
        sniGateRuntime = SniGateRuntime(this)
        caInstaller = AndroidSystemCaInstaller(this)
        oemFreezeLease = OemFreezeLease()
        ensureNotificationChannel()
        maintenance.scheduleWithFixedDelay({
            leaseHeartbeatTick()
            try {
                worker.execute(::maintenanceTick)
            } catch (_: Throwable) {
            }
        }, LEASE_REFRESH_SECONDS, LEASE_REFRESH_SECONDS, TimeUnit.SECONDS)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val command = RootServiceCommandPolicy.classify(intent?.action)
        if (command == RootServiceCommand.STOP) {
            enqueueCommand(startId, command) { stopBackend(userRequested = true) }
            return START_NOT_STICKY
        }

        // startForegroundService 的所有入口必须立即发布通知，再做 su/iptables 等慢操作。
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.root_service_starting)))
        // 被 ColorOS HANS 通过 Binder/网络事件短暂唤醒时，在进入慢任务前续上 Root Binder 租约。
        oemFreezeLease.acquire(this)
        when (command) {
            RootServiceCommand.REFRESH -> enqueueCommand(startId, command, ::refreshCommand)
            RootServiceCommand.REPROBE -> enqueueCommand(startId, command, ::reprobeCommand)
            RootServiceCommand.START -> {
                val mode = parseMode(intent?.getStringExtra(EXTRA_MODE))
                enqueueCommand(startId, command) { startBackend(mode) }
            }
            RootServiceCommand.RESTORE -> enqueueCommand(startId, command) {
                if (!settings.isRootServiceEnabled()) {
                    stopBackend(userRequested = false)
                } else {
                    startBackend(settings.backendMode())
                }
            }
            RootServiceCommand.STOP -> Unit // 已在 startForeground 前处理
        }
        return if (settings.isRootServiceEnabled()) START_STICKY else START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        maintenance.shutdownNow()
        try {
            // Android 在主线程调用 Service.onDestroy；su/iptables 最坏可等待数十秒，不能在此
            // 同步执行。正常 STOP 已在 worker 串行清理；异常销毁则由该任务与独立 guardian
            // 共同兜底，任务来不及运行时 guardian 仍会在心跳过期后 fail-open。
            worker.execute {
                try {
                    BackendManager.get(this).stop(cleanupStaleRoot = false)
                    sniGateRuntime.stop()
                } catch (t: Throwable) {
                    Log.w(TAG, "服务销毁时异步清理 Root 后端失败", t)
                } finally {
                    oemFreezeLease.release(this)
                }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "服务销毁时无法调度 Root 后端清理", t)
        }
        worker.shutdown()
        super.onDestroy()
    }

    private fun prepareManager(): BackendManager? {
        if (!DirectEngine.ensureInit(this, true)) {
            publish(Phase.FAILED, null, "引擎初始化失败", "engine.init")
            updateNotification(getString(R.string.root_service_failed))
            return null
        }
        return BackendManager.get(this)
    }

    /** 所有 Service 命令的统一异常边界；线程池任务异常不得让前台服务静默常驻。 */
    private fun enqueueCommand(
        startId: Int,
        command: RootServiceCommand,
        action: () -> Unit,
    ) {
        try {
            worker.execute {
                try {
                    action()
                } catch (t: Throwable) {
                    Log.w(TAG, "Root 服务命令 $command 异常", t)
                    val mode = runCatching { BackendManager.get(this).currentMode() }.getOrNull()
                    val detail = t.message?.take(160).orEmpty().ifBlank { t.javaClass.simpleName }
                    publish(
                        Phase.FAILED,
                        mode,
                        "Root 服务命令 ${command.name} 异常：$detail",
                        "service.${command.name.lowercase()}",
                    )
                    updateNotification(getString(R.string.root_service_failed))
                } finally {
                    finishOneShotIfNeeded(startId, command)
                }
            }
        } catch (t: Throwable) {
            // 仅可能发生在 Service 正在销毁、executor 已拒绝任务时；此时不可再保留前台态。
            Log.w(TAG, "Root 服务命令 $command 无法调度", t)
            finishOneShotIfNeeded(startId, command)
        }
    }

    private fun finishOneShotIfNeeded(startId: Int, command: RootServiceCommand) {
        if (!RootServiceCommandPolicy.shouldStopAfterCompletion(command, settings.isRootServiceEnabled())) return
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf(startId)
    }

    private fun refreshCommand() {
        val manager = prepareManager() ?: return
        DirectEngine.reconcileProviders()
        DirectEngine.withRouteSnapshotBarrier {
            refreshCommandLocked(manager)
        }
    }

    /** 候选刷新与同代 Root 规则激活必须共用一段可重入屏障，不能给自动刷新留下竞态窗口。 */
    private fun refreshCommandLocked(manager: BackendManager) {
        val count = DirectEngine.refreshProviders()
        val wasActive = manager.isRootBackendActive()
        val transaction = rootDataPlaneTransaction(manager) {
            !wasActive || manager.refreshRootDataPlane()
        }
        if (wasActive && !transaction.operationOk) {
            publishBackendFailure(
                manager,
                manager.currentMode(),
                "候选已刷新，但 Root 规则更新失败并已回滚",
                "rules.refresh",
            )
            updateNotification(getString(R.string.root_service_failed))
            return
        }
        if (!transaction.snapshotActivated) return
        val message = if (wasActive) {
            "候选源刷新完成：$count 个 provider；规则更新成功"
        } else {
            "候选源刷新完成：$count 个 provider；Root 后端未运行，未安装规则"
        }
        publishCommandResult(manager, message)
    }

    private fun reprobeCommand() {
        val manager = prepareManager() ?: return
        DirectEngine.withRouteSnapshotBarrier {
            reprobeCommandLocked(manager)
        }
    }

    /** 强制重探、数据面切换与 Hook 快照发布保持同一候选 generation。 */
    private fun reprobeCommandLocked(manager: BackendManager) {
        val commandStarted = SystemClock.elapsedRealtime()
        val caps = manager.rootCapabilities(force = true)
        val candidateStarted = SystemClock.elapsedRealtime()
        val count = DirectEngine.reprobeProviders()
        val candidateElapsed = SystemClock.elapsedRealtime() - candidateStarted
        val wasActive = manager.isRootBackendActive()
        val dataPlaneStarted = SystemClock.elapsedRealtime()
        val transaction = rootDataPlaneTransaction(manager, forceTlsVerification = true) {
            !wasActive || manager.refreshRootDataPlane()
        }
        val dataPlaneElapsed = SystemClock.elapsedRealtime() - dataPlaneStarted
        if (wasActive) {
            if (!transaction.operationOk) {
                publishBackendFailure(
                    manager,
                    manager.currentMode(),
                    "重探完成，但 Root 规则更新失败并已回滚",
                    "rules.reprobe",
                )
                updateNotification(getString(R.string.root_service_failed))
                return
            }
            if (!transaction.snapshotActivated) return
        } else if (caps?.requiredOk() != true) {
            publish(Phase.FAILED, manager.currentMode(), "Root 能力探测失败；候选完成 $count 个 provider", "capabilities.probe")
            updateNotification(getString(R.string.root_service_failed))
            return
        }
        val totalElapsed = SystemClock.elapsedRealtime() - commandStarted
        Log.i(
            TAG,
            "REPROBE complete: candidates=${candidateElapsed}ms, " +
                "dataPlane=${dataPlaneElapsed}ms, total=${totalElapsed}ms",
        )
        publishCommandResult(
            manager,
            "Root 能力与候选重探完成：$count 个 provider" +
                "（候选 ${candidateElapsed / 1000.0}s，数据面 ${dataPlaneElapsed / 1000.0}s）",
        )
    }

    /** 未启用常驻服务的一次性命令成功时应记录 STOPPED，而不是伪造 backend.inactive 故障。 */
    private fun publishCommandResult(manager: BackendManager, message: String) {
        if (manager.isRootBackendActive()) {
            publishCurrent(message)
        } else if (settings.isRootServiceEnabled()) {
            publish(Phase.FAILED, manager.currentMode(), message, "backend.inactive")
            updateNotification(message)
        } else {
            publish(Phase.STOPPED, manager.currentMode(), message)
            updateNotification(message)
        }
    }

    private fun startBackend(requestedMode: BackendMode) {
        val mode = when (requestedMode) {
            BackendMode.VPN -> BackendMode.XPOSED_ONLY
            else -> requestedMode
        }
        settings.setRootServiceEnabled(true)
        settings.setBackendMode(mode)
        publish(Phase.STARTING, mode, "正在安装 Root 数据面")
        updateNotification(getString(R.string.root_service_starting))

        val manager = prepareManager() ?: return
        val transaction = try {
            rootDataPlaneTransaction(manager) { manager.start(mode) }
        } catch (t: Throwable) {
            Log.w(TAG, "Root 后端启动异常", t)
            RootDataPlaneTransactionResult(false, false, false)
        }
        if (transaction.operationOk && transaction.backendActive) {
            if (!transaction.snapshotActivated) return
            publish(Phase.ACTIVE, mode, "Root 数据面已启用")
            updateNotification(getString(R.string.root_service_active))
        } else if (transaction.operationOk && mode == BackendMode.XPOSED_ONLY) {
            sniGateRuntime.stop()
            tlsRuntimeStatus = SniGateRuntimeStatus(false)
            // Xposed DNS 可以独立工作，但该前台服务没有 Root 数据面可持有，避免伪报 ACTIVE。
            publish(Phase.FAILED, mode, "Xposed 已启用，但 Root TLS 中继未启动", "backend.start")
            updateNotification(getString(R.string.root_service_degraded))
        } else {
            sniGateRuntime.stop()
            tlsRuntimeStatus = SniGateRuntimeStatus(false)
            publishBackendFailure(manager, mode, "Root 数据面启动失败", "backend.start")
            updateNotification(getString(R.string.root_service_failed))
        }
    }

    private fun stopBackend(userRequested: Boolean) {
        // 先持久化用户意图：若进程在后续 Root 清理期间死亡，独立 guardian
        // 仍会删除规则，但不得再将服务拉起。
        if (userRequested) settings.setRootServiceEnabled(false)
        try {
            BackendManager.get(this).stop(cleanupStaleRoot = true)
        } catch (t: Throwable) {
            Log.w(TAG, "停止 Root 后端失败", t)
        } finally {
            sniGateRuntime.stop()
            tlsRuntimeStatus = SniGateRuntimeStatus(false)
            oemFreezeLease.release(this)
        }
        publish(Phase.STOPPED, null, "Root 数据面已停止")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun publishCurrent(message: String) {
        val manager = try {
            BackendManager.get(this)
        } catch (_: Throwable) {
            null
        }
        val active = manager?.isRootBackendActive() == true
        publish(
            if (active) Phase.ACTIVE else Phase.FAILED,
            manager?.currentMode(),
            message,
            if (active) "" else "backend.inactive",
        )
        updateNotification(message)
    }

    /**
     * guardian/ipset 的最小租约续期必须直接运行在独立调度线程；候选网络刷新可能占用命令
     * worker 超过 13 秒，若把续期排在同一队列中，guardian 会按设计清除仍健康的旧规则。
     */
    private fun leaseHeartbeatTick() {
        val manager = try {
            BackendManager.get(this)
        } catch (_: Throwable) {
            return
        }
        if (!manager.isRootBackendActive()) {
            leaseFailures.set(0)
            return
        }
        if (manager.refreshFailOpenLease()) {
            leaseFailures.set(0)
            return
        }
        if (leaseFailures.incrementAndGet() < 2 || !leaseRepairQueued.compareAndSet(false, true)) return
        leaseFailures.set(0)
        try {
            worker.execute {
                try {
                    repairFailedLease()
                } finally {
                    leaseRepairQueued.set(false)
                }
            }
        } catch (_: Throwable) {
            leaseRepairQueued.set(false)
        }
    }

    private fun repairFailedLease() {
        val manager = try {
            BackendManager.get(this)
        } catch (_: Throwable) {
            return
        }
        if (!settings.isRootServiceEnabled() || !manager.isRootBackendActive()) return
        // 队列等待期间可能已经自行恢复，先复验，避免无意义切换 guardian 代次。
        if (manager.refreshFailOpenLease()) return
        val repaired = manager.refreshRootDataPlane()
        if (repaired) {
            if (!activateInstalledSnapshot(manager)) return
            publishCurrent("fail-open 心跳已恢复；规则 generation ${manager.activeRuleGeneration()}")
        } else {
            publishBackendFailure(manager, null, "fail-open 心跳刷新失败，规则已回滚", "lease.refresh")
            updateNotification(getString(R.string.root_service_failed))
        }
    }

    private fun maintenanceTick() {
        // ColorOS 可能独立终止 Binder 租约助手；定期复验并在丢失后自动重建。
        oemFreezeLease.acquire(this)
        val manager = try {
            BackendManager.get(this)
        } catch (_: Throwable) {
            return
        }
        if (!manager.isRootBackendActive()) {
            // BackendManager 自带的 30s watchdog 可能已在另一线程完成 fail-open 回滚；
            // 前台服务必须同步持久化状态，不能继续向 UI 伪报 ACTIVE。
            if (settings.isRootServiceEnabled()) {
                val current = readStatus(this)
                val failure = manager.rootBackendFailure()
                val stage = failure?.stage ?: "backend.inactive"
                if (current.phase != Phase.FAILED || current.failureStage != stage) {
                    publishBackendFailure(
                        manager,
                        manager.currentMode() ?: settings.backendMode(),
                        "Root 数据面已停止并保持 fail-open；需要重新启动或重探",
                        "backend.inactive",
                    )
                    updateNotification(getString(R.string.root_service_failed))
                }
            }
            return
        }

        val desiredGeneration = DirectEngine.routeSnapshot().generation
        val installedGeneration = manager.activeRuleGeneration()
        if (desiredGeneration != installedGeneration) {
            val transaction = rootDataPlaneTransaction(
                manager,
                operation = manager::refreshRootDataPlane,
            )
            if (!transaction.operationOk) {
                publish(
                    Phase.FAILED,
                    null,
                    "候选 generation $desiredGeneration 与已安装 generation $installedGeneration 不一致；重装失败并已 fail-open",
                    "rules.refresh",
                )
                updateNotification(getString(R.string.root_service_failed))
            } else if (transaction.snapshotActivated) {
                publishCurrent("规则已切换至 generation ${manager.activeRuleGeneration()}")
            }
            return
        }

        // BackendManager watchdog 可直接重装规则；若 generation 已相等但远程 Hook 尚未发布，
        // 在这里补齐激活事务。相等时不重复写 SharedPreferences。
        val publishedGeneration = runCatching {
            DirectEngine.settings()?.routeSnapshot()?.second ?: 0L
        }.getOrDefault(0L)
        if (publishedGeneration != installedGeneration && activateInstalledSnapshot(manager)) {
            publishCurrent("规则与 Hook 快照已同步至 generation $installedGeneration")
        }
    }

    /**
     * 规则代次与内存快照必须一致后才能发布给远程 Hook。若 provider 在前一段耗时的
     * sni-gate/iptables 事务中发布了更新快照，在发布屏障内按最新代次补装一次；不能把
     * 旧规则错误激活，也不能因正常刷新竞争永久进入 FAILED。
     */
    private fun activateInstalledSnapshot(manager: BackendManager): Boolean =
        DirectEngine.withRouteSnapshotBarrier {
            var generation = manager.activeRuleGeneration()
            val desiredGeneration = DirectEngine.routeSnapshot().generation
            if (generation != desiredGeneration) {
                syncTlsTermination()
                if (!manager.refreshRootDataPlane()) {
                    publishBackendFailure(
                        manager,
                        manager.currentMode(),
                        "候选已更新至 generation $desiredGeneration，但同代规则补装失败并已 fail-open",
                        "rules.catchup",
                    )
                    updateNotification(getString(R.string.root_service_failed))
                    return@withRouteSnapshotBarrier false
                }
                generation = manager.activeRuleGeneration()
            }
            if (DirectEngine.activateRouteSnapshot(generation)) {
                return@withRouteSnapshotBarrier true
            }
            publish(
                Phase.FAILED,
                manager.currentMode(),
                "规则 generation $generation 与候选快照不一致；等待维护重试",
                "snapshot.activate",
            )
            updateNotification(getString(R.string.root_service_failed))
            false
        }

    private fun rootDataPlaneTransaction(
        manager: BackendManager,
        forceTlsVerification: Boolean = false,
        operation: () -> Boolean,
    ): RootDataPlaneTransactionResult = runRootDataPlaneTransaction(
        withBarrier = { action -> DirectEngine.withRouteSnapshotBarrier(action) },
        syncTlsTermination = { syncTlsTermination(forceTlsVerification) },
        operation = operation,
        isBackendActive = manager::isRootBackendActive,
        activateSnapshot = { activateInstalledSnapshot(manager) },
    )

    private fun publish(
        phase: Phase,
        mode: BackendMode?,
        message: String,
        failureStage: String = "",
    ) {
        val prefs = getSharedPreferences(STATUS_PREFS, MODE_PRIVATE)
        val generation = prefs.getLong(KEY_GENERATION, 0L) + 1L
        val manager = runCatching { BackendManager.get(this) }.getOrNull()
        val route = DirectEngine.routeSnapshot()
        val now = System.currentTimeMillis()
        val candidateCount = route.plans.values.sumOf { plan ->
            plan.candidates.count { it.usable(now) }
        }
        val scope = manager?.rootScopeUids().orEmpty().sorted()
        val embeddedCapture = manager?.embeddedCaptureUids().orEmpty().sorted()
        val realIp = manager?.realIpRedirectActive() == true
        val realIpV6 = manager?.ipv6RealIpRedirectActive() == true
        val guardian = manager?.failOpenGuardianActive() == true
        val unclassified = manager?.unclassifiedTlsTotal() ?: 0L
        val routeDegradation = DirectEngine.routeDegradationReason()
        val degradation = buildList {
            if (routeDegradation.isNotBlank()) add(routeDegradation)
            if (unclassified > 0L) {
                add("检测到 $unclassified 个无法按可见 SNI/精确原 IP 归类的连接（可能为 ECH），已原样透传")
            }
            if (settings.isTlsTerminationEnabled() && !tlsRuntimeStatus.active) {
                add(tlsRuntimeStatus.detail.ifBlank {
                    systemCaStatus.detail.ifBlank { "可选 TLS 终止未激活" }
                })
            }
            if (settings.nat64FallbackConfig().activationOrNull() != null) {
                when {
                    !tlsRuntimeStatus.nat64Verified -> add(
                        "NON_STRICT_NAT64 出口校验未通过：" +
                            tlsRuntimeStatus.nat64ProbeDetail.ifBlank { "无实测结果" },
                    )
                    tlsRuntimeStatus.nat64RouteCount == 0 -> add(
                        "NON_STRICT_NAT64 出口已验证，但没有 OpenAI/ChatGPT 路由通过 ECH/证书预检",
                    )
                }
            }
            val freezeLease = oemFreezeLease.status()
            if (freezeLease.required && !freezeLease.active) {
                add(freezeLease.detail.ifBlank { "Oplus HANS 后台运行豁免未生效" })
            }
        }.joinToString("；")
        val failOpenMode = when {
            manager?.ipSetLeaseActive() == true && guardian -> "ipset-20s+guardian-15s"
            guardian -> "root-guardian-15s"
            else -> "disabled"
        }
        prefs.edit()
            .putLong(KEY_GENERATION, generation)
            .putString(KEY_PHASE, phase.name)
            .putString(KEY_MODE, mode?.name)
            .putString(KEY_MESSAGE, message)
            .putLong(KEY_UPDATED_AT, now)
            .putLong(KEY_RULE_GENERATION, manager?.activeRuleGeneration() ?: 0L)
            .putString(KEY_SCOPE_UIDS, scope.joinToString(","))
            .putString(KEY_EMBEDDED_CAPTURE_UIDS, embeddedCapture.joinToString(","))
            .putInt(KEY_CANDIDATE_COUNT, candidateCount)
            .putString(KEY_LAST_ERROR, if (phase == Phase.FAILED) message else "")
            .putString(KEY_FAILURE_STAGE, if (phase == Phase.FAILED) failureStage else "")
            .putBoolean(KEY_REAL_IP_REDIRECT, realIp)
            .putBoolean(KEY_REAL_IP_REDIRECT_V6, realIpV6)
            .putString(KEY_FAIL_OPEN_MODE, failOpenMode)
            .putString(KEY_DEGRADATION_REASON, degradation)
            .putLong(KEY_UNCLASSIFIED_TLS_COUNT, unclassified)
            .putBoolean(KEY_TLS_TERMINATION_ENABLED, settings.isTlsTerminationEnabled())
            .putBoolean(KEY_TLS_TERMINATION_ACTIVE, tlsRuntimeStatus.active)
            .putInt(KEY_TLS_TERMINATION_ROUTES, tlsRuntimeStatus.routeCount)
            .putBoolean(KEY_NAT64_FALLBACK_ACTIVE, tlsRuntimeStatus.nat64RouteCount > 0)
            .putInt(KEY_NAT64_FALLBACK_ROUTES, tlsRuntimeStatus.nat64RouteCount)
            .putString(KEY_NAT64_OPERATOR, tlsRuntimeStatus.nat64Operator)
            .putString(KEY_NAT64_EXPECTED_ASN, tlsRuntimeStatus.nat64ExpectedAsn)
            .putString(KEY_NAT64_EXPECTED_REGION, tlsRuntimeStatus.nat64ExpectedRegion)
            .putBoolean(KEY_NAT64_VERIFIED, tlsRuntimeStatus.nat64Verified)
            .putString(KEY_NAT64_OBSERVED_IP, tlsRuntimeStatus.nat64ObservedIp)
            .putString(KEY_NAT64_OBSERVED_ASN, tlsRuntimeStatus.nat64ObservedAsn)
            .putString(KEY_NAT64_OBSERVED_OPERATOR, tlsRuntimeStatus.nat64ObservedOperator)
            .putString(KEY_NAT64_OBSERVED_REGION, tlsRuntimeStatus.nat64ObservedRegion)
            .putLong(KEY_NAT64_OBSERVED_AT, tlsRuntimeStatus.nat64ObservedAt)
            .putString(KEY_NAT64_PROBE_DETAIL, tlsRuntimeStatus.nat64ProbeDetail)
            .putString(KEY_CA_STATE, systemCaStatus.state.name)
            .apply()
    }

    /** CA 未受信任或运行时失败时只清空可选路由，既有候选/分片链保持工作。 */
    private fun syncTlsTermination(forceVerification: Boolean = false) {
        if (!settings.isTlsTerminationEnabled()) {
            sniGateRuntime.stop()
            tlsRuntimeStatus = SniGateRuntimeStatus(false)
            val ca = runCatching {
                DeviceCertificateAuthority.load(sniGateRuntime.certificateFile())
            }.getOrNull()
            systemCaStatus = if (ca == null) {
                SystemCaStatus(SystemCaState.NOT_GENERATED)
            } else {
                caInstaller.status(ca)
            }
            return
        }
        val ca = runCatching {
            DeviceCertificateAuthority.load(sniGateRuntime.certificateFile())
        }.getOrNull()
        if (ca == null) {
            sniGateRuntime.stop()
            systemCaStatus = SystemCaStatus(
                SystemCaState.NOT_GENERATED,
                detail = "每设备 CA 尚未生成/安装",
            )
            tlsRuntimeStatus = SniGateRuntimeStatus(false, detail = systemCaStatus.detail)
            return
        }
        systemCaStatus = caInstaller.status(ca)
        if (systemCaStatus.state != SystemCaState.TRUSTED) {
            sniGateRuntime.stop()
            tlsRuntimeStatus = SniGateRuntimeStatus(
                false,
                detail = systemCaStatus.detail.ifBlank {
                    "系统 CA 状态：${systemCaStatus.state.name}"
                },
            )
            return
        }
        tlsRuntimeStatus = sniGateRuntime.ensureRunning(
            DirectEngine.routeSnapshot(),
            forceVerification = forceVerification,
        )
    }

    /** 优先保留 RootBackend 的精确阶段，避免维护循环把真实错误覆盖成 backend.inactive。 */
    private fun publishBackendFailure(
        manager: BackendManager,
        mode: BackendMode?,
        fallbackMessage: String,
        fallbackStage: String,
    ) {
        val failure = manager.rootBackendFailure()
        val message = if (failure == null) {
            fallbackMessage
        } else {
            "$fallbackMessage（${failure.stage}：${failure.detail.ifBlank { "无附加输出" }}）"
        }
        publish(Phase.FAILED, mode, message, failure?.stage ?: fallbackStage)
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.root_service_channel),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.root_service_channel_description)
                setShowBadge(false)
            }
        )
    }

    private fun buildNotification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, RootRelayService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_app)
            .setContentTitle(getString(R.string.root_service_title))
            .setContentText(text)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.root_service_stop), stopIntent).build())
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    companion object {
        const val ACTION_START = RootServiceCommandPolicy.ACTION_START
        const val ACTION_STOP = RootServiceCommandPolicy.ACTION_STOP
        const val ACTION_REFRESH = RootServiceCommandPolicy.ACTION_REFRESH
        const val ACTION_REPROBE = RootServiceCommandPolicy.ACTION_REPROBE
        const val ACTION_RESTORE = RootServiceCommandPolicy.ACTION_RESTORE
        const val EXTRA_MODE = "backend_mode"

        private const val TAG = "RootRelayService"
        private const val CHANNEL_ID = "github_direct_root"
        private const val NOTIFICATION_ID = 4101
        private const val STATUS_PREFS = "root_relay_status"
        private const val KEY_GENERATION = "generation"
        private const val KEY_PHASE = "phase"
        private const val KEY_MODE = "mode"
        private const val KEY_MESSAGE = "message"
        private const val KEY_UPDATED_AT = "updated_at"
        private const val KEY_RULE_GENERATION = "rule_generation"
        private const val KEY_SCOPE_UIDS = "scope_uids"
        private const val KEY_EMBEDDED_CAPTURE_UIDS = "embedded_capture_uids"
        private const val KEY_CANDIDATE_COUNT = "candidate_count"
        private const val KEY_LAST_ERROR = "last_error"
        private const val KEY_FAILURE_STAGE = "failure_stage"
        private const val KEY_REAL_IP_REDIRECT = "real_ip_redirect"
        private const val KEY_REAL_IP_REDIRECT_V6 = "real_ip_redirect_v6"
        private const val KEY_FAIL_OPEN_MODE = "fail_open_mode"
        private const val KEY_DEGRADATION_REASON = "degradation_reason"
        private const val KEY_UNCLASSIFIED_TLS_COUNT = "unclassified_tls_count"
        private const val KEY_TLS_TERMINATION_ENABLED = "tls_termination_enabled"
        private const val KEY_TLS_TERMINATION_ACTIVE = "tls_termination_active"
        private const val KEY_TLS_TERMINATION_ROUTES = "tls_termination_routes"
        private const val KEY_NAT64_FALLBACK_ACTIVE = "nat64_fallback_active"
        private const val KEY_NAT64_FALLBACK_ROUTES = "nat64_fallback_routes"
        private const val KEY_NAT64_OPERATOR = "nat64_operator"
        private const val KEY_NAT64_EXPECTED_ASN = "nat64_expected_asn"
        private const val KEY_NAT64_EXPECTED_REGION = "nat64_expected_region"
        private const val KEY_NAT64_VERIFIED = "nat64_verified"
        private const val KEY_NAT64_OBSERVED_IP = "nat64_observed_ip"
        private const val KEY_NAT64_OBSERVED_ASN = "nat64_observed_asn"
        private const val KEY_NAT64_OBSERVED_OPERATOR = "nat64_observed_operator"
        private const val KEY_NAT64_OBSERVED_REGION = "nat64_observed_region"
        private const val KEY_NAT64_OBSERVED_AT = "nat64_observed_at"
        private const val KEY_NAT64_PROBE_DETAIL = "nat64_probe_detail"
        private const val KEY_CA_STATE = "ca_state"
        private const val LEASE_REFRESH_SECONDS = 5L
        // TLS 路由验证自身有 35 秒全局硬截止；还要给 CA/规则事务与状态提交留出余量。
        private const val START_AWAIT_TIMEOUT_MS = 60_000L

        private val requestGeneration = AtomicLong()

        fun requestStart(context: Context, mode: BackendMode): Long {
            val app = context.applicationContext
            AndroidSettingsStore(app).apply {
                setRootServiceEnabled(true)
                setBackendMode(mode)
            }
            val before = readStatus(app).generation
            requestGeneration.incrementAndGet()
            app.startForegroundService(
                Intent(app, RootRelayService::class.java)
                    .setAction(ACTION_START)
                    .putExtra(EXTRA_MODE, mode.name)
            )
            return before
        }

        fun requestStop(context: Context) {
            val app = context.applicationContext
            AndroidSettingsStore(app).setRootServiceEnabled(false)
            app.startService(Intent(app, RootRelayService::class.java).setAction(ACTION_STOP))
        }

        fun requestRefresh(context: Context) {
            val app = context.applicationContext
            app.startForegroundService(Intent(app, RootRelayService::class.java).setAction(ACTION_REFRESH))
        }

        fun requestReprobe(context: Context) {
            val app = context.applicationContext
            app.startForegroundService(Intent(app, RootRelayService::class.java).setAction(ACTION_REPROBE))
        }

        fun readStatus(context: Context): Status {
            val prefs = context.getSharedPreferences(STATUS_PREFS, MODE_PRIVATE)
            val phase = runCatching {
                Phase.valueOf(prefs.getString(KEY_PHASE, Phase.STOPPED.name)!!)
            }.getOrDefault(Phase.STOPPED)
            val mode = parseMode(prefs.getString(KEY_MODE, null))
            return Status(
                generation = prefs.getLong(KEY_GENERATION, 0L),
                phase = phase,
                mode = mode,
                message = prefs.getString(KEY_MESSAGE, "").orEmpty(),
                updatedAt = prefs.getLong(KEY_UPDATED_AT, 0L),
                ruleGeneration = prefs.getLong(KEY_RULE_GENERATION, 0L),
                scopeUids = prefs.getString(KEY_SCOPE_UIDS, "").orEmpty()
                    .split(',').mapNotNull(String::toIntOrNull),
                embeddedCaptureUids = prefs.getString(KEY_EMBEDDED_CAPTURE_UIDS, "").orEmpty()
                    .split(',').mapNotNull(String::toIntOrNull),
                candidateCount = prefs.getInt(KEY_CANDIDATE_COUNT, 0).coerceAtLeast(0),
                lastError = prefs.getString(KEY_LAST_ERROR, "").orEmpty(),
                failureStage = prefs.getString(KEY_FAILURE_STAGE, "").orEmpty(),
                realIpRedirect = prefs.getBoolean(KEY_REAL_IP_REDIRECT, false),
                ipv6RealIpRedirect = prefs.getBoolean(KEY_REAL_IP_REDIRECT_V6, false),
                failOpenMode = prefs.getString(KEY_FAIL_OPEN_MODE, "disabled").orEmpty(),
                degradationReason = prefs.getString(KEY_DEGRADATION_REASON, "").orEmpty(),
                unclassifiedTlsCount = prefs.getLong(KEY_UNCLASSIFIED_TLS_COUNT, 0L).coerceAtLeast(0L),
                tlsTerminationEnabled = prefs.getBoolean(KEY_TLS_TERMINATION_ENABLED, false),
                tlsTerminationActive = prefs.getBoolean(KEY_TLS_TERMINATION_ACTIVE, false),
                tlsTerminationRoutes = prefs.getInt(KEY_TLS_TERMINATION_ROUTES, 0).coerceAtLeast(0),
                nat64FallbackActive = prefs.getBoolean(KEY_NAT64_FALLBACK_ACTIVE, false),
                nat64FallbackRoutes = prefs.getInt(KEY_NAT64_FALLBACK_ROUTES, 0).coerceAtLeast(0),
                nat64Operator = prefs.getString(KEY_NAT64_OPERATOR, "").orEmpty(),
                nat64ExpectedAsn = prefs.getString(KEY_NAT64_EXPECTED_ASN, "").orEmpty(),
                nat64ExpectedRegion = prefs.getString(KEY_NAT64_EXPECTED_REGION, "").orEmpty(),
                nat64Verified = prefs.getBoolean(KEY_NAT64_VERIFIED, false),
                nat64ObservedIp = prefs.getString(KEY_NAT64_OBSERVED_IP, "").orEmpty(),
                nat64ObservedAsn = prefs.getString(KEY_NAT64_OBSERVED_ASN, "").orEmpty(),
                nat64ObservedOperator = prefs.getString(
                    KEY_NAT64_OBSERVED_OPERATOR,
                    "",
                ).orEmpty(),
                nat64ObservedRegion = prefs.getString(KEY_NAT64_OBSERVED_REGION, "").orEmpty(),
                nat64ObservedAt = prefs.getLong(KEY_NAT64_OBSERVED_AT, 0L),
                nat64ProbeDetail = prefs.getString(KEY_NAT64_PROBE_DETAIL, "").orEmpty(),
                caState = prefs.getString(KEY_CA_STATE, SystemCaState.NOT_GENERATED.name)
                    .orEmpty(),
            )
        }

        /** 仅供后台线程等待本次命令进入终态。 */
        fun awaitTerminal(
            context: Context,
            afterGeneration: Long,
            timeoutMs: Long = START_AWAIT_TIMEOUT_MS,
        ): Status {
            val deadline = SystemClock.elapsedRealtime() + timeoutMs
            var last = readStatus(context)
            while (SystemClock.elapsedRealtime() < deadline) {
                last = readStatus(context)
                if (last.generation > afterGeneration
                    && (last.phase == Phase.ACTIVE || last.phase == Phase.FAILED || last.phase == Phase.STOPPED)
                ) return last
                SystemClock.sleep(100)
            }
            return last
        }

        private fun parseMode(raw: String?): BackendMode =
            BackendMode.values().firstOrNull { it.name == raw } ?: BackendMode.XPOSED_ONLY
    }
}

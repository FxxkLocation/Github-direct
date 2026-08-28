package org.xiyu.githubdirect.data

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.dns.SelectiveDnsEngine
import org.xiyu.githubdirect.core.net.VirtualIpPool
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode
import org.xiyu.githubdirect.root.BackendState
import org.xiyu.githubdirect.root.CapabilityProber
import org.xiyu.githubdirect.root.FirewallRules
import org.xiyu.githubdirect.root.RootBackend
import org.xiyu.githubdirect.root.RootBackendFailure
import org.xiyu.githubdirect.root.RootCapabilities
import org.xiyu.githubdirect.root.RootCapabilityProbe
import org.xiyu.githubdirect.root.RootShell
import org.xiyu.githubdirect.root.TransparentDnsListener
import org.xiyu.githubdirect.root.TransparentTcpListener
import org.xiyu.githubdirect.root.OriginalDestination
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.vpn.DnsVpnService
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Root 后端控制抽象（集成层依赖注入点；测试用 fake，生产用 [RootBackendAdapter]）。
 * RootBackend 是 final 类，经此接口隔离出 BackendManager 可单测的边界。
 */
interface RootBackendControl {
    val state: BackendState

    val lastFailure: RootBackendFailure? get() = null

    val activeGeneration: Long get() = 0L

    val realIpRedirectActive: Boolean get() = false

    val ipv6RealIpRedirectActive: Boolean get() = false

    val fullTlsCaptureUidCount: Int get() = 0

    val ipSetLeaseActive: Boolean get() = false

    val failOpenGuardianActive: Boolean get() = false

    val unclassifiedTlsTotal: Long get() = 0L

    val activeTcpSessions: Int get() = 0

    /** start 前注入 scope 规则构造器（BackendManager 按当前设置构建，uid 由 start 时探测提供）。 */
    fun configureScope(rulesBuilder: (Int) -> FirewallRules)

    fun start(dnsHandler: (ByteArray) -> ByteArray?, resolveRealIp: (Int) -> ByteArray?): Boolean

    /** 仅切换防火墙/guardian 代次；监听器与已建立的 TCP 会话必须保持运行。 */
    fun refreshRules(): Boolean = false

    fun stop(): Boolean

    /** Root 服务跨进程停止时清理可能由上个进程留下的数据面。 */
    fun cleanupStaleInstallation(): Boolean = stop()

    fun healthCheck(): Boolean

    /** 由 RootRelayService 每 5 秒调用；刷新 ipset 租约和独立 guardian 心跳。 */
    fun refreshFailOpenLease(): Boolean = true
}

/**
 * [RootBackend] 的集成适配：把真实组件（RootShell / 探测器 / 监听器）接上，
 * scope 规则构造器由 BackendManager 每次 start 前注入。
 */
class RootBackendAdapter(
    private val shell: RootShell = RootShell(),
    private val capabilities: CapabilityProber = RootCapabilityProbe(shell, android.os.Process.myUid()),
    private val dnsListener: org.xiyu.githubdirect.root.DnsListener = TransparentDnsListener(),
    private val tcpListener: org.xiyu.githubdirect.root.TcpListener = TransparentTcpListener(),
) : RootBackendControl {

    @Volatile
    private var scopeBuilder: ((Int) -> FirewallRules)? = null

    private val backend = RootBackend(
        shell = shell,
        capabilities = capabilities,
        dnsListener = dnsListener,
        tcpListener = tcpListener,
        rulesBuilder = { uid -> scopeBuilder?.invoke(uid) ?: FirewallRules(selfUid = uid) },
    )

    override val state: BackendState get() = backend.state
    override val lastFailure: RootBackendFailure? get() = backend.lastFailure
    override val activeGeneration: Long get() = backend.activeGeneration
    override val realIpRedirectActive: Boolean get() = backend.realIpRedirectActive
    override val ipv6RealIpRedirectActive: Boolean get() = backend.ipv6RealIpRedirectActive
    override val fullTlsCaptureUidCount: Int get() = backend.fullTlsCaptureUidCount
    override val ipSetLeaseActive: Boolean get() = backend.ipSetLeaseActive
    override val failOpenGuardianActive: Boolean get() = backend.failOpenGuardianActive
    override val unclassifiedTlsTotal: Long get() = backend.unclassifiedTlsTotal
    override val activeTcpSessions: Int get() = backend.activeTcpSessions

    override fun configureScope(rulesBuilder: (Int) -> FirewallRules) {
        scopeBuilder = rulesBuilder
    }

    override fun start(dnsHandler: (ByteArray) -> ByteArray?, resolveRealIp: (Int) -> ByteArray?): Boolean =
        backend.start(dnsHandler, resolveRealIp)

    override fun refreshRules(): Boolean = backend.refreshRules()

    override fun stop(): Boolean = backend.stop()

    override fun cleanupStaleInstallation(): Boolean = backend.cleanupStaleInstallation()

    override fun healthCheck(): Boolean = backend.healthCheck()

    override fun refreshFailOpenLease(): Boolean = backend.refreshFailOpenLease()
}

/**
 * 包名 → UID 的 scope 解析抽象（测试注入点）。
 * 结果为空（全部包未安装/非法）→ degraded=true；SELECTED 模式保持空集合（不接管任何应用）。
 */
interface ScopeUidResolver {
    fun resolveUids(mode: AppScopeMode, packages: Set<String>): ResolvedScope
}

/** scope 解析结果：uid 集合 + 是否降级（uids 为空且调用方原意是过滤时置 true）。 */
data class ResolvedScope(val uids: Set<Int>, val degraded: Boolean)

/**
 * PackageManager 实现（§67 注入安全延伸）：uid 是 PackageManager 产物（数字），
 * 绝不把用户输入直接拼进 shell 命令。
 */
class PackageScopeResolver(private val context: Context) : ScopeUidResolver {

    override fun resolveUids(mode: AppScopeMode, packages: Set<String>): ResolvedScope {
        if (mode == AppScopeMode.ALL_APPS) {
            return ResolvedScope(emptySet(), degraded = false)
        }
        if (packages.isEmpty()) return ResolvedScope(emptySet(), degraded = true)
        val uids = LinkedHashSet<Int>()
        for (pkg in packages) {
            if (!pkg.matches(PACKAGE_RE)) {
                Log.w(TAG, "非法包名，跳过: $pkg")
                continue
            }
            try {
                val uid = context.packageManager.getPackageUid(pkg, 0)
                if (uid > 0) uids.add(uid)
            } catch (t: Throwable) {
                Log.w(TAG, "包未安装，跳过: $pkg")
            }
        }
        if (uids.isEmpty()) {
            Log.w(TAG, "scope 解析结果为空；SELECTED 模式将保持不接管，EXCLUDED 模式等价于不排除")
            return ResolvedScope(uids, degraded = true)
        }
        return ResolvedScope(uids, degraded = false)
    }

    companion object {
        private const val TAG = "PackageScopeResolver"
        private val PACKAGE_RE = Regex("^[a-zA-Z][a-zA-Z0-9_.]*$")
    }
}

/**
 * 三大 backend 集成管理器（进程内单例，设计 §15/§16/§22）。
 *
 * 职责：
 * - start(mode) 统一入口：停旧 backend → 按模式启动（互斥保证）
 * - ROOT_TRANSPARENT：经 [RootBackendControl] 启动 Root 透明后端（不占 VPN slot）；
 *   DNS 处理器 = 共享 SelectiveDnsEngine.handleQuery（raw→raw，null 丢弃）；
 *   真实 IP 解析 = VirtualIpPool.lookupReal(vip)?.v4
 * - VPN：只负责记录模式与互斥（切 root 前发 ACTION_STOP 停 VPN）；服务启动仍走
 *   VpnService.prepare 授权流（MainActivity 编排），激活态经 vpnActiveCheck 查询
 * - XPOSED_ONLY：LSPosed DNS 注入；若 Root 能力可用则同时启动透明中继（SNI 分片）
 * - watchdog（§22 轻量）：ROOT 以及 Xposed 叠了 Root 中继时每 30s healthCheck；失败 → 一次 stop+start 修复；
 *   再失败 → rollback（stop）→ 通知监听器 FAILED
 *
 * 构造全部可注入（纯 JVM 可单测）；watchdog 线程在 watchdogEnabled=false 时停用（测试用）。
 */
class BackendManager @JvmOverloads constructor(
    private val settings: SettingsStore,
    private val rootBackend: RootBackendControl?,
    private val capProbe: CapabilityProber?,
    private val scopeResolver: ScopeUidResolver,
    private val dnsEngine: () -> SelectiveDnsEngine?,
    private val pool: () -> VirtualIpPool?,
    private val vpnActiveCheck: () -> Boolean = { false },
    private val vpnStopRequest: () -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis,
    private val watchdogIntervalMs: Long = WATCHDOG_INTERVAL_MS,
    private val watchdogEnabled: Boolean = true,
    private val onRootPrepare: () -> Unit = {},
    private val routeSnapshotProvider: () -> RouteSnapshot = { DirectEngine.routeSnapshot() },
    private val originalDestinationAvailable: () -> Boolean = OriginalDestination::available,
) {

    @Volatile
    private var currentModeInternal: BackendMode? = null

    @Volatile
    private var lastProbe: RootCapabilities? = null

    @Volatile
    private var lastProbeAt: Long = 0

    @Volatile
    private var rootDnsHandler: ((ByteArray) -> ByteArray?)? = null

    @Volatile
    private var rootResolveRealIp: ((Int) -> ByteArray?)? = null

    @Volatile
    private var lastScopeUids: Set<Int> = emptySet()

    @Volatile
    private var lastEmbeddedCaptureUids: Set<Int> = emptySet()

    private val listeners = CopyOnWriteArrayList<(BackendMode?, Boolean, String) -> Unit>()

    private var watchdogThread: HandlerThread? = null
    private var watchdogHandler: Handler? = null
    private val watchdogRunnable = object : Runnable {
        override fun run() {
            watchdogTick()
            watchdogHandler?.postDelayed(this, watchdogIntervalMs)
        }
    }

    // ==================== 查询 ====================

    /** 当前生效（或最近一次尝试）的模式。 */
    fun currentMode(): BackendMode? = currentModeInternal

    /**
     * 最近一次能力探测结果。
     * 成功缓存 [PROBE_CACHE_MS]；失败只缓存 [PROBE_FAIL_CACHE_MS]，避免刚在 KernelSU 授权后仍显示不可用。
     */
    fun rootCapabilities(force: Boolean = false): RootCapabilities? {
        val now = clock()
        val cached = lastProbe
        if (!force && cached != null) {
            val ttl = if (cached.requiredOk()) PROBE_CACHE_MS else PROBE_FAIL_CACHE_MS
            if (now - lastProbeAt < ttl) return cached
        }
        val caps = try {
            capProbe?.probe()
        } catch (t: Throwable) {
            Log.w(TAG, "root 探测异常: ${t.message}")
            null
        }
        lastProbe = caps
        lastProbeAt = now
        return caps
    }

    /** 不触发探测的缓存结果（UI 状态行用，避免主线程 su 调用）。 */
    fun cachedRootCapabilities(): RootCapabilities? = lastProbe

    /** AUTO 判定：root 能力齐备 → ROOT_TRANSPARENT，否则 VPN。 */
    fun resolveAuto(): BackendMode =
        if (rootCapabilities()?.requiredOk() == true) BackendMode.ROOT_TRANSPARENT else BackendMode.VPN

    /** Root 透明中继是否在跑（含 Xposed 模式下的 SNI 辅助中继）。 */
    fun isRootBackendActive(): Boolean = rootBackend?.state == BackendState.ACTIVE

    fun activeRuleGeneration(): Long = rootBackend?.activeGeneration ?: 0L

    fun realIpRedirectActive(): Boolean = rootBackend?.realIpRedirectActive == true

    fun ipv6RealIpRedirectActive(): Boolean = rootBackend?.ipv6RealIpRedirectActive == true

    fun fullTlsCaptureUidCount(): Int = rootBackend?.fullTlsCaptureUidCount ?: 0

    fun ipSetLeaseActive(): Boolean = rootBackend?.ipSetLeaseActive == true

    fun failOpenGuardianActive(): Boolean = rootBackend?.failOpenGuardianActive == true

    fun unclassifiedTlsTotal(): Long = rootBackend?.unclassifiedTlsTotal ?: 0L

    fun rootBackendFailure(): RootBackendFailure? = rootBackend?.lastFailure

    fun refreshFailOpenLease(): Boolean = rootBackend?.refreshFailOpenLease() ?: false

    fun rootScopeUids(): Set<Int> = lastScopeUids

    fun embeddedCaptureUids(): Set<Int> = lastEmbeddedCaptureUids

    /** 当前是否有后端在生效（VPN 服务静态激活态跨进程重启仍可识别）。 */
    fun isBackendActive(): Boolean {
        if (vpnActiveCheck()) return true
        return when (currentModeInternal) {
            null -> false
            BackendMode.ROOT_TRANSPARENT -> rootBackend?.state == BackendState.ACTIVE
            BackendMode.XPOSED_ONLY -> true // DNS 注入在目标进程；Root 中继是否起来另见 isRootBackendActive()
            else -> false
        }
    }

    fun addBackendListener(listener: (mode: BackendMode?, active: Boolean, message: String) -> Unit) {
        listeners += listener
    }

    // ==================== 生命周期 ====================

    /** 统一启动入口：停旧 backend → 按模式启动。与 stop/watchdogTick 同一把锁串行化，防止并发安装过期规则。 */
    @Synchronized
    fun start(mode: BackendMode): Boolean = when (mode) {
        BackendMode.AUTO -> start(resolveAuto())
        BackendMode.ROOT_TRANSPARENT -> startRoot()
        BackendMode.VPN -> startVpn()
        BackendMode.XPOSED_ONLY -> startXposedOnly()
    }

    /** 停止全部 backend，清空模式。与 start/watchdogTick 串行化。 */
    @Synchronized
    @JvmOverloads
    fun stop(cleanupStaleRoot: Boolean = false) {
        stopRoot(cleanupStaleRoot)
        if (vpnActiveCheck() || currentModeInternal == BackendMode.VPN) {
            try {
                vpnStopRequest()
            } catch (t: Throwable) {
                Log.w(TAG, "VPN 停止请求异常: ${t.message}")
            }
        }
        currentModeInternal = null
        try {
            DirectEngine.stopProviders()
            (DirectEngine.binder() as? org.xiyu.githubdirect.vpn.VpnNetworkBinder)?.stop()
        } catch (t: Throwable) {
            Log.w(TAG, "停 providers/binder 异常: ${t.message}")
        }
        notifyState(null, false, "已停止")
    }

    /** 候选 generation 变化时由前台服务串行调用：保持监听/会话，只切换自有规则与 guardian。 */
    @Synchronized
    fun refreshRootDataPlane(): Boolean {
        val mode = currentModeInternal
        if (mode != BackendMode.ROOT_TRANSPARENT && mode != BackendMode.XPOSED_ONLY) return false
        val rb = rootBackend ?: return false
        if (rb.state != BackendState.ACTIVE || !configureRootRules(rb, notifyOnMissing = false)) {
            try {
                rb.stop()
            } catch (_: Throwable) {
            }
            currentModeInternal = null
            stopWatchdog()
            notifyState(null, false, "Root 规则更新准备失败，已 fail-open 回滚")
            return false
        }
        val currentDataPlaneHealthy = try {
            rb.healthCheck()
        } catch (_: Throwable) {
            false
        }
        if (!currentDataPlaneHealthy) {
            // guardian 可能已在长耗时刷新期间按设计清除旧链。此时“保留 jump 的原位刷新”
            // 没有可复用的活动数据面，必须走一次完整 stop/start 重建，而不是生成无入口孤儿链。
            val handler = rootDnsHandler
            val resolveRealIp = rootResolveRealIp
            val repaired = try {
                rb.stop()
                handler != null && resolveRealIp != null &&
                    rb.start(handler, resolveRealIp) && rb.state == BackendState.ACTIVE
            } catch (t: Throwable) {
                Log.w(TAG, "Root 数据面缺失后的完整重建异常: ${t.message}")
                false
            }
            if (repaired) {
                notifyState(mode, true, "Root 规则已完整重建至 generation ${rb.activeGeneration}")
                return true
            }
            currentModeInternal = null
            stopWatchdog()
            notifyState(null, false, "Root 数据面缺失且重建失败，已 fail-open 回滚")
            return false
        }
        val ok = try {
            rb.refreshRules()
        } catch (t: Throwable) {
            Log.w(TAG, "Root 规则原位更新异常: ${t.message}")
            false
        }
        if (ok) {
            notifyState(mode, true, "Root 规则已更新至 generation ${rb.activeGeneration}")
            return true
        }
        currentModeInternal = null
        stopWatchdog()
        notifyState(null, false, "Root 规则更新失败，已 fail-open 回滚")
        return false
    }

    private fun startRoot(): Boolean {
        if (!launchRoot(notifyOnMissing = true)) {
            currentModeInternal = null
            return false
        }
        currentModeInternal = BackendMode.ROOT_TRANSPARENT
        startWatchdog()
        notifyState(BackendMode.ROOT_TRANSPARENT, true, "Root 透明模式已启用")
        return true
    }

    /**
     * 真正拉起 Root 透明中继（不改 currentMode）。
     * Xposed 模式会把它当 SNI 辅助层：LSPosed 只修 DNS，443 仍需分片才能过 GitHub。
     */
    private fun launchRoot(notifyOnMissing: Boolean): Boolean {
        val rb = rootBackend
        val engine = dnsEngine()
        val vp = pool()
        if (rb == null || engine == null || vp == null) {
            Log.w(TAG, "Root 后端组件不可用（root=$rb engine=$engine pool=$vp）")
            if (notifyOnMissing) {
                notifyState(BackendMode.ROOT_TRANSPARENT, false, "Root 后端组件不可用")
            }
            return false
        }
        if (vpnActiveCheck() || currentModeInternal == BackendMode.VPN) {
            try {
                vpnStopRequest()
            } catch (t: Throwable) {
                Log.w(TAG, "VPN 停止请求异常: ${t.message}")
            }
        }

        if (!configureRootRules(rb, notifyOnMissing)) return false

        val handler: (ByteArray) -> ByteArray? = { raw ->
            try {
                engine.handleQuery(raw) ?: org.xiyu.githubdirect.core.dns.DnsPacketCodec.buildServFailResponse(raw)
            } catch (t: Throwable) {
                org.xiyu.githubdirect.core.dns.DnsPacketCodec.buildServFailResponse(raw)
            }
        }
        val realIp: (Int) -> ByteArray? = { vip -> vp.lookupReal(vip)?.v4 }

        val ok = try {
            rb.start(handler, realIp)
        } catch (t: Throwable) {
            Log.w(TAG, "Root 启动异常: ${t.message}")
            false
        }
        if (!ok || rb.state != BackendState.ACTIVE) {
            val failure = rb.lastFailure
            val diagnostic = failure?.let { "${it.stage}: ${it.detail}" }.orEmpty()
            Log.w(TAG, "Root 后端启动失败${diagnostic.takeIf { it.isNotBlank() }?.let { ": $it" }.orEmpty()}")
            if (notifyOnMissing) {
                notifyState(
                    BackendMode.ROOT_TRANSPARENT,
                    false,
                    if (diagnostic.isBlank()) "Root 后端启动失败" else "Root 后端启动失败（$diagnostic）",
                )
            }
            return false
        }
        rootDnsHandler = handler
        rootResolveRealIp = realIp
        return true
    }

    /** 重新解析能力/scope 并注入下一代规则构造器；不触碰正在运行的监听器。 */
    private fun configureRootRules(rb: RootBackendControl, notifyOnMissing: Boolean): Boolean {
        lastEmbeddedCaptureUids = emptySet()
        val caps = try {
            rootCapabilities()
        } catch (t: Throwable) {
            Log.w(TAG, "root 探测异常: ${t.message}")
            null
        }
        if (caps?.requiredOk() != true) {
            val missing = caps?.missingRequired()?.joinToString().orEmpty().ifBlank { "探测失败" }
            Log.w(TAG, "root 探测未通过: missing=$missing caps=$caps")
            if (notifyOnMissing) {
                notifyState(BackendMode.ROOT_TRANSPARENT, false, "Root 探测未通过：缺少 $missing")
            }
            return false
        }

        val scopeMode = settings.appScopeMode()
        val packages = settings.scopedPackages()
        val resolved = scopeResolver.resolveUids(scopeMode, packages)
        lastScopeUids = resolved.uids
        if (resolved.degraded) Log.w(TAG, "scope 中没有可解析 UID（mode=$scopeMode）")
        if (scopeMode == AppScopeMode.SELECTED_APPS && resolved.uids.isEmpty()) {
            if (notifyOnMissing) {
                notifyState(
                    BackendMode.ROOT_TRANSPARENT,
                    false,
                    "Root 作用域为空：请明确选择平台客户端、内置运行时宿主或浏览器",
                )
            }
            return false
        }
        // Electron-like 宿主的全 TLS 捕获是第二层显式授权，并且只能是 SELECTED scope 的子集。
        // 解析结果仍来自 PackageManager UID，绝不把包名直接拼进 shell。
        val embeddedPackages = if (scopeMode == AppScopeMode.SELECTED_APPS) {
            settings.embeddedTlsCapturePackages().intersect(packages)
        } else {
            emptySet()
        }
        val resolvedEmbeddedUids = if (embeddedPackages.isEmpty()) {
            emptySet()
        } else {
            scopeResolver.resolveUids(AppScopeMode.SELECTED_APPS, embeddedPackages).uids
                .intersect(resolved.uids)
        }
        val embeddedUids = if (
            settings.isRealIpRedirectEnabled() && originalDestinationAvailable()
        ) resolvedEmbeddedUids else emptySet()
        lastEmbeddedCaptureUids = embeddedUids
        rb.configureScope { selfUid ->
            buildFirewallRules(selfUid, scopeMode, resolved.uids, embeddedUids, caps)
        }
        try {
            onRootPrepare()
        } catch (t: Throwable) {
            Log.w(TAG, "Root 预备（hosts/binder）失败: ${t.message}")
        }
        return true
    }

    /** VPN：只记录模式与互斥；服务启动由调用方（prepare 授权流）负责。 */
    private fun startVpn(): Boolean {
        // 互斥：切 VPN 前停 root
        if (rootBackend?.state == BackendState.ACTIVE || currentModeInternal == BackendMode.ROOT_TRANSPARENT) {
            stopRoot()
        }
        currentModeInternal = BackendMode.VPN
        notifyState(BackendMode.VPN, vpnActiveCheck(), "VPN 模式")
        return true
    }

    /**
     * Xposed：DNS hook 在目标进程生效。
     * LSPosed 设备通常具备 root，因此同时尝试启动透明中继，为启用平台处理 SNI 阻断。
     * Root 拉不起来也不失败——退化为纯 DNS。
     */
    private fun startXposedOnly(): Boolean {
        if (rootBackend?.state == BackendState.ACTIVE || currentModeInternal == BackendMode.ROOT_TRANSPARENT) {
            stopRoot()
        }
        if (vpnActiveCheck() || currentModeInternal == BackendMode.VPN) {
            try {
                vpnStopRequest()
            } catch (t: Throwable) {
                Log.w(TAG, "VPN 停止请求异常: ${t.message}")
            }
        }
        val rootAssist = launchRoot(notifyOnMissing = false)
        currentModeInternal = BackendMode.XPOSED_ONLY
        if (rootAssist) startWatchdog()
        notifyState(
            BackendMode.XPOSED_ONLY,
            true,
            if (rootAssist) "Xposed + Root 透明中继已启用" else "Xposed 本地 DNS 已启用（无 SNI 分片）",
        )
        return true
    }

    private fun stopRoot(cleanupStale: Boolean = false) {
        stopWatchdog()
        rootDnsHandler = null
        rootResolveRealIp = null
        try {
            if (cleanupStale) rootBackend?.cleanupStaleInstallation() else rootBackend?.stop()
        } catch (t: Throwable) {
            Log.w(TAG, "Root 停止异常: ${t.message}")
        }
    }

    // ==================== watchdog（§22 轻量，仅 ROOT 模式） ====================

    /** 周期检测：healthCheck 失败 → 一次 stop+start 修复 → 仍失败 → rollback + FAILED 通知。
     *  与 start/stop 串行化：修复期间用户切换模式不会交错安装过期规则。 */
    @Synchronized
    internal fun watchdogTick() {
        val watchingRoot = currentModeInternal == BackendMode.ROOT_TRANSPARENT
                || (currentModeInternal == BackendMode.XPOSED_ONLY && rootBackend?.state == BackendState.ACTIVE)
        if (!watchingRoot) return
        val rb = rootBackend ?: return

        val healthy = try {
            rb.healthCheck()
        } catch (t: Throwable) {
            false
        }
        if (healthy) return

        Log.w(TAG, "watchdog: Root 后端失联，尝试一次修复")
        var repaired = false
        try {
            rb.stop()
            val h = rootDnsHandler
            val r = rootResolveRealIp
            if (h != null && r != null) {
                repaired = rb.start(h, r) && rb.state == BackendState.ACTIVE
            }
        } catch (t: Throwable) {
            repaired = false
        }
        if (repaired) {
            notifyState(currentModeInternal, true, "watchdog 修复成功")
            return
        }

        // 修复失败 → rollback（stop）并通知 FAILED
        try {
            rb.stop()
        } catch (t: Throwable) {
        }
        currentModeInternal = null
        stopWatchdog()
        notifyState(null, false, "Root 后端失联，已回滚（FAILED）")
    }

    private fun startWatchdog() {
        if (!watchdogEnabled) return
        stopWatchdog()
        val thread = HandlerThread("GHD-Watchdog").apply { start() }
        watchdogThread = thread
        watchdogHandler = Handler(thread.looper).also { it.post(watchdogRunnable) }
    }

    private fun stopWatchdog() {
        watchdogHandler?.removeCallbacksAndMessages(null)
        watchdogHandler = null
        watchdogThread?.quitSafely()
        watchdogThread = null
    }

    // ==================== 规则构造（§40/§41/§42） ====================

    /**
     * scope → FirewallRules（uid 全部来自 PackageManager，数字，绝无用户输入拼接）。
     * ALL_APPS → 全量；SELECTED 空集合 → 不接管；EXCLUDED 空集合 → 不排除。
     */
    private fun buildFirewallRules(
        selfUid: Int,
        mode: AppScopeMode,
        uids: Set<Int>,
        embeddedCaptureUids: Set<Int>,
        capabilities: RootCapabilities,
    ): FirewallRules {
        if (mode == AppScopeMode.EXCLUDED_APPS && uids.size > FirewallRules.MAX_EXCLUDED_UIDS) {
            Log.w(TAG, "EXCLUDED scope 超出上限(${FirewallRules.MAX_EXCLUDED_UIDS})，截断")
        }
        val snapshot = routeSnapshotProvider()
        val enableRealRedirect = settings.isRealIpRedirectEnabled() && originalDestinationAvailable()
        val effectiveScope = when (mode) {
            AppScopeMode.ALL_APPS -> null
            AppScopeMode.EXCLUDED_APPS -> uids.take(FirewallRules.MAX_EXCLUDED_UIDS).toSet()
            AppScopeMode.SELECTED_APPS -> uids.take(MAX_SELECTED_UIDS).toSet()
        }
        return FirewallRules(
            selfUid = selfUid,
            scopeUids = effectiveScope,
            scopeInclude = mode == AppScopeMode.SELECTED_APPS,
            fullTlsCaptureUids = if (enableRealRedirect) embeddedCaptureUids else emptySet(),
            directDestinations = snapshot.interceptDestinations(),
            enableRealIpRedirect = enableRealRedirect,
            enableIpv6Redirect = capabilities.ipv6Netfilter,
            useIpSet = capabilities.ipset,
            rejectUdp443 = capabilities.rejectTarget,
            rejectIpv6Udp443 = capabilities.ipv6RejectTarget,
            generation = snapshot.generation,
        )
    }

    private fun notifyState(mode: BackendMode?, active: Boolean, message: String) {
        for (l in listeners) {
            try {
                l(mode, active, message)
            } catch (t: Throwable) {
                // 监听器异常不扩散
            }
        }
    }

    companion object {
        private const val TAG = "BackendManager"
        const val WATCHDOG_INTERVAL_MS = 30_000L
        const val PROBE_CACHE_MS = 60_000L
        const val PROBE_FAIL_CACHE_MS = 5_000L
        const val MAX_SELECTED_UIDS = 32

        @Volatile
        private var instance: BackendManager? = null

        /** 进程内单例（Android 真实装配；测试直接构造注入 fake）。 */
        @JvmStatic
        fun get(context: Context): BackendManager {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                val ctx = context.applicationContext
                val shell = RootShell()
                val appUid = android.os.Process.myUid()
                val probe = RootCapabilityProbe(shell, appUid)
                val manager = BackendManager(
                    settings = DirectEngine.settings() ?: AndroidSettingsStore(ctx),
                    rootBackend = RootBackendAdapter(shell = shell, capabilities = probe),
                    capProbe = probe,
                    scopeResolver = PackageScopeResolver(ctx),
                    dnsEngine = { DirectEngine.dnsEngine() },
                    pool = { DirectEngine.pool() },
                    vpnActiveCheck = { DnsVpnService.isActive() },
                    vpnStopRequest = {
                        try {
                            val intent = Intent(ctx, DnsVpnService::class.java)
                            intent.action = DnsVpnService.ACTION_STOP
                            ctx.startService(intent)
                        } catch (t: Throwable) {
                            Log.w(TAG, "VPN 停止请求失败: ${t.message}")
                        }
                    },
                    onRootPrepare = {
                        DirectEngine.ensureInit(ctx, true)
                        (DirectEngine.binder() as? org.xiyu.githubdirect.vpn.VpnNetworkBinder)?.start()
                    },
                )
                instance = manager
                return manager
            }
        }
    }
}

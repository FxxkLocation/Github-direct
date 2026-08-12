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
import org.xiyu.githubdirect.root.RootCapabilities
import org.xiyu.githubdirect.root.RootCapabilityProbe
import org.xiyu.githubdirect.root.RootShell
import org.xiyu.githubdirect.root.TransparentDnsListener
import org.xiyu.githubdirect.root.TransparentTcpListener
import org.xiyu.githubdirect.vpn.DnsVpnService
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Root 后端控制抽象（集成层依赖注入点；测试用 fake，生产用 [RootBackendAdapter]）。
 * RootBackend 是 final 类，经此接口隔离出 BackendManager 可单测的边界。
 */
interface RootBackendControl {
    val state: BackendState

    /** start 前注入 scope 规则构造器（BackendManager 按当前设置构建，uid 由 start 时探测提供）。 */
    fun configureScope(rulesBuilder: (Int) -> FirewallRules)

    fun start(dnsHandler: (ByteArray) -> ByteArray?, resolveRealIp: (Int) -> ByteArray?): Boolean

    fun stop(): Boolean

    fun healthCheck(): Boolean
}

/**
 * [RootBackend] 的集成适配：把真实组件（RootShell / 探测器 / 监听器）接上，
 * scope 规则构造器由 BackendManager 每次 start 前注入。
 */
class RootBackendAdapter(
    private val shell: RootShell = RootShell(),
    private val capabilities: CapabilityProber = RootCapabilityProbe(RootShell()),
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

    override fun configureScope(rulesBuilder: (Int) -> FirewallRules) {
        scopeBuilder = rulesBuilder
    }

    override fun start(dnsHandler: (ByteArray) -> ByteArray?, resolveRealIp: (Int) -> ByteArray?): Boolean =
        backend.start(dnsHandler, resolveRealIp)

    override fun stop(): Boolean = backend.stop()

    override fun healthCheck(): Boolean = backend.healthCheck()
}

/**
 * 包名 → UID 的 scope 解析抽象（测试注入点）。
 * 结果为空（全部包未安装/非法）→ degraded=true，调用方降级 ALL_APPS。
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
        if (mode == AppScopeMode.ALL_APPS || packages.isEmpty()) {
            return ResolvedScope(emptySet(), degraded = false)
        }
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
            Log.w(TAG, "scope 解析结果为空，降级 ALL_APPS")
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
 * - XPOSED_ONLY：不启动任何 backend，状态直接 ACTIVE
 * - watchdog（§22 轻量）：仅 ROOT 模式每 30s healthCheck；失败 → 一次 stop+start 修复；
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
     * 最近一次能力探测结果（60s 内缓存；缓存未命中时发起真实探测）。
     * 探测为 su 提权 + 多条命令，仅在用户主动切换/启动时调用。
     */
    fun rootCapabilities(): RootCapabilities? {
        val now = clock()
        val cached = lastProbe
        if (cached != null && now - lastProbeAt < PROBE_CACHE_MS) return cached
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

    /** 当前是否有后端在生效（VPN 服务静态激活态跨进程重启仍可识别）。 */
    fun isBackendActive(): Boolean {
        if (vpnActiveCheck()) return true
        return when (currentModeInternal) {
            null -> false
            BackendMode.ROOT_TRANSPARENT -> rootBackend?.state == BackendState.ACTIVE
            BackendMode.XPOSED_ONLY -> true
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
    fun stop() {
        stopRoot()
        if (vpnActiveCheck() || currentModeInternal == BackendMode.VPN) {
            try {
                vpnStopRequest()
            } catch (t: Throwable) {
                Log.w(TAG, "VPN 停止请求异常: ${t.message}")
            }
        }
        currentModeInternal = null
        notifyState(null, false, "已停止")
    }

    private fun startRoot(): Boolean {
        val rb = rootBackend
        val engine = dnsEngine()
        val vp = pool()
        if (rb == null || engine == null || vp == null) {
            Log.w(TAG, "Root 后端组件不可用（root=$rb engine=$engine pool=$vp）")
            notifyState(BackendMode.ROOT_TRANSPARENT, false, "Root 后端组件不可用")
            return false
        }
        // 互斥：切 root 前停 VPN
        if (vpnActiveCheck() || currentModeInternal == BackendMode.VPN) {
            try {
                vpnStopRequest()
            } catch (t: Throwable) {
                Log.w(TAG, "VPN 停止请求异常: ${t.message}")
            }
        }

        // 按 scope 配置构造规则（空结果降级 ALL_APPS，绝不让 uid 为空的白名单拦截一切）
        val scopeMode = settings.appScopeMode()
        val packages = settings.scopedPackages()
        val resolved = scopeResolver.resolveUids(scopeMode, packages)
        if (resolved.degraded) {
            Log.w(TAG, "scope 解析降级为 ALL_APPS（mode=$scopeMode）")
        }
        rb.configureScope { selfUid -> buildFirewallRules(selfUid, scopeMode, resolved.uids) }

        val handler: (ByteArray) -> ByteArray? = { raw -> engine.handleQuery(raw) }
        val realIp: (Int) -> ByteArray? = { vip -> vp.lookupReal(vip)?.v4 }

        val ok = try {
            rb.start(handler, realIp)
        } catch (t: Throwable) {
            Log.w(TAG, "Root 启动异常: ${t.message}")
            false
        }
        if (!ok || rb.state != BackendState.ACTIVE) {
            currentModeInternal = null
            notifyState(BackendMode.ROOT_TRANSPARENT, false, "Root 后端启动失败")
            return false
        }
        rootDnsHandler = handler
        rootResolveRealIp = realIp
        currentModeInternal = BackendMode.ROOT_TRANSPARENT
        startWatchdog()
        notifyState(BackendMode.ROOT_TRANSPARENT, true, "Root 透明模式已启用")
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

    /** Xposed：不启动任何 backend，状态直接 ACTIVE（DNS 修复在目标进程生效）。 */
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
        currentModeInternal = BackendMode.XPOSED_ONLY
        notifyState(BackendMode.XPOSED_ONLY, true, "Xposed 本地模式已启用")
        return true
    }

    private fun stopRoot() {
        stopWatchdog()
        rootDnsHandler = null
        rootResolveRealIp = null
        try {
            rootBackend?.stop()
        } catch (t: Throwable) {
            Log.w(TAG, "Root 停止异常: ${t.message}")
        }
    }

    // ==================== watchdog（§22 轻量，仅 ROOT 模式） ====================

    /** 周期检测：healthCheck 失败 → 一次 stop+start 修复 → 仍失败 → rollback + FAILED 通知。
     *  与 start/stop 串行化：修复期间用户切换模式不会交错安装过期规则。 */
    @Synchronized
    internal fun watchdogTick() {
        if (currentModeInternal != BackendMode.ROOT_TRANSPARENT) return
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
            notifyState(BackendMode.ROOT_TRANSPARENT, true, "watchdog 修复成功")
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
     * ALL_APPS / 解析为空 → 全量；SELECTED → 白名单子链；EXCLUDED → 叠加排除（上限截断防御）。
     */
    private fun buildFirewallRules(selfUid: Int, mode: AppScopeMode, uids: Set<Int>): FirewallRules {
        if (mode == AppScopeMode.ALL_APPS || uids.isEmpty()) {
            return FirewallRules(selfUid = selfUid)
        }
        if (mode == AppScopeMode.EXCLUDED_APPS && uids.size > FirewallRules.MAX_EXCLUDED_UIDS) {
            Log.w(TAG, "EXCLUDED scope 超出上限(${FirewallRules.MAX_EXCLUDED_UIDS})，截断")
        }
        return FirewallRules(
            selfUid = selfUid,
            scopeUids = uids.take(FirewallRules.MAX_EXCLUDED_UIDS).toSet(),
            scopeInclude = mode == AppScopeMode.SELECTED_APPS,
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

        @Volatile
        private var instance: BackendManager? = null

        /** 进程内单例（Android 真实装配；测试直接构造注入 fake）。 */
        @JvmStatic
        fun get(context: Context): BackendManager {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                val ctx = context.applicationContext
                val manager = BackendManager(
                    settings = DirectEngine.settings() ?: AndroidSettingsStore(ctx),
                    rootBackend = RootBackendAdapter(),
                    capProbe = RootCapabilityProbe(RootShell()),
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
                )
                instance = manager
                return manager
            }
        }
    }
}

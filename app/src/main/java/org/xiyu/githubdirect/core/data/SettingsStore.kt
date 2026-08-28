package org.xiyu.githubdirect.core.data

import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode

/** 安全默认值：只接管 GitHub App；浏览器和 Git 客户端必须由用户明确加入。 */
object ScopeDefaults {
    val MODE: AppScopeMode = AppScopeMode.SELECTED_APPS
    val PACKAGES: Set<String> = setOf("com.github.android")
}

/**
 * 设置持久化接口（Android 实现为 SharedPreferences "direct_settings"）。
 *
 * key 命名空间：service.enabled.{id} / diagnostics.enabled / hosts.{providerId}.data|lastSync /
 * backend.mode / scope.mode / scope.packages
 */
interface SettingsStore {

    fun isServiceEnabled(id: String, default: Boolean): Boolean

    fun setServiceEnabled(id: String, enabled: Boolean)

    /**
     * 批量写入服务启用状态。Android 实现应使用单次 SharedPreferences.Editor 提交，
     * 避免“全部开启/关闭”时产生 N 次持久化写入。
     */
    fun setServicesEnabled(ids: Collection<String>, enabled: Boolean) {
        for (id in ids) setServiceEnabled(id, enabled)
    }

    fun isDiagEnabled(): Boolean

    fun setDiagEnabled(v: Boolean)

    /** (raw hosts data, lastSyncMillis)；无缓存返回 null。 */
    fun hostsData(providerId: String): Pair<String, Long>?

    fun saveHostsData(providerId: String, data: String, lastSync: Long)

    // ==================== 后端模式（§15/§40） ====================

    fun backendMode(): BackendMode

    fun setBackendMode(mode: BackendMode)

    fun appScopeMode(): AppScopeMode

    fun setAppScopeMode(mode: AppScopeMode)

    /** 作用域选中的应用包名集合（SELECTED_APPS / EXCLUDED_APPS 时生效）。 */
    fun scopedPackages(): Set<String>

    fun setScopedPackages(packages: Set<String>)

    /**
     * Electron-like / WebView / Cronet 宿主的可选全 TLS 捕获包。
     *
     * 仅在 SELECTED_APPS + Root 真实原目的地址可用时生效；未命中启用域名的连接仍按
     * 原目的地址原样透传。默认空集合，禁止静默扩大任一应用的 HTTPS 接管面。
     */
    fun embeddedTlsCapturePackages(): Set<String> = emptySet()

    fun setEmbeddedTlsCapturePackages(packages: Set<String>) = Unit

    /** Root 前台服务是否由用户启用；默认关闭，禁止安装后自动接管流量。 */
    fun isRootServiceEnabled(): Boolean = false

    fun setRootServiceEnabled(enabled: Boolean) = Unit

    /** 开机自启是独立显式选项；启用 Root 服务不等于允许开机自启。 */
    fun isRootAutoStartEnabled(): Boolean = false

    fun setRootAutoStartEnabled(enabled: Boolean) = Unit

    /** 分阶段发布开关；按依赖顺序关闭 tls_fragment_v2 → real_ip_redirect → adaptive_candidates。 */
    fun isAdaptiveCandidatesEnabled(): Boolean = true

    fun setAdaptiveCandidatesEnabled(enabled: Boolean) = Unit

    fun isRealIpRedirectEnabled(): Boolean = true

    fun setRealIpRedirectEnabled(enabled: Boolean) = Unit

    fun isTlsFragmentV2Enabled(): Boolean = true

    fun setTlsFragmentV2Enabled(enabled: Boolean) = Unit

    /**
     * 可选的本机 TLS 终止路径。默认关闭；只有每设备 CA 已进入系统信任库且本地
     * sni-gate 健康时才会发布路由，关闭后立即退回不解密的候选/分片路径。
     */
    fun isTlsTerminationEnabled(): Boolean = false

    fun setTlsTerminationEnabled(enabled: Boolean) = Unit

    /**
     * OpenAI/ChatGPT 的第三方公共 NAT64 可用性兜底。默认关闭；配置完整且用户单独确认
     * 风险后才可能进入数据面，运行时仍须做真实 ECH/证书预检。
     */
    fun nat64FallbackConfig(): Nat64FallbackConfig = Nat64FallbackConfig.DISABLED

    fun setNat64FallbackConfig(config: Nat64FallbackConfig) = Unit

    /** 小型、版本化的跨进程路由快照。 */
    fun routeSnapshot(): Pair<String, Long>? = null

    fun saveRouteSnapshot(json: String, generation: Long) = Unit

    /** 返回或创建安装级 128-bit 随机令牌；Hook 心跳必须回显该令牌。 */
    fun ensureHookHeartbeatToken(): String? = null

    fun recordHookHeartbeat(heartbeat: HookHeartbeat) = Unit

    fun hookHeartbeats(): List<HookHeartbeat> = emptyList()

    /** SharedPreferences/远程设置发生变化时通知；非 Android 实现可保持 no-op。 */
    fun addChangeListener(listener: (String) -> Unit): java.io.Closeable? = null
}

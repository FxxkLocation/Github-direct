package org.xiyu.githubdirect.core.data

import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode

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
}

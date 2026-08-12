package org.xiyu.githubdirect.data

import android.content.Context
import android.content.SharedPreferences
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode

/**
 * SettingsStore 的 SharedPreferences 实现（"direct_settings"）。
 *
 * key：service.enabled.{id} / diagnostics.enabled / hosts.{providerId}.data|lastSync /
 * backend.mode / scope.mode / scope.packages
 */
class AndroidSettingsStore(context: Context) : SettingsStore {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    override fun isServiceEnabled(id: String, default: Boolean): Boolean =
        prefs.getBoolean("service.enabled.$id", default)

    override fun setServiceEnabled(id: String, enabled: Boolean) {
        prefs.edit().putBoolean("service.enabled.$id", enabled).apply()
    }

    override fun setServicesEnabled(ids: Collection<String>, enabled: Boolean) {
        if (ids.isEmpty()) return
        val editor = prefs.edit()
        for (id in ids) {
            editor.putBoolean("service.enabled.$id", enabled)
        }
        editor.apply()
    }

    override fun isDiagEnabled(): Boolean = prefs.getBoolean("diagnostics.enabled", false)

    override fun setDiagEnabled(v: Boolean) {
        prefs.edit().putBoolean("diagnostics.enabled", v).apply()
    }

    override fun hostsData(providerId: String): Pair<String, Long>? {
        val data = prefs.getString("hosts.$providerId.data", null) ?: return null
        val lastSync = prefs.getLong("hosts.$providerId.lastSync", 0)
        return data to lastSync
    }

    override fun saveHostsData(providerId: String, data: String, lastSync: Long) {
        prefs.edit()
            .putString("hosts.$providerId.data", data)
            .putLong("hosts.$providerId.lastSync", lastSync)
            .apply()
    }

    // ==================== 后端模式（§15/§40） ====================

    override fun backendMode(): BackendMode =
        BackendMode.values().firstOrNull { it.name == prefs.getString(KEY_BACKEND_MODE, null) }
            ?: BackendMode.AUTO

    override fun setBackendMode(mode: BackendMode) {
        prefs.edit().putString(KEY_BACKEND_MODE, mode.name).apply()
    }

    override fun appScopeMode(): AppScopeMode =
        AppScopeMode.values().firstOrNull { it.name == prefs.getString(KEY_SCOPE_MODE, null) }
            ?: AppScopeMode.ALL_APPS

    override fun setAppScopeMode(mode: AppScopeMode) {
        prefs.edit().putString(KEY_SCOPE_MODE, mode.name).apply()
    }

    override fun scopedPackages(): Set<String> =
        prefs.getStringSet(KEY_SCOPE_PACKAGES, null) ?: emptySet()

    override fun setScopedPackages(packages: Set<String>) {
        prefs.edit().putStringSet(KEY_SCOPE_PACKAGES, packages.toSet()).apply()
    }

    companion object {
        const val PREFS_NAME = "direct_settings"

        private const val KEY_BACKEND_MODE = "backend.mode"
        private const val KEY_SCOPE_MODE = "scope.mode"
        private const val KEY_SCOPE_PACKAGES = "scope.packages"
    }
}

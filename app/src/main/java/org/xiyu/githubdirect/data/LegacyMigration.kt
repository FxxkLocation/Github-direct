package org.xiyu.githubdirect.data

import android.content.Context

/**
 * 旧 key 一次性迁移（App.onCreate 调用）。
 *
 * 旧 prefs "github_hosts"（KEY_HOSTS_DATA/KEY_LAST_SYNC）→ 新 prefs "direct_settings" 的
 * hosts.github-hosts.data/lastSync，然后删除旧 prefs 文件。
 * 纯缓存数据，迁移失败静默忽略（代价仅一次重新拉取）。
 */
object LegacyMigration {

    private const val OLD_PREFS_NAME = "github_hosts"
    private const val OLD_KEY_HOSTS_DATA = "hosts_data"
    private const val OLD_KEY_LAST_SYNC = "last_sync"
    private const val PROVIDER_ID = "github-hosts"

    fun run(context: Context) {
        try {
            val old = context.getSharedPreferences(OLD_PREFS_NAME, Context.MODE_PRIVATE)
            val data = old.getString(OLD_KEY_HOSTS_DATA, null) ?: return
            val lastSync = old.getLong(OLD_KEY_LAST_SYNC, 0)
            if (data.isNullOrEmpty()) return

            val store = AndroidSettingsStore(context)
            val existing = store.hostsData(PROVIDER_ID)
            if (existing == null || existing.second < lastSync) {
                store.saveHostsData(PROVIDER_ID, data, lastSync)
            }
            // 删除旧 prefs 文件
            old.edit().clear().commit()
        } catch (_: Throwable) {
            // 静默失败
        }
    }
}

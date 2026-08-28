package org.xiyu.githubdirect

import android.app.Application
import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper
import org.xiyu.githubdirect.data.AndroidSettingsStore
import org.xiyu.githubdirect.data.LegacyMigration
import org.xiyu.githubdirect.data.RemoteSettingsBridge
import org.xiyu.githubdirect.data.RemoteSettingsSync
import java.util.concurrent.CopyOnWriteArraySet

class App : Application(), XposedServiceHelper.OnServiceListener {

    interface ServiceStateListener {
        fun onServiceBind(service: XposedService)
        fun onServiceDied(service: XposedService)
        fun onRemoteSettingsStateChanged(ready: Boolean, message: String) = Unit
        fun onHookHeartbeatChanged() = Unit
    }

    @Volatile
    var service: XposedService? = null
        private set

    @Volatile
    var remoteSettingsReady: Boolean = false
        private set

    @Volatile
    var remoteSettingsMessage: String = "等待 LSPosed 服务"
        private set

    private val listeners = CopyOnWriteArraySet<ServiceStateListener>()
    private lateinit var remoteSettingsBridge: RemoteSettingsBridge
    private val heartbeatListener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key != null && RemoteSettingsSync.isHookHeartbeatKey(key)) {
            for (listener in listeners) listener.onHookHeartbeatChanged()
        }
    }

    override fun onCreate() {
        super.onCreate()
        // 旧版 hosts 数据迁移（github_hosts → direct_settings；失败静默）
        LegacyMigration.run(this)
        val preferences = getSharedPreferences(AndroidSettingsStore.PREFS_NAME, MODE_PRIVATE)
        preferences.registerOnSharedPreferenceChangeListener(heartbeatListener)
        remoteSettingsBridge = RemoteSettingsBridge(
            preferences,
            ::updateRemoteSettingsState,
        )
        XposedServiceHelper.registerListener(this)
    }

    fun addServiceStateListener(listener: ServiceStateListener) {
        listeners.add(listener)
        service?.let { listener.onServiceBind(it) }
    }

    fun removeServiceStateListener(listener: ServiceStateListener) {
        listeners.remove(listener)
    }

    override fun onServiceBind(service: XposedService) {
        this.service = service
        updateRemoteSettingsState(false, "正在同步 LSPosed 远程配置")
        remoteSettingsBridge.bind(service)
        for (listener in listeners) {
            listener.onServiceBind(service)
        }
    }

    override fun onServiceDied(service: XposedService) {
        // 重连时旧 Binder 的死亡回调可能晚于新 Binder 的 onServiceBind；只清理当前连接。
        if (this.service !== service) return
        this.service = null
        updateRemoteSettingsState(false, "LSPosed 服务已断开")
        remoteSettingsBridge.unbind()
        for (listener in listeners) {
            listener.onServiceDied(service)
        }
    }

    private fun updateRemoteSettingsState(ready: Boolean, message: String) {
        remoteSettingsReady = ready
        remoteSettingsMessage = message
        for (listener in listeners) {
            listener.onRemoteSettingsStateChanged(ready, message)
        }
    }
}

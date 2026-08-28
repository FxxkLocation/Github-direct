package org.xiyu.githubdirect.data

import android.content.SharedPreferences
import io.github.libxposed.service.XposedService
import java.io.Closeable
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * 模块应用的私有 SharedPreferences 与 LSPosed Remote Preferences 并不是同一存储。
 *
 * 只同步 Hook 真正需要的配置：服务开关、已激活路由快照与心跳令牌；Root、作用域及 hosts
 * 原始数据继续只留在应用私有目录。目标进程里的远程偏好是只读的，Hook 心跳改由受令牌和
 * Binder 调用 UID 双重校验的 write-only Provider 回传。远程配置提交在单线程后台执行，
 * 心跳由目标进程的后台调度器调用 Provider，不阻塞 Activity、Root 服务或 DNS 热路径。
 */
internal class RemoteSettingsBridge(
    private val local: SharedPreferences,
    private val onStateChanged: (ready: Boolean, message: String) -> Unit,
) : Closeable {

    private val closed = AtomicBoolean(false)
    private val epoch = AtomicLong(0L)
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "GHD-RemoteSettings").apply { isDaemon = true }
    }

    @Volatile
    private var remote: SharedPreferences? = null

    private val localListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == null || !RemoteSettingsSync.isHookConfigurationKey(key)) return@OnSharedPreferenceChangeListener
        val expectedEpoch = epoch.get()
        enqueue {
            if (closed.get() || epoch.get() != expectedEpoch) return@enqueue
            val current = remote ?: return@enqueue
            try {
                check(RemoteSettingsSync.pushHookConfiguration(local, current)) {
                    "LSPosed Remote Preferences 拒绝配置提交"
                }
                reportIfCurrent(expectedEpoch, true, "已同步 LSPosed 远程配置")
            } catch (t: Throwable) {
                reportIfCurrent(expectedEpoch, false, failureMessage(t))
            }
        }
    }

    init {
        local.registerOnSharedPreferenceChangeListener(localListener)
    }

    fun bind(service: XposedService) {
        val expectedEpoch = epoch.incrementAndGet()
        enqueue {
            try {
                check(service.frameworkProperties and XposedService.PROP_CAP_REMOTE != 0L) {
                    "当前框架不支持 Remote Preferences"
                }
                val preferences = service.getRemotePreferences(AndroidSettingsStore.PREFS_NAME)
                if (closed.get() || epoch.get() != expectedEpoch) return@enqueue

                detachRemote()
                remote = preferences
                check(AndroidSettingsStore(local).ensureHookHeartbeatToken() != null) {
                    "本地心跳令牌初始化失败"
                }
                check(RemoteSettingsSync.pushHookConfiguration(local, preferences)) {
                    "LSPosed Remote Preferences 拒绝初始配置"
                }
                reportIfCurrent(expectedEpoch, true, "已同步 LSPosed 远程配置")
            } catch (t: Throwable) {
                if (epoch.get() == expectedEpoch) detachRemote()
                reportIfCurrent(expectedEpoch, false, failureMessage(t))
            }
        }
    }

    fun unbind() {
        val expectedEpoch = epoch.incrementAndGet()
        enqueue {
            if (epoch.get() != expectedEpoch) return@enqueue
            detachRemote()
            reportIfCurrent(expectedEpoch, false, "LSPosed 服务已断开")
        }
    }

    private fun reportIfCurrent(expectedEpoch: Long, ready: Boolean, message: String) {
        if (!closed.get() && epoch.get() == expectedEpoch) onStateChanged(ready, message)
    }

    private fun detachRemote() {
        remote = null
    }

    private fun enqueue(block: () -> Unit) {
        if (closed.get()) return
        try {
            executor.execute(block)
        } catch (_: RejectedExecutionException) {
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        epoch.incrementAndGet()
        local.unregisterOnSharedPreferenceChangeListener(localListener)
        detachRemote()
        executor.shutdownNow()
    }

    private fun failureMessage(t: Throwable): String {
        val detail = t.message?.take(160).orEmpty()
        return if (detail.isBlank()) {
            "LSPosed 远程配置同步失败：${t.javaClass.simpleName}"
        } else {
            "LSPosed 远程配置同步失败：$detail"
        }
    }
}

/** 可独立单测的同步策略；远程偏好只允许模块向 Hook 发布只读配置。 */
internal object RemoteSettingsSync {
    private const val SERVICE_PREFIX = "service.enabled."
    private const val ROUTE_SNAPSHOT_KEY = "route.snapshot.json"
    private const val ROUTE_GENERATION_KEY = "route.snapshot.generation"
    private const val HEARTBEAT_TOKEN_KEY = "hook.heartbeat.token"
    private const val HEARTBEAT_PREFIX = "hook.heartbeat.package."

    fun isHookConfigurationKey(key: String): Boolean =
        key.startsWith(SERVICE_PREFIX) || key == ROUTE_SNAPSHOT_KEY
            || key == ROUTE_GENERATION_KEY || key == HEARTBEAT_TOKEN_KEY

    fun isHookHeartbeatKey(key: String): Boolean = key.startsWith(HEARTBEAT_PREFIX)

    fun pushHookConfiguration(local: SharedPreferences, remote: SharedPreferences): Boolean {
        val source = local.all.filterKeys(::isHookConfigurationKey)
        val editor = remote.edit()
        remote.all.keys.asSequence()
            .filter { key ->
                isHookHeartbeatKey(key) || !isHookConfigurationKey(key) || !source.containsKey(key)
            }
            .forEach(editor::remove)
        source.forEach { (key, value) -> putValue(editor, key, value) }
        return editor.commit()
    }

    private fun putValue(editor: SharedPreferences.Editor, key: String, value: Any?) {
        when (value) {
            is String -> editor.putString(key, value)
            is Boolean -> editor.putBoolean(key, value)
            is Int -> editor.putInt(key, value)
            is Long -> editor.putLong(key, value)
            is Float -> editor.putFloat(key, value)
            is Set<*> -> {
                if (value.all { it is String }) {
                    editor.putStringSet(key, value.filterIsInstance<String>().toSet())
                } else {
                    editor.remove(key)
                }
            }
            else -> editor.remove(key)
        }
    }
}

package org.xiyu.githubdirect.data

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.SystemClock
import org.xiyu.githubdirect.core.data.HookHeartbeat
import java.util.concurrent.ConcurrentHashMap

/** Hook 目标进程到模块应用的单向、write-only 心跳通道。 */
object HookHeartbeatIpc {
    const val AUTHORITY = "org.xiyu.githubdirect.hookstatus"
    const val METHOD_RECORD = "record"
    const val KEY_ACCEPTED = "accepted"
    private val URI = Uri.parse("content://$AUTHORITY")

    @JvmStatic
    fun report(context: Context, heartbeat: HookHeartbeat): Boolean {
        val extras = Bundle().apply {
            putString(KEY_PACKAGE, heartbeat.packageName)
            putString(KEY_PROCESS, heartbeat.processName)
            putLong(KEY_GENERATION, heartbeat.routeGeneration)
            putString(KEY_FRAMEWORK, heartbeat.framework)
            putInt(KEY_API, heartbeat.apiVersion)
            putLong(KEY_HITS, heartbeat.hitCount)
            putString(KEY_TOKEN, heartbeat.token)
        }
        return try {
            context.contentResolver.call(URI, METHOD_RECORD, null, extras)
                ?.getBoolean(KEY_ACCEPTED, false) == true
        } catch (_: Throwable) {
            false
        }
    }

    internal const val KEY_PACKAGE = "package"
    internal const val KEY_PROCESS = "process"
    internal const val KEY_GENERATION = "generation"
    internal const val KEY_FRAMEWORK = "framework"
    internal const val KEY_API = "api"
    internal const val KEY_HITS = "hits"
    internal const val KEY_TOKEN = "token"
}

class HookHeartbeatProvider : ContentProvider() {
    private val lastAcceptedAt = ConcurrentHashMap<String, Long>()

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        if (method != HookHeartbeatIpc.METHOD_RECORD || extras == null) return result(false)
        val appContext = context?.applicationContext ?: context ?: return result(false)
        val callingUid = Binder.getCallingUid()
        val callerPackages = appContext.packageManager.getPackagesForUid(callingUid)
            ?.toSet().orEmpty()
        val payload = HookHeartbeatIngress.Payload(
            packageName = extras.getString(HookHeartbeatIpc.KEY_PACKAGE).orEmpty(),
            processName = extras.getString(HookHeartbeatIpc.KEY_PROCESS).orEmpty(),
            routeGeneration = extras.getLong(HookHeartbeatIpc.KEY_GENERATION, -1L),
            framework = extras.getString(HookHeartbeatIpc.KEY_FRAMEWORK).orEmpty(),
            apiVersion = extras.getInt(HookHeartbeatIpc.KEY_API, -1),
            hitCount = extras.getLong(HookHeartbeatIpc.KEY_HITS, -1L),
            token = extras.getString(HookHeartbeatIpc.KEY_TOKEN).orEmpty(),
        )
        val settings = AndroidSettingsStore(appContext)
        val heartbeat = HookHeartbeatIngress.accept(
            payload = payload,
            callerPackages = callerPackages,
            expectedToken = settings.ensureHookHeartbeatToken(),
            acceptedAt = System.currentTimeMillis(),
        ) ?: return result(false)

        val rateKey = "$callingUid:${heartbeat.processName}"
        val nowElapsed = SystemClock.elapsedRealtime()
        val previous = lastAcceptedAt.put(rateKey, nowElapsed)
        if (previous != null && nowElapsed - previous < MIN_INTERVAL_MS) return result(false)
        return try {
            settings.recordHookHeartbeat(heartbeat)
            result(true)
        } catch (_: Throwable) {
            result(false)
        }
    }

    private fun result(accepted: Boolean) = Bundle().apply {
        putBoolean(HookHeartbeatIpc.KEY_ACCEPTED, accepted)
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    private companion object {
        const val MIN_INTERVAL_MS = 1_000L
    }
}

package org.xiyu.githubdirect.root

import android.content.Context
import android.os.Build
import android.os.Process
import android.os.SystemClock

/**
 * ColorOS/OxygenOS/realme UI 的 HANS 会在部分版本中冻结仍持有前台服务的第三方进程。
 *
 * 厂商 API 要求签名级 com.oplus.permission.safe.POWER，普通应用即使有 su 也不能直接获得。
 * 因此只在 Oplus 系 ROM 上启动一个 UID 0 的最小 app_process Binder 租约守护器：守护器
 * 绑定当前应用 PID，应用退出或守护器死亡时 system_server 通过 Binder death 自动撤销豁免。
 * 非 Oplus 系设备完全不触发；任何失败都只返回可见降级，不改变标准 Android 生命周期。
 */
internal class OemFreezeLease(
    private val shell: RootShell = RootShell(),
) {

    data class Status(
        val required: Boolean,
        val active: Boolean,
        val detail: String = "",
    )

    private val lock = Any()
    private var current = Status(required = false, active = false)
    private var uid = 0
    private var lastHealthCheckAt = 0L

    fun status(): Status = synchronized(lock) { current }

    fun acquire(context: Context): Status = synchronized(lock) {
        val required = isOplusFamily(Build.MANUFACTURER, Build.BRAND)
        if (!required) {
            current = Status(required = false, active = false)
            return@synchronized current
        }

        val app = context.applicationContext
        val appUid = app.applicationInfo.uid
        val appPid = Process.myPid()
        val now = SystemClock.elapsedRealtime()
        if (current.active && now - lastHealthCheckAt < HEALTH_CHECK_INTERVAL_MS) {
            return@synchronized current
        }
        if (!current.active && lastHealthCheckAt > 0L &&
            now - lastHealthCheckAt < FAILURE_RETRY_INTERVAL_MS
        ) {
            return@synchronized current
        }
        lastHealthCheckAt = now
        if (current.active && appUid > 0 && leaseHealthy(appUid, appPid)) {
            return@synchronized current
        }
        if (current.active) {
            current = Status(true, false, "Oplus HANS 助手已失联，正在重建 Binder 租约")
        }

        val appProcessDex = runCatching { RootAppProcessDex.from(app) }.getOrNull()
        if (appUid <= 0 || appPid <= 0 || appProcessDex == null) {
            current = Status(true, false, "Oplus HANS 租约参数非法")
            return@synchronized current
        }
        uid = appUid
        val paths = paths(appUid)
        val script = """
            set -e
            ${appProcessDex.prepareScript()}
            oldpid=${'$'}(cat ${paths.pid} 2>/dev/null || true)
            if [ -n "${'$'}oldpid" ] && kill -0 "${'$'}oldpid" 2>/dev/null; then
              oldcmd=${'$'}(tr '\000' ' ' < /proc/${'$'}oldpid/cmdline 2>/dev/null || true)
              case "${'$'}oldcmd" in
                *$HELPER_CLASS*)
                  if [ "${'$'}(cat ${paths.status} 2>/dev/null)" = "active:$appPid" ]; then
                    exit 0
                  fi
                  touch ${paths.stop}
                  kill "${'$'}oldpid" 2>/dev/null || true
                  ;;
                *) rm -f ${paths.pid} ${paths.status} ${paths.stop} ;;
              esac
            fi
            waited=0
            while [ -n "${'$'}oldpid" ] && kill -0 "${'$'}oldpid" 2>/dev/null && [ "${'$'}waited" -lt 5 ]
            do
              sleep 1
              waited=${'$'}((waited+1))
            done
            rm -f ${paths.pid} ${paths.status} ${paths.stop}
            nohup setsid -d env CLASSPATH="${'$'}GHD_CLASSPATH" /system/bin/app_process /system/bin \
              $HELPER_CLASS $appUid $APPLICATION_ID $appPid \
              ${paths.pid} ${paths.status} ${paths.stop} >/dev/null 2>&1 &
            waited=0
            while [ "${'$'}waited" -lt 8 ]
            do
              helper_pid=${'$'}(cat ${paths.pid} 2>/dev/null || true)
              helper_status=${'$'}(cat ${paths.status} 2>/dev/null || true)
              if [ "${'$'}helper_status" = "active:$appPid" ] && [ -n "${'$'}helper_pid" ] && \
                 kill -0 "${'$'}helper_pid" 2>/dev/null; then
                chmod 600 ${paths.pid} ${paths.status} 2>/dev/null || true
                exit 0
              fi
              case "${'$'}helper_status" in error:*) echo "${'$'}helper_status" >&2; exit 1 ;; esac
              sleep 1
              waited=${'$'}((waited+1))
            done
            exit 1
        """.trimIndent()
        current = try {
            val result = shell.execTrustedScript(script, timeoutSec = 16)
            if (result.ok) {
                Status(true, true, "Oplus HANS Root Binder 租约已生效")
            } else {
                Status(true, false, "Oplus HANS Root 租约失败：${result.diagnosticSummary(220)}")
            }
        } catch (t: Throwable) {
            Status(true, false, "Oplus HANS Root 租约失败：${failureText(t)}")
        }
        current
    }

    private fun leaseHealthy(appUid: Int, appPid: Int): Boolean {
        val paths = paths(appUid)
        val script = """
            pid=${'$'}(cat ${paths.pid} 2>/dev/null || true)
            [ -n "${'$'}pid" ] || exit 1
            [ "${'$'}(cat ${paths.status} 2>/dev/null || true)" = "active:$appPid" ] || exit 1
            kill -0 "${'$'}pid" 2>/dev/null || exit 1
            cmd=${'$'}(tr '\000' ' ' < /proc/${'$'}pid/cmdline 2>/dev/null || true)
            case "${'$'}cmd" in *$HELPER_CLASS*) exit 0 ;; *) exit 1 ;; esac
        """.trimIndent()
        return runCatching { shell.execTrustedScript(script, timeoutSec = 4).ok }
            .getOrDefault(false)
    }

    fun release(context: Context) = synchronized(lock) {
        val appUid = uid.takeIf { it > 0 } ?: context.applicationInfo.uid
        if (appUid > 0) {
            val paths = paths(appUid)
            val script = """
                pid=${'$'}(cat ${paths.pid} 2>/dev/null || true)
                touch ${paths.stop}
                if [ -n "${'$'}pid" ] && kill -0 "${'$'}pid" 2>/dev/null; then
                  cmd=${'$'}(tr '\000' ' ' < /proc/${'$'}pid/cmdline 2>/dev/null || true)
                  case "${'$'}cmd" in *$HELPER_CLASS*) kill "${'$'}pid" 2>/dev/null || true ;; esac
                fi
                rm -f ${paths.pid} ${paths.status} ${paths.stop}
            """.trimIndent()
            runCatching { shell.execTrustedScript(script, timeoutSec = 6) }
        }
        uid = 0
        lastHealthCheckAt = 0L
        current = Status(required = isOplusFamily(Build.MANUFACTURER, Build.BRAND), active = false)
    }

    private data class Paths(val pid: String, val status: String, val stop: String)

    private fun paths(appUid: Int): Paths {
        val suffix = appUid.coerceAtLeast(1)
        return Paths(
            pid = "/data/local/tmp/ghd_hans_$suffix.pid",
            status = "/data/local/tmp/ghd_hans_$suffix.status",
            stop = "/data/local/tmp/ghd_hans_$suffix.stop",
        )
    }

    companion object {
        private const val APPLICATION_ID = "org.xiyu.githubdirect"
        private const val HELPER_CLASS = "org.xiyu.githubdirect.root.OplusHansRootLease"
        private const val HEALTH_CHECK_INTERVAL_MS = 15_000L
        private const val FAILURE_RETRY_INTERVAL_MS = 30_000L

        internal fun isOplusFamily(manufacturer: String?, brand: String?): Boolean =
            sequenceOf(manufacturer, brand)
                .filterNotNull()
                .map { it.trim().lowercase() }
                .any { it == "oppo" || it == "oplus" || it == "oneplus" || it == "realme" }

        private fun failureText(t: Throwable): String {
            var root = t
            repeat(4) { root = root.cause ?: return@repeat }
            return "${root.javaClass.simpleName}: ${root.message.orEmpty()}".trim().take(220)
        }
    }
}

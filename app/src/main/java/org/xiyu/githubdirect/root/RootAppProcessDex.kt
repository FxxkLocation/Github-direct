package org.xiyu.githubdirect.root

import android.content.Context

/**
 * Prepares a root-owned, ordered multi-dex class path for short-lived app_process helpers.
 *
 * app_process does not run Application/MultiDex initialization, so pointing CLASSPATH at an APK
 * only exposes classes.dex on this device. The installed, PackageManager-controlled APK is
 * extracted into a root-owned cache and every classesN.dex is supplied explicitly.
 */
internal class RootAppProcessDex private constructor(
    private val apkPath: String,
    private val appUid: Int,
) {
    val cacheDir: String = cacheDir(appUid)

    fun prepareScript(): String = renderPrepareScript(apkPath, appUid)

    fun foregroundInvocation(mainClass: String, args: List<String>): String {
        require(SAFE_HELPER_CLASSES.contains(mainClass)) { "unsupported app_process helper" }
        args.forEach { require(SAFE_ARGUMENT.matches(it)) { "unsafe app_process argument" } }
        return buildString {
            appendLine(prepareScript())
            append("exec env CLASSPATH=\"\$GHD_CLASSPATH\" /system/bin/app_process /system/bin ")
            append(mainClass)
            args.forEach { append(' ').append(it) }
        }
    }

    companion object {
        private const val APPLICATION_ID = "org.xiyu.githubdirect"
        private val SAFE_APK_PATH = Regex(
            "^/data/app/[A-Za-z0-9_+=~.-]+/$APPLICATION_ID-[A-Za-z0-9_+=~.-]+/base\\.apk${'$'}",
        )
        private val SAFE_ARGUMENT = Regex("^[A-Za-z0-9_./:=+~-]+${'$'}")
        private val SAFE_HELPER_CLASSES = setOf(
            "org.xiyu.githubdirect.root.AndroidKeyChainRootHelper",
            "org.xiyu.githubdirect.root.BrowserPolicyRootHelper",
            "org.xiyu.githubdirect.root.OplusHansRootLease",
        )

        fun from(context: Context): RootAppProcessDex {
            val app = context.applicationContext
            val source = app.applicationInfo.sourceDir.orEmpty()
            val uid = app.applicationInfo.uid
            require(isSafeApkPath(source)) { "unsafe installed APK path" }
            require(uid in 10_000..999_999) { "unsafe application UID" }
            return RootAppProcessDex(source, uid)
        }

        internal fun isSafeApkPath(path: String): Boolean = SAFE_APK_PATH.matches(path)

        internal fun cacheDir(uid: Int): String {
            require(uid in 10_000..999_999)
            return "/data/local/tmp/ghd_app_process_$uid"
        }

        internal fun renderPrepareScript(apkPath: String, uid: Int): String {
            require(isSafeApkPath(apkPath))
            val cache = cacheDir(uid)
            return """
                GHD_APK='$apkPath'
                GHD_CACHE='$cache'
                GHD_STAGE='$cache.new'
                GHD_OLD='$cache.old'
                GHD_LOCK='$cache.lock'
                [ "${'$'}(id -u)" = "0" ] || exit 71
                [ -f "${'$'}GHD_APK" ] && [ ! -L "${'$'}GHD_APK" ] || exit 72
                GHD_LOCK_WAIT=0
                while ! mkdir "${'$'}GHD_LOCK" 2>/dev/null; do
                  GHD_LOCK_PID=${'$'}(cat "${'$'}GHD_LOCK/pid" 2>/dev/null || true)
                  if [ -n "${'$'}GHD_LOCK_PID" ] && ! kill -0 "${'$'}GHD_LOCK_PID" 2>/dev/null; then
                    rm -rf "${'$'}GHD_LOCK"
                    continue
                  fi
                  if [ -z "${'$'}GHD_LOCK_PID" ] && [ "${'$'}GHD_LOCK_WAIT" -ge 2 ]; then
                    rm -rf "${'$'}GHD_LOCK"
                    continue
                  fi
                  [ "${'$'}GHD_LOCK_WAIT" -lt 20 ] || exit 78
                  sleep 1
                  GHD_LOCK_WAIT=${'$'}((GHD_LOCK_WAIT+1))
                done
                printf '%s\n' "${'$'}${'$'}" > "${'$'}GHD_LOCK/pid"
                chmod 0700 "${'$'}GHD_LOCK"
                chmod 0600 "${'$'}GHD_LOCK/pid"
                GHD_APK_SIZE=${'$'}(stat -c %s "${'$'}GHD_APK")
                GHD_APK_MTIME=${'$'}(stat -c %Y "${'$'}GHD_APK")
                GHD_APK_KEY="${'$'}GHD_APK|${'$'}GHD_APK_SIZE|${'$'}GHD_APK_MTIME"
                GHD_REBUILD=1
                if [ -d "${'$'}GHD_CACHE" ] && [ ! -L "${'$'}GHD_CACHE" ] && \
                   [ "${'$'}(cat "${'$'}GHD_CACHE/apk.meta" 2>/dev/null || true)" = "${'$'}GHD_APK_KEY" ] && \
                   [ -f "${'$'}GHD_CACHE/classes.dex" ] && [ ! -L "${'$'}GHD_CACHE/classes.dex" ]; then
                  GHD_REBUILD=0
                fi
                if [ "${'$'}GHD_REBUILD" = "1" ]; then
                  rm -rf "${'$'}GHD_STAGE" "${'$'}GHD_OLD"
                  mkdir -p "${'$'}GHD_STAGE"
                  if command -v unzip >/dev/null 2>&1; then
                    unzip -oq "${'$'}GHD_APK" 'classes*.dex' -d "${'$'}GHD_STAGE"
                  elif [ -x /data/adb/magisk/busybox ]; then
                    /data/adb/magisk/busybox unzip -oq "${'$'}GHD_APK" 'classes*.dex' -d "${'$'}GHD_STAGE"
                  elif [ -x /data/adb/ksu/bin/busybox ]; then
                    /data/adb/ksu/bin/busybox unzip -oq "${'$'}GHD_APK" 'classes*.dex' -d "${'$'}GHD_STAGE"
                  else
                    exit 73
                  fi
                  GHD_DEX_COUNT=${'$'}(find "${'$'}GHD_STAGE" -maxdepth 1 -type f -name 'classes*.dex' | wc -l)
                  [ "${'$'}GHD_DEX_COUNT" -ge 1 ] && [ "${'$'}GHD_DEX_COUNT" -le 99 ] || exit 74
                  GHD_I=1
                  while [ "${'$'}GHD_I" -le "${'$'}GHD_DEX_COUNT" ]; do
                    if [ "${'$'}GHD_I" = "1" ]; then
                      GHD_DEX="${'$'}GHD_STAGE/classes.dex"
                    else
                      GHD_DEX="${'$'}GHD_STAGE/classes${'$'}GHD_I.dex"
                    fi
                    [ -f "${'$'}GHD_DEX" ] && [ ! -L "${'$'}GHD_DEX" ] || exit 75
                    GHD_I=${'$'}((GHD_I+1))
                  done
                  printf '%s\n' "${'$'}GHD_APK_KEY" > "${'$'}GHD_STAGE/apk.meta"
                  chown -R 0:0 "${'$'}GHD_STAGE"
                  chmod 0755 "${'$'}GHD_STAGE"
                  chmod 0644 "${'$'}GHD_STAGE"/classes*.dex "${'$'}GHD_STAGE/apk.meta"
                  if [ -e "${'$'}GHD_CACHE" ]; then mv "${'$'}GHD_CACHE" "${'$'}GHD_OLD"; fi
                  mv "${'$'}GHD_STAGE" "${'$'}GHD_CACHE"
                  rm -rf "${'$'}GHD_OLD"
                fi
                rm -rf "${'$'}GHD_LOCK"
                GHD_DEX_COUNT=${'$'}(find "${'$'}GHD_CACHE" -maxdepth 1 -type f -name 'classes*.dex' | wc -l)
                [ "${'$'}GHD_DEX_COUNT" -ge 1 ] && [ "${'$'}GHD_DEX_COUNT" -le 99 ] || exit 76
                GHD_CLASSPATH=""
                GHD_I=1
                while [ "${'$'}GHD_I" -le "${'$'}GHD_DEX_COUNT" ]; do
                  if [ "${'$'}GHD_I" = "1" ]; then
                    GHD_DEX="${'$'}GHD_CACHE/classes.dex"
                  else
                    GHD_DEX="${'$'}GHD_CACHE/classes${'$'}GHD_I.dex"
                  fi
                  [ -f "${'$'}GHD_DEX" ] && [ ! -L "${'$'}GHD_DEX" ] || exit 77
                  if [ -z "${'$'}GHD_CLASSPATH" ]; then
                    GHD_CLASSPATH="${'$'}GHD_DEX"
                  else
                    GHD_CLASSPATH="${'$'}GHD_CLASSPATH:${'$'}GHD_DEX"
                  fi
                  GHD_I=${'$'}((GHD_I+1))
                done
            """.trimIndent()
        }
    }
}

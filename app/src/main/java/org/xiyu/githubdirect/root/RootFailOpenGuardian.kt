package org.xiyu.githubdirect.root

import java.util.UUID

/**
 * 最小独立 root 守护器；ipset 与内联规则模式均启用。
 *
 * 它只持有固定 UID 对应的 heartbeat/pid/stop 文件和本代明确的 GHD_* 清理命令；应用死亡后
 * heartbeat 停止，守护器在 13 秒阈值 + 2 秒轮询内移除自有链。清理后仅当包未被
 * force-stop、用户配置仍启用且没有新服务/守护器时，才限频请求一次 RESTORE。
 * 不会使用通配符，也不会触碰其他应用的防火墙规则。
 */
internal class RootFailOpenGuardian(
    private val shell: RootShell,
    appUid: Int,
    private val ownerToken: String = newOwnerToken(),
) {
    init {
        require(SAFE_OWNER_TOKEN.matches(ownerToken)) { "guardian owner token 非法" }
    }

    @Volatile
    var lastFailureDetail: String = ""
        private set

    private val suffix = appUid.coerceAtLeast(1).toString()
    private val heartbeatPath = "/data/local/tmp/ghd_guard_$suffix.hb"
    private val stopPath = "/data/local/tmp/ghd_guard_$suffix.stop"
    private val pidPath = "/data/local/tmp/ghd_guard_$suffix.pid"
    private val ownerPath = "/data/local/tmp/ghd_guard_$suffix.owner"
    private val restartPath = "/data/local/tmp/ghd_guard_$suffix.restart"
    private val recoveryPath = "/data/local/tmp/ghd_guard_$suffix.recovery"
    private val userId = appUid.coerceAtLeast(1) / ANDROID_UIDS_PER_USER
    private val settingsPath =
        "/data/user/$userId/$APPLICATION_ID/shared_prefs/$SETTINGS_FILE"

    fun start(cleanupCommands: List<String>): Boolean {
        lastFailureDetail = ""
        if (cleanupCommands.isEmpty() || cleanupCommands.any { !SAFE_CLEANUP.matches(it) }) {
            lastFailureDetail = "guardian 清理命令未通过内部白名单"
            return false
        }
        val cleanup = cleanupCommands.joinToString("\n")
        val child = """
            owns() {
              [ "${'$'}(cat $ownerPath 2>/dev/null)" = "$ownerToken" ]
            }
            service_alive() {
              service_state=${'$'}(dumpsys activity services $SERVICE_COMPONENT 2>/dev/null)
              case "${'$'}service_state" in *"ServiceRecord{"*) ;; *) return 1 ;; esac
              case "${'$'}service_state" in *"app=ProcessRecord{"*) ;; *) return 1 ;; esac
              case "${'$'}service_state" in *"isForeground=true"*) return 0 ;; *) return 1 ;; esac
            }
            guardian_pid_alive() {
              candidate=${'$'}1
              case "${'$'}candidate" in ""|*[!0-9]*) return 1 ;; esac
              kill -0 "${'$'}candidate" 2>/dev/null || return 1
              grep -F "$ownerPath" "/proc/${'$'}candidate/cmdline" >/dev/null 2>&1
            }
            owns || exit 0
            echo ${'$'}${'$'} > $pidPath
            while true
            do
              sleep $POLL_SECONDS
              owns || exit 0
              if [ -e $stopPath ]; then
                if owns; then
                  rm -f $heartbeatPath $pidPath $stopPath $ownerPath
                fi
                exit 0
              fi
              last=${'$'}(cat $heartbeatPath 2>/dev/null || echo 0)
              read uptime rest < /proc/uptime || uptime=0
              now=${'$'}{uptime%%.*}
              age=${'$'}((now-last))
              if [ "${'$'}age" -ge $RECOVERY_SECONDS ] && [ "${'$'}age" -lt $STALE_SECONDS ]; then
                recovered_for=${'$'}(cat $recoveryPath 2>/dev/null || echo -1)
                if [ "${'$'}recovered_for" != "${'$'}last" ] && service_alive; then
                  echo "${'$'}last" > $recoveryPath
                  am start-foreground-service --user $userId -a $RESTORE_ACTION \
                    -n $SERVICE_COMPONENT >/dev/null 2>&1 || true
                fi
              fi
              if [ "${'$'}age" -lt 0 ] || [ "${'$'}age" -ge $STALE_SECONDS ]; then
                break
              fi
            done
            owns || exit 0
            $cleanup
            if owns; then
              rm -f $heartbeatPath $pidPath $stopPath $ownerPath $recoveryPath
            else
              exit 0
            fi

            # START_STICKY 在部分 OEM 上会丢失 ServiceRecord。先保持 fail-open，再受控恢复：
            # force-stop 和用户主动禁用都必须尊重；解析不出状态时也禁止拉起。
            restart_allowed() {
              user_state=${'$'}(dumpsys package $APPLICATION_ID 2>/dev/null | grep "User $userId:" | head -n 1)
              case "${'$'}user_state" in
                *"stopped=false"*) ;;
                *) return 1 ;;
              esac
              setting=${'$'}(grep "name=\"root.service.enabled\"" $settingsPath 2>/dev/null | head -n 1)
              case "${'$'}setting" in
                *"value=\"true\""*) return 0 ;;
                *) return 1 ;;
              esac
            }

            restart_allowed || exit 0
            last_restart=${'$'}(cat $restartPath 2>/dev/null || echo 0)
            case "${'$'}last_restart" in
              ""|*[!0-9]*) last_restart=0 ;;
            esac
            read uptime rest < /proc/uptime || exit 0
            now=${'$'}{uptime%%.*}
            age=${'$'}((now-last_restart))
            if [ "${'$'}age" -ge 0 ] && [ "${'$'}age" -lt $RESTART_MIN_INTERVAL_SECONDS ]; then
              sleep ${'$'}(($RESTART_MIN_INTERVAL_SECONDS-age))
            fi

            # 等待期间 Android 或用户可能已经恢复/停止了服务，因此必须重新检查。
            next_guardian_pid=${'$'}(cat $pidPath 2>/dev/null || echo 0)
            if guardian_pid_alive "${'$'}next_guardian_pid"; then
              exit 0
            fi
            dumpsys activity services $SERVICE_COMPONENT 2>/dev/null |
              grep "ServiceRecord{" >/dev/null && exit 0
            restart_allowed || exit 0
            read uptime rest < /proc/uptime || exit 0
            echo ${'$'}{uptime%%.*} > $restartPath
            am start-foreground-service --user $userId -n $SERVICE_COMPONENT >/dev/null 2>&1 || true
        """.trimIndent()
        val launch = """
            set -e
            guardian_pid_alive() {
              candidate=${'$'}1
              case "${'$'}candidate" in ""|*[!0-9]*) return 1 ;; esac
              kill -0 "${'$'}candidate" 2>/dev/null || return 1
              grep -F "$ownerPath" "/proc/${'$'}candidate/cmdline" >/dev/null 2>&1
            }
            oldpid=${'$'}(cat $pidPath 2>/dev/null || true)
            echo $ownerToken > $ownerPath
            touch $stopPath
            waited=0
            if guardian_pid_alive "${'$'}oldpid"; then
              while guardian_pid_alive "${'$'}oldpid" && [ "${'$'}waited" -lt $OLD_GUARDIAN_WAIT_SECONDS ]
              do
                sleep 1
                waited=${'$'}((waited+1))
              done
              if guardian_pid_alive "${'$'}oldpid"; then
                exit 1
              fi
            else
              sleep ${POLL_SECONDS + 1}
            fi
            test "${'$'}(cat $ownerPath 2>/dev/null)" = "$ownerToken"
            rm -f $stopPath $pidPath $heartbeatPath $recoveryPath
            read uptime rest < /proc/uptime
            echo ${'$'}{uptime%%.*} > $heartbeatPath
            nohup sh -c '$child' >/dev/null 2>&1 &
            sleep 1
            test "${'$'}(cat $ownerPath 2>/dev/null)" = "$ownerToken"
            test -s $pidPath
        """.trimIndent()
        return try {
            val result = shell.execTrustedScript(launch, timeoutSec = OLD_GUARDIAN_WAIT_SECONDS + 10)
            if (!result.ok) lastFailureDetail = result.diagnosticSummary()
            result.ok
        } catch (t: Throwable) {
            lastFailureDetail = "${t.javaClass.simpleName}: ${t.message.orEmpty()}".trim().take(512)
            false
        }
    }

    fun heartbeat(): Boolean {
        lastFailureDetail = ""
        val script = """
            set -e
            guardian_pid_alive() {
              candidate=${'$'}1
              case "${'$'}candidate" in ""|*[!0-9]*) return 1 ;; esac
              kill -0 "${'$'}candidate" 2>/dev/null || return 1
              grep -F "$ownerPath" "/proc/${'$'}candidate/cmdline" >/dev/null 2>&1
            }
            test "${'$'}(cat $ownerPath 2>/dev/null)" = "$ownerToken"
            test -s $pidPath
            guardian_pid_alive "${'$'}(cat $pidPath)"
            read uptime rest < /proc/uptime
            test "${'$'}(cat $ownerPath 2>/dev/null)" = "$ownerToken"
            echo ${'$'}{uptime%%.*} > $heartbeatPath
        """.trimIndent()
        return try {
            val result = shell.execTrustedScript(script, timeoutSec = 5)
            if (!result.ok) lastFailureDetail = result.diagnosticSummary()
            result.ok
        } catch (t: Throwable) {
            lastFailureDetail = "${t.javaClass.simpleName}: ${t.message.orEmpty()}".trim().take(512)
            false
        }
    }

    fun stopGracefully() {
        val script = """
            if [ "${'$'}(cat $ownerPath 2>/dev/null)" = "$ownerToken" ]; then
              touch $stopPath
              rm -f $heartbeatPath
            fi
        """.trimIndent()
        try {
            shell.execTrustedScript(script, timeoutSec = 5)
        } catch (_: Throwable) {
        }
    }

    companion object {
        private const val POLL_SECONDS = 2
        private const val STALE_SECONDS = 13
        private const val RECOVERY_SECONDS = 8
        private const val OLD_GUARDIAN_WAIT_SECONDS = 15
        private const val RESTART_MIN_INTERVAL_SECONDS = 60
        private const val ANDROID_UIDS_PER_USER = 100_000
        private const val APPLICATION_ID = "org.xiyu.githubdirect"
        private const val SERVICE_COMPONENT =
            "org.xiyu.githubdirect/org.xiyu.githubdirect.root.RootRelayService"
        private const val RESTORE_ACTION = "org.xiyu.githubdirect.action.ROOT_RESTORE"
        private const val SETTINGS_FILE = "direct_settings.xml"
        private val SAFE_OWNER_TOKEN = Regex("^[a-f0-9]{32}$")
        private val SAFE_CLEANUP = Regex(
            "^(?:ip6?tables -t (?:nat|filter) -(?:D OUTPUT -j|F|X) GHD_[A-Za-z0-9_]+|" +
                "ipset destroy GHD_[A-Za-z0-9_]+|" +
                "ip -6 rule del priority 105(?:[0-2][0-9]|3[01]) table 52[0-9]{3}|" +
                "ip -6 route flush table 52[0-9]{3})$",
        )

        private fun newOwnerToken(): String = UUID.randomUUID().toString().replace("-", "")
    }
}

package org.xiyu.githubdirect.root

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.xiyu.githubdirect.core.rules.BackendMode
import org.xiyu.githubdirect.data.AndroidSettingsStore

/** 开机只恢复用户同时启用了 Root 服务和“开机自启”的状态。 */
class RootBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val settings = AndroidSettingsStore(context)
        if (!settings.isRootServiceEnabled() || !settings.isRootAutoStartEnabled()) return
        val mode = settings.backendMode().let {
            if (it == BackendMode.VPN) BackendMode.XPOSED_ONLY else it
        }
        RootRelayService.requestStart(context, mode)
    }
}

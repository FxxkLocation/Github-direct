package org.xiyu.githubdirect

import android.app.Application
import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper
import org.xiyu.githubdirect.data.LegacyMigration
import java.util.concurrent.CopyOnWriteArraySet

class App : Application(), XposedServiceHelper.OnServiceListener {

    interface ServiceStateListener {
        fun onServiceBind(service: XposedService)
        fun onServiceDied(service: XposedService)
    }

    @Volatile
    var service: XposedService? = null
        private set

    private val listeners = CopyOnWriteArraySet<ServiceStateListener>()

    override fun onCreate() {
        super.onCreate()
        // 旧版 hosts 数据迁移（github_hosts → direct_settings；失败静默）
        LegacyMigration.run(this)
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
        for (listener in listeners) {
            listener.onServiceBind(service)
        }
    }

    override fun onServiceDied(service: XposedService) {
        this.service = null
        for (listener in listeners) {
            listener.onServiceDied(service)
        }
    }
}

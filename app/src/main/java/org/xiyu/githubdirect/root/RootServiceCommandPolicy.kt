package org.xiyu.githubdirect.root

/**
 * RootRelayService 命令的纯策略层。
 *
 * 与 Android Service 分离后，可在 JVM 中验证 null-intent 恢复、一次性命令和停止语义，
 * 避免前台服务因为 REFRESH/REPROBE 完成或异常后无人 stop 而常驻。
 */
internal enum class RootServiceCommand {
    START,
    STOP,
    REFRESH,
    REPROBE,
    RESTORE,
}

internal object RootServiceCommandPolicy {
    const val ACTION_START = "org.xiyu.githubdirect.action.ROOT_START"
    const val ACTION_STOP = "org.xiyu.githubdirect.action.ROOT_STOP"
    const val ACTION_REFRESH = "org.xiyu.githubdirect.action.ROOT_REFRESH"
    const val ACTION_REPROBE = "org.xiyu.githubdirect.action.ROOT_REPROBE"
    const val ACTION_RESTORE = "org.xiyu.githubdirect.action.ROOT_RESTORE"

    fun classify(action: String?): RootServiceCommand = when (action) {
        ACTION_START -> RootServiceCommand.START
        ACTION_STOP -> RootServiceCommand.STOP
        ACTION_REFRESH -> RootServiceCommand.REFRESH
        ACTION_REPROBE -> RootServiceCommand.REPROBE
        ACTION_RESTORE -> RootServiceCommand.RESTORE
        else -> RootServiceCommand.RESTORE
    }

    fun shouldStopAfterCompletion(command: RootServiceCommand, serviceEnabled: Boolean): Boolean =
        command == RootServiceCommand.STOP ||
            (!serviceEnabled && (command == RootServiceCommand.REFRESH || command == RootServiceCommand.REPROBE))
}

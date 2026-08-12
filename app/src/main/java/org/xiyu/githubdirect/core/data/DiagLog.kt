package org.xiyu.githubdirect.core.data

/**
 * 诊断日志开关（设计 §8.4）。默认关闭 = 零日志开销。
 * 由引擎装配时从 settings.isDiagEnabled() 初始化。
 */
object DiagLog {

    @Volatile
    private var enabled = false

    fun setEnabled(v: Boolean) {
        enabled = v
    }

    fun isEnabled(): Boolean = enabled
}

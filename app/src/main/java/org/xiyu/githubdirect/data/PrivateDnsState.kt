package org.xiyu.githubdirect.data

import android.content.Context
import android.provider.Settings

/**
 * 系统 Private DNS 模式（§35：只读检测 + UI 提示，绝不自动改设置）。
 *
 * Android 设置键：Settings.Global "private_dns_mode"
 * - "off" / null（默认）→ OFF
 * - "opportunistic" → AUTO（机会式，可用即加密，失败回退明文）
 * - "strict" → STRICT（强制 DoT，非加密流量被系统拦截）
 */
enum class PrivateDnsMode { OFF, AUTO, STRICT, UNKNOWN }

object PrivateDnsState {

    /**
     * 读取系统 Private DNS 模式。非系统应用读取 Settings.Global 通常可用；
     * 任何异常（权限/多用户限制等）→ UNKNOWN，UI 不显示误导性提示。
     */
    fun detect(context: Context): PrivateDnsMode = try {
        when (Settings.Global.getString(context.contentResolver, "private_dns_mode")) {
            "opportunistic" -> PrivateDnsMode.AUTO
            "strict" -> PrivateDnsMode.STRICT
            else -> PrivateDnsMode.OFF // "off" / null / 未知值：Android 默认即为关闭
        }
    } catch (t: Throwable) {
        PrivateDnsMode.UNKNOWN
    }
}

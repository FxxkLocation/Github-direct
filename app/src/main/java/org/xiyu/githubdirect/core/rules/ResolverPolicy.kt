package org.xiyu.githubdirect.core.rules

/**
 * IP 来源策略（与 TransportPolicy 正交）。
 *
 * - DOH            : 仅 DoH 解析 + CIDR 过滤（默认；clean 域与 Xposed 模式主路径）
 * - PROVIDER_FIRST : 先查 provider 表（RelayIpTable，已 TCP 探活验证），miss/失效再 DoH
 * - PROVIDER_ONLY  : 仅 provider 表（固定 IP 直连场景）
 */
enum class ResolverPolicy {
    DOH,
    PROVIDER_FIRST,
    PROVIDER_ONLY;

    companion object {
        fun fromJson(name: String?): ResolverPolicy? = when (name?.uppercase()) {
            "DOH" -> DOH
            "PROVIDER_FIRST" -> PROVIDER_FIRST
            "PROVIDER_ONLY" -> PROVIDER_ONLY
            else -> null
        }
    }
}

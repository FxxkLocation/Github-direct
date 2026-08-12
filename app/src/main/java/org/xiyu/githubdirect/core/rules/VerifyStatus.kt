package org.xiyu.githubdirect.core.rules

/**
 * 服务验证状态：
 * - VERIFIED    : 已验证（github profile；回归基线，默认启用）
 * - NEEDS_VERIFY: 未验证（后续 Agent 填充的平台规则，默认关闭）
 * - BROKEN      : 已确认失效
 */
enum class VerifyStatus {
    VERIFIED,
    NEEDS_VERIFY,
    BROKEN;

    companion object {
        fun fromJson(name: String?): VerifyStatus? = when (name?.uppercase()) {
            "VERIFIED" -> VERIFIED
            "NEEDS_VERIFY" -> NEEDS_VERIFY
            "BROKEN" -> BROKEN
            else -> null
        }
    }
}

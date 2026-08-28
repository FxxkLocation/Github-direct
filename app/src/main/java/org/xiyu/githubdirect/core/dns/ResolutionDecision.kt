package org.xiyu.githubdirect.core.dns

/**
 * DNS Hook 的显式决策，避免用 null/空列表同时表达放行、失败和 NXDOMAIN。
 * 所有地址都必须是已经解析并验证过的字面量；Hook 调用方不得在热路径发起网络访问。
 */
sealed class ResolutionDecision {
    data object Passthrough : ResolutionDecision()
    data object Nxdomain : ResolutionDecision()
    data class Addresses(val addresses: List<String>) : ResolutionDecision() {
        init {
            require(addresses.isNotEmpty()) { "Addresses 不能为空" }
        }
    }
}

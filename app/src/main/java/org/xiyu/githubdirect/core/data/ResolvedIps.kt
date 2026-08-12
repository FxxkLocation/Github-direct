package org.xiyu.githubdirect.core.data

/**
 * 一次解析的完整结果：IPv4 + IPv6 字节数组列表（CIDR 过滤后）。
 * 全部使用 ByteArray 而非 InetAddress，保持 core 纯 JVM 可测。
 */
data class ResolvedIps(
    val v4: List<ByteArray>,
    val v6: List<ByteArray>,
) {
    companion object {
        val EMPTY: ResolvedIps = ResolvedIps(emptyList(), emptyList())
    }
}

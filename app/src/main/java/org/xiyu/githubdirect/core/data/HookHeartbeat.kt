package org.xiyu.githubdirect.core.data

/** LSPosed Hook 的限频运行证明；hitCount=0 表示已初始化但尚无 Java DNS 命中。 */
data class HookHeartbeat(
    val packageName: String,
    val processName: String,
    val timestamp: Long,
    val routeGeneration: Long,
    val framework: String,
    val apiVersion: Int,
    val hitCount: Long,
    val token: String,
)

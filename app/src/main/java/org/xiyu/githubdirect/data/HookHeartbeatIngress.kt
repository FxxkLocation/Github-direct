package org.xiyu.githubdirect.data

import org.xiyu.githubdirect.core.data.HookHeartbeat

/** Exported heartbeat endpoint 的纯数据校验层；Android Binder 包装由 HookHeartbeatProvider 负责。 */
internal object HookHeartbeatIngress {
    private val TOKEN_RE = Regex("^[0-9a-f]{32}$")
    private val PACKAGE_RE = Regex("^[A-Za-z][A-Za-z0-9_.]{0,159}$")
    private const val MAX_PROCESS_CHARS = 160
    private const val MAX_FRAMEWORK_CHARS = 160
    private const val MAX_API_VERSION = 10_000

    data class Payload(
        val packageName: String,
        val processName: String,
        val routeGeneration: Long,
        val framework: String,
        val apiVersion: Int,
        val hitCount: Long,
        val token: String,
    )

    fun accept(
        payload: Payload,
        callerPackages: Set<String>,
        expectedToken: String?,
        acceptedAt: Long,
    ): HookHeartbeat? {
        if (!PACKAGE_RE.matches(payload.packageName)) return null
        if (payload.packageName !in callerPackages) return null
        if (payload.processName.length !in 1..MAX_PROCESS_CHARS) return null
        if (payload.processName != payload.packageName
            && !payload.processName.startsWith("${payload.packageName}:")
        ) return null
        if (payload.framework.length !in 1..MAX_FRAMEWORK_CHARS) return null
        if (payload.apiVersion !in 1..MAX_API_VERSION) return null
        if (payload.routeGeneration < 0L || payload.hitCount < 0L) return null
        if (!TOKEN_RE.matches(payload.token) || payload.token != expectedToken) return null
        if (acceptedAt <= 0L) return null
        return HookHeartbeat(
            packageName = payload.packageName,
            processName = payload.processName,
            timestamp = acceptedAt,
            routeGeneration = payload.routeGeneration,
            framework = payload.framework,
            apiVersion = payload.apiVersion,
            hitCount = payload.hitCount,
            token = payload.token,
        )
    }
}

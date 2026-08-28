package org.xiyu.githubdirect.data

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONObject
import java.security.SecureRandom
import org.xiyu.githubdirect.core.data.HookHeartbeat
import org.xiyu.githubdirect.core.data.Nat64FallbackConfig
import org.xiyu.githubdirect.core.data.ScopeDefaults
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode

/**
 * SettingsStore 的 SharedPreferences 实现（"direct_settings"）。
 *
 * key：service.enabled.{id} / diagnostics.enabled / hosts.{providerId}.data|lastSync /
 * backend.mode / scope.mode / scope.packages
 */
class AndroidSettingsStore(private val prefs: SharedPreferences) : SettingsStore {

    constructor(context: Context) : this(
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    )

    override fun isServiceEnabled(id: String, default: Boolean): Boolean =
        prefs.getBoolean("service.enabled.$id", default)

    override fun setServiceEnabled(id: String, enabled: Boolean) {
        prefs.edit().putBoolean("service.enabled.$id", enabled).apply()
    }

    override fun setServicesEnabled(ids: Collection<String>, enabled: Boolean) {
        if (ids.isEmpty()) return
        val editor = prefs.edit()
        for (id in ids) {
            editor.putBoolean("service.enabled.$id", enabled)
        }
        editor.apply()
    }

    override fun isDiagEnabled(): Boolean = prefs.getBoolean("diagnostics.enabled", false)

    override fun setDiagEnabled(v: Boolean) {
        prefs.edit().putBoolean("diagnostics.enabled", v).apply()
    }

    override fun hostsData(providerId: String): Pair<String, Long>? {
        val data = prefs.getString("hosts.$providerId.data", null) ?: return null
        val lastSync = prefs.getLong("hosts.$providerId.lastSync", 0)
        return data to lastSync
    }

    override fun saveHostsData(providerId: String, data: String, lastSync: Long) {
        prefs.edit()
            .putString("hosts.$providerId.data", data)
            .putLong("hosts.$providerId.lastSync", lastSync)
            .apply()
    }

    // ==================== 后端模式（§15/§40） ====================

    override fun backendMode(): BackendMode =
        BackendMode.values().firstOrNull { it.name == prefs.getString(KEY_BACKEND_MODE, null) }
            ?: BackendMode.AUTO

    override fun setBackendMode(mode: BackendMode) {
        prefs.edit().putString(KEY_BACKEND_MODE, mode.name).apply()
    }

    override fun appScopeMode(): AppScopeMode =
        AppScopeMode.values().firstOrNull { it.name == prefs.getString(KEY_SCOPE_MODE, null) }
            ?: ScopeDefaults.MODE

    override fun setAppScopeMode(mode: AppScopeMode) {
        prefs.edit().putString(KEY_SCOPE_MODE, mode.name).apply()
    }

    override fun scopedPackages(): Set<String> =
        prefs.getStringSet(KEY_SCOPE_PACKAGES, null)?.toSet() ?: ScopeDefaults.PACKAGES.toSet()

    override fun setScopedPackages(packages: Set<String>) {
        prefs.edit().putStringSet(KEY_SCOPE_PACKAGES, packages.toSet()).apply()
    }

    override fun embeddedTlsCapturePackages(): Set<String> =
        prefs.getStringSet(KEY_EMBEDDED_TLS_PACKAGES, null)?.toSet() ?: emptySet()

    override fun setEmbeddedTlsCapturePackages(packages: Set<String>) {
        prefs.edit().putStringSet(KEY_EMBEDDED_TLS_PACKAGES, packages.toSet()).apply()
    }

    override fun isRootServiceEnabled(): Boolean =
        prefs.getBoolean(KEY_ROOT_SERVICE_ENABLED, false)

    override fun setRootServiceEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ROOT_SERVICE_ENABLED, enabled).apply()
    }

    override fun isRootAutoStartEnabled(): Boolean =
        prefs.getBoolean(KEY_ROOT_AUTOSTART, false)

    override fun setRootAutoStartEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ROOT_AUTOSTART, enabled).apply()
    }

    override fun isAdaptiveCandidatesEnabled(): Boolean =
        prefs.getBoolean(KEY_ADAPTIVE_CANDIDATES, true)

    override fun setAdaptiveCandidatesEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ADAPTIVE_CANDIDATES, enabled).apply()
    }

    override fun isRealIpRedirectEnabled(): Boolean =
        prefs.getBoolean(KEY_REAL_IP_REDIRECT, true)

    override fun setRealIpRedirectEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_REAL_IP_REDIRECT, enabled).apply()
    }

    override fun isTlsFragmentV2Enabled(): Boolean =
        prefs.getBoolean(KEY_TLS_FRAGMENT_V2, true)

    override fun setTlsFragmentV2Enabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_TLS_FRAGMENT_V2, enabled).apply()
    }

    override fun isTlsTerminationEnabled(): Boolean =
        prefs.getBoolean(KEY_TLS_TERMINATION, false)

    override fun setTlsTerminationEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_TLS_TERMINATION, enabled).apply()
    }

    override fun nat64FallbackConfig(): Nat64FallbackConfig = Nat64FallbackConfig(
        enabled = prefs.getBoolean(KEY_NAT64_ENABLED, false),
        prefix = prefs.getString(KEY_NAT64_PREFIX, "").orEmpty(),
        operator = prefs.getString(KEY_NAT64_OPERATOR, "").orEmpty(),
        expectedAsn = prefs.getString(KEY_NAT64_ASN, "").orEmpty(),
        expectedRegion = prefs.getString(KEY_NAT64_REGION, "").orEmpty(),
        riskAccepted = prefs.getBoolean(KEY_NAT64_RISK_ACCEPTED, false),
    ).normalized()

    override fun setNat64FallbackConfig(config: Nat64FallbackConfig) {
        val normalized = config.normalized()
        // 损坏或不完整的外部写入只能保存为关闭状态，不能越过 UI/风险确认进入数据面。
        val safe = if (!normalized.enabled || normalized.activationOrNull() != null) {
            normalized
        } else {
            normalized.copy(enabled = false, riskAccepted = false)
        }
        prefs.edit()
            .putBoolean(KEY_NAT64_ENABLED, safe.enabled)
            .putString(KEY_NAT64_PREFIX, safe.prefix)
            .putString(KEY_NAT64_OPERATOR, safe.operator)
            .putString(KEY_NAT64_ASN, safe.expectedAsn)
            .putString(KEY_NAT64_REGION, safe.expectedRegion)
            .putBoolean(KEY_NAT64_RISK_ACCEPTED, safe.riskAccepted)
            .apply()
    }

    override fun routeSnapshot(): Pair<String, Long>? {
        val json = prefs.getString(KEY_ROUTE_SNAPSHOT, null) ?: return null
        return json to prefs.getLong(KEY_ROUTE_GENERATION, 0)
    }

    override fun saveRouteSnapshot(json: String, generation: Long) {
        prefs.edit()
            .putString(KEY_ROUTE_SNAPSHOT, json)
            .putLong(KEY_ROUTE_GENERATION, generation)
            .apply()
    }

    override fun ensureHookHeartbeatToken(): String? {
        prefs.getString(KEY_HOOK_TOKEN, null)?.takeIf(TOKEN_RE::matches)?.let { return it }
        val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val generated = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return try {
            if (prefs.edit().putString(KEY_HOOK_TOKEN, generated).commit()) {
                prefs.getString(KEY_HOOK_TOKEN, generated)
            } else {
                null
            }
        } catch (_: Throwable) {
            null
        }
    }

    override fun recordHookHeartbeat(heartbeat: HookHeartbeat) {
        if (!PACKAGE_RE.matches(heartbeat.packageName) || !TOKEN_RE.matches(heartbeat.token)) return
        val expected = prefs.getString(KEY_HOOK_TOKEN, null) ?: return
        if (heartbeat.token != expected) return
        val json = JSONObject()
            .put("package", heartbeat.packageName)
            .put("process", heartbeat.processName.take(160))
            .put("timestamp", heartbeat.timestamp)
            .put("generation", heartbeat.routeGeneration)
            .put("framework", heartbeat.framework.take(160))
            .put("api", heartbeat.apiVersion)
            .put("hits", heartbeat.hitCount)
            .put("token", heartbeat.token)
            .toString()
        val heartbeatKey = KEY_HOOK_HEARTBEAT_PREFIX + heartbeat.packageName
        val editor = prefs.edit().putString(heartbeatKey, json)
        val older = prefs.all.asSequence()
            .filter { (key, _) -> key.startsWith(KEY_HOOK_HEARTBEAT_PREFIX) && key != heartbeatKey }
            .map { (key, value) -> key to heartbeatTimestamp(value as? String) }
            .sortedWith(compareBy<Pair<String, Long>> { it.second }.thenBy { it.first })
            .toList()
        val overflow = (older.size + 1 - MAX_HEARTBEATS).coerceAtLeast(0)
        older.take(overflow).forEach { (key, _) -> editor.remove(key) }
        check(editor.commit()) { "Hook heartbeat commit failed" }
    }

    override fun hookHeartbeats(): List<HookHeartbeat> {
        val expected = prefs.getString(KEY_HOOK_TOKEN, null) ?: return emptyList()
        return prefs.all.asSequence()
            .filter { (key, _) -> key.startsWith(KEY_HOOK_HEARTBEAT_PREFIX) }
            .mapNotNull { (_, value) -> decodeHeartbeat(value as? String, expected) }
            .sortedByDescending { it.timestamp }
            .take(MAX_HEARTBEATS)
            .toList()
    }

    private fun decodeHeartbeat(raw: String?, expectedToken: String): HookHeartbeat? {
        return try {
            val obj = JSONObject(raw ?: return null)
            val pkg = obj.optString("package")
            val token = obj.optString("token")
            if (!PACKAGE_RE.matches(pkg) || token != expectedToken) return null
            HookHeartbeat(
                packageName = pkg,
                processName = obj.optString("process", pkg),
                timestamp = obj.optLong("timestamp", 0L).coerceAtLeast(0L),
                routeGeneration = obj.optLong("generation", 0L).coerceAtLeast(0L),
                framework = obj.optString("framework", "unknown").take(160),
                apiVersion = obj.optInt("api", 0).coerceAtLeast(0),
                hitCount = obj.optLong("hits", 0L).coerceAtLeast(0L),
                token = token,
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun heartbeatTimestamp(raw: String?): Long {
        if (raw == null) return Long.MIN_VALUE
        return try {
            JSONObject(raw).optLong("timestamp", Long.MIN_VALUE)
        } catch (_: Throwable) {
            Long.MIN_VALUE
        }
    }

    override fun addChangeListener(listener: (String) -> Unit): java.io.Closeable {
        val wrapper = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key != null) listener(key)
        }
        prefs.registerOnSharedPreferenceChangeListener(wrapper)
        return java.io.Closeable { prefs.unregisterOnSharedPreferenceChangeListener(wrapper) }
    }

    companion object {
        const val PREFS_NAME = "direct_settings"

        private const val KEY_BACKEND_MODE = "backend.mode"
        private const val KEY_SCOPE_MODE = "scope.mode"
        private const val KEY_SCOPE_PACKAGES = "scope.packages"
        private const val KEY_EMBEDDED_TLS_PACKAGES = "scope.embedded_tls_packages"
        private const val KEY_ROOT_SERVICE_ENABLED = "root.service.enabled"
        private const val KEY_ROOT_AUTOSTART = "root.service.autostart"
        private const val KEY_ADAPTIVE_CANDIDATES = "feature.adaptive_candidates"
        private const val KEY_REAL_IP_REDIRECT = "feature.real_ip_redirect"
        private const val KEY_TLS_FRAGMENT_V2 = "feature.tls_fragment_v2"
        const val KEY_TLS_TERMINATION = "feature.tls_termination"
        private const val KEY_NAT64_ENABLED = "feature.nat64_fallback.enabled"
        private const val KEY_NAT64_PREFIX = "feature.nat64_fallback.prefix"
        private const val KEY_NAT64_OPERATOR = "feature.nat64_fallback.operator"
        private const val KEY_NAT64_ASN = "feature.nat64_fallback.expected_asn"
        private const val KEY_NAT64_REGION = "feature.nat64_fallback.expected_region"
        private const val KEY_NAT64_RISK_ACCEPTED = "feature.nat64_fallback.risk_accepted"
        private const val KEY_ROUTE_SNAPSHOT = "route.snapshot.json"
        private const val KEY_ROUTE_GENERATION = "route.snapshot.generation"
        private const val KEY_HOOK_TOKEN = "hook.heartbeat.token"
        private const val KEY_HOOK_HEARTBEAT_PREFIX = "hook.heartbeat.package."
        private const val MAX_HEARTBEATS = 32
        private val TOKEN_RE = Regex("^[0-9a-f]{32}$")
        private val PACKAGE_RE = Regex("^[A-Za-z][A-Za-z0-9_.]{0,159}$")

    }
}

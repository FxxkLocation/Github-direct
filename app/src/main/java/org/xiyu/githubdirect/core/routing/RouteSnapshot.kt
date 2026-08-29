package org.xiyu.githubdirect.core.routing

import org.json.JSONArray
import org.json.JSONObject
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.rules.DnsNames

enum class CandidateSource {
    BUNDLED,
    GITHUB_META,
    WIRE_DOH,
    /** 来自显式同 CDN 池；只在目标域再次通过严格 TLS 验证后才可作为上游。 */
    CANDIDATE_POOL,
    /** 不受信任的独立解析器观测；永远只能进入拦截目标集。 */
    DNS_OBSERVER,
    LOCAL_DNS,
    COMMUNITY,
    HISTORICAL,
}

enum class RouteCapability {
    DIRECT_TLS,
    FRAGMENTED_TLS,
    /** 上游不发送 SNI 仍能通过系统链与原主机名校验；只能经本机 CA 终止路径使用。 */
    NO_SNI_TLS,
    UNUSABLE,
}

/** 候选最近一次主动探测失败阶段；用于解释降级，不参与放宽信任判定。 */
enum class CandidateFailureStage {
    NONE,
    INVALID_ADDRESS,
    TCP_CONNECT,
    TLS_RESET,
    CERTIFICATE,
    TLS_HANDSHAKE,
    HTTP_SEMANTIC,
}

data class EndpointCandidate(
    val domain: String,
    val address: String,
    val source: CandidateSource,
    val fetchedAt: Long,
    val expiresAt: Long,
    val latencyMs: Long,
    val capability: RouteCapability,
    val failures: Int = 0,
    val backoffUntil: Long = 0,
    /** Android Network handle/传输快照；bundled 使用 "any"。 */
    val networkKey: String = "any",
    /** 污染/不可信 DNS 地址只进入防火墙目标集，绝不作为中继上游。 */
    val interceptOnly: Boolean = false,
    /**
     * 同一地址在不发送 SNI 时仍通过系统信任链与 [domain] 主机名校验。
     * 与 [capability] 独立：一个地址可以同时 DIRECT_TLS 与 NO-SNI 可用。
     */
    val noSniCapable: Boolean = capability == RouteCapability.NO_SNI_TLS,
    /** 区分“严格探测为 false”和“旧快照/关闭 TLS 终止时从未探测”。 */
    val noSniProbed: Boolean = noSniCapable,
    /** 最近一次主动/被动 TLS 路由失败的有界诊断；成功探测后清空。 */
    val lastError: String = "",
    val failureStage: CandidateFailureStage = CandidateFailureStage.NONE,
) {
    fun usable(now: Long): Boolean =
        !interceptOnly && capability != RouteCapability.UNUSABLE
            && (expiresAt <= 0L || now < expiresAt) && now >= backoffUntil
}

data class EndpointPlan(
    val domain: String,
    val endpointGroup: String,
    val includeSubdomains: Boolean = false,
    val candidates: List<EndpointCandidate>,
)

data class RouteSnapshot(
    val generation: Long,
    val createdAt: Long,
    val expiresAt: Long,
    val plans: Map<String, EndpointPlan>,
    val metaCidrs: Set<String>,
) {
    fun planFor(rawDomain: String): EndpointPlan? {
        val domain = DnsNames.normalize(rawDomain) ?: return null
        plans[domain]?.let { return it }
        return plans.values.asSequence()
            .filter { it.includeSubdomains && domain.endsWith(".${it.domain}") }
            .maxByOrNull { it.domain.length }
    }

    fun candidatesFor(rawDomain: String, now: Long = System.currentTimeMillis()): List<EndpointCandidate> =
        planFor(rawDomain)?.candidates.orEmpty()
            .asSequence()
            .filter { it.usable(now) }
            .sortedWith(
                compareBy<EndpointCandidate> { capabilityRank(it.capability) }
                    .thenBy { if (it.latencyMs > 0) it.latencyMs else Long.MAX_VALUE }
                    .thenBy { sourceRank(it.source) }
                    .thenBy { it.address },
            )
            .take(MAX_ACTIVE_PER_DOMAIN)
            .toList()

    fun relayHosts(now: Long = System.currentTimeMillis()): Map<String, List<String>> {
        val result = LinkedHashMap<String, List<String>>()
        for (plan in plans.values) {
            val addresses = candidatesFor(plan.domain, now).map { it.address }.distinct()
            if (addresses.isEmpty()) continue
            result[plan.domain] = addresses
            if (plan.includeSubdomains) result["*.${plan.domain}"] = addresses
        }
        return result
    }

    /** Meta CIDR + 可用候选 + 污染地址；所有值都已规范化为 CIDR。 */
    fun interceptDestinations(now: Long = System.currentTimeMillis()): Set<String> {
        val result = LinkedHashSet<String>()
        metaCidrs.filterTo(result) { RouteSnapshotCodec.isRoutableCidr(it) }
        for (plan in plans.values) {
            for (candidate in plan.candidates) {
                if (candidate.expiresAt > 0L && now >= candidate.expiresAt) continue
                val raw = IpAddresses.parseIpAddress(candidate.address) ?: continue
                if (IpAddresses.isBogonOrPoisoned(raw)) continue
                result += candidate.address + if (raw.size == 4) "/32" else "/128"
            }
        }
        return result
    }

    companion object {
        const val MAX_ACTIVE_PER_DOMAIN = 3
        val EMPTY = RouteSnapshot(0, 0, 0, emptyMap(), emptySet())

        private fun capabilityRank(value: RouteCapability): Int = when (value) {
            RouteCapability.DIRECT_TLS -> 0
            RouteCapability.FRAGMENTED_TLS -> 1
            RouteCapability.NO_SNI_TLS -> 2
            RouteCapability.UNUSABLE -> 3
        }

        private fun sourceRank(value: CandidateSource): Int = when (value) {
            CandidateSource.GITHUB_META -> 0
            CandidateSource.WIRE_DOH -> 1
            CandidateSource.CANDIDATE_POOL -> 2
            CandidateSource.BUNDLED -> 3
            CandidateSource.HISTORICAL -> 4
            CandidateSource.COMMUNITY -> 5
            CandidateSource.LOCAL_DNS -> 6
            CandidateSource.DNS_OBSERVER -> 7
        }
    }
}

object RouteSnapshotCodec {
    const val VERSION = 1
    private const val MAX_PLANS = 128
    private const val MAX_CANDIDATES = 32
    private const val MAX_CIDRS = 512

    fun encode(snapshot: RouteSnapshot): String {
        val root = JSONObject()
            .put("version", VERSION)
            .put("generation", snapshot.generation)
            .put("createdAt", snapshot.createdAt)
            .put("expiresAt", snapshot.expiresAt)
        root.put("metaCidrs", JSONArray(snapshot.metaCidrs.sorted()))
        val plans = JSONArray()
        for (plan in snapshot.plans.values.sortedBy { it.domain }) {
            val candidates = JSONArray()
            for (candidate in plan.candidates.take(MAX_CANDIDATES)) {
                val encoded = JSONObject()
                    .put("address", candidate.address)
                    .put("source", candidate.source.name)
                    .put("fetchedAt", candidate.fetchedAt)
                    .put("expiresAt", candidate.expiresAt)
                    .put("latencyMs", candidate.latencyMs)
                    .put("capability", candidate.capability.name)
                    .put("failures", candidate.failures)
                    .put("backoffUntil", candidate.backoffUntil)
                    .put("networkKey", candidate.networkKey.take(64))
                    .put("interceptOnly", candidate.interceptOnly)
                    .put("noSniCapable", candidate.noSniCapable)
                    .put("noSniProbed", candidate.noSniProbed)
                sanitizeDiagnostic(candidate.lastError).takeIf(String::isNotEmpty)?.let {
                    encoded.put("lastError", it)
                }
                if (candidate.failureStage != CandidateFailureStage.NONE) {
                    encoded.put("failureStage", candidate.failureStage.name)
                }
                candidates.put(encoded)
            }
            plans.put(
                JSONObject()
                    .put("domain", plan.domain)
                    .put("endpointGroup", plan.endpointGroup)
                    .put("includeSubdomains", plan.includeSubdomains)
                    .put("candidates", candidates),
            )
        }
        root.put("plans", plans)
        return root.toString()
    }

    fun decode(json: String?): RouteSnapshot? {
        if (json.isNullOrBlank()) return null
        return try {
            val root = JSONObject(json)
            if (root.optInt("version", -1) != VERSION) return null
            val cidrs = LinkedHashSet<String>()
            val cidrArray = root.optJSONArray("metaCidrs") ?: JSONArray()
            for (i in 0 until minOf(cidrArray.length(), MAX_CIDRS)) {
                cidrArray.optString(i).takeIf(::isRoutableCidr)?.let(cidrs::add)
            }
            val decodedPlans = LinkedHashMap<String, EndpointPlan>()
            val plans = root.optJSONArray("plans") ?: JSONArray()
            for (i in 0 until minOf(plans.length(), MAX_PLANS)) {
                val obj = plans.optJSONObject(i) ?: continue
                val domain = DnsNames.normalize(obj.optString("domain")) ?: continue
                val group = obj.optString("endpointGroup", domain).take(64).ifBlank { domain }
                val decoded = ArrayList<EndpointCandidate>()
                val candidates = obj.optJSONArray("candidates") ?: JSONArray()
                for (j in 0 until minOf(candidates.length(), MAX_CANDIDATES)) {
                    val c = candidates.optJSONObject(j) ?: continue
                    val address = c.optString("address")
                    val rawAddress = IpAddresses.parseIpAddress(address) ?: continue
                    if (IpAddresses.isBogonOrPoisoned(rawAddress)) continue
                    val source = enumValue<CandidateSource>(c.optString("source")) ?: continue
                    val capability = enumValue<RouteCapability>(c.optString("capability")) ?: continue
                    decoded += EndpointCandidate(
                        domain = domain,
                        address = address,
                        source = source,
                        fetchedAt = c.optLong("fetchedAt", 0),
                        expiresAt = c.optLong("expiresAt", 0),
                        latencyMs = c.optLong("latencyMs", 0).coerceIn(0, MAX_LATENCY_MS),
                        capability = capability,
                        failures = c.optInt("failures", 0).coerceIn(0, 1_000_000),
                        backoffUntil = c.optLong("backoffUntil", 0),
                        networkKey = c.optString("networkKey", "any").take(64).ifBlank { "any" },
                        interceptOnly = c.optBoolean("interceptOnly", false),
                        noSniCapable = c.optBoolean(
                            "noSniCapable",
                            capability == RouteCapability.NO_SNI_TLS,
                        ),
                        noSniProbed = c.optBoolean(
                            "noSniProbed",
                            capability == RouteCapability.NO_SNI_TLS,
                        ),
                        lastError = sanitizeDiagnostic(c.optString("lastError")),
                        failureStage = enumValue<CandidateFailureStage>(
                            c.optString("failureStage"),
                        ) ?: CandidateFailureStage.NONE,
                    )
                }
                decodedPlans[domain] = EndpointPlan(
                    domain = domain,
                    endpointGroup = group,
                    includeSubdomains = obj.optBoolean("includeSubdomains", false),
                    candidates = decoded.distinctBy { it.address },
                )
            }
            RouteSnapshot(
                generation = root.optLong("generation", 0).coerceAtLeast(0),
                createdAt = root.optLong("createdAt", 0).coerceAtLeast(0),
                expiresAt = root.optLong("expiresAt", 0).coerceAtLeast(0),
                plans = decodedPlans,
                metaCidrs = cidrs,
            )
        } catch (_: Throwable) {
            null
        }
    }

    fun isValidCidr(value: String): Boolean {
        return parseCidr(value) != null
    }

    /**
     * 用于防火墙数据面的严格 CIDR：必须是公网网络地址，且不允许过宽前缀。
     * 宽前缀被拒绝时保留旧快照，避免损坏/异常 Meta 把大量无关 HTTPS 引入代理。
     */
    fun isRoutableCidr(value: String): Boolean {
        val (raw, prefix) = parseCidr(value) ?: return false
        if (IpAddresses.isBogonOrPoisoned(raw)) return false
        val minimumPrefix = if (raw.size == 4) 16 else 24
        return prefix >= minimumPrefix && hasZeroHostBits(raw, prefix)
    }

    private fun parseCidr(value: String): Pair<ByteArray, Int>? {
        val slash = value.lastIndexOf('/')
        if (slash <= 0 || slash == value.lastIndex) return null
        val address = value.substring(0, slash)
        val raw = IpAddresses.parseIpAddress(address) ?: return null
        val prefix = value.substring(slash + 1).toIntOrNull() ?: return null
        if (prefix !in 0..if (raw.size == 4) 32 else 128) return null
        return raw to prefix
    }

    private fun hasZeroHostBits(raw: ByteArray, prefix: Int): Boolean {
        val fullBytes = prefix / 8
        val remainingBits = prefix % 8
        if (remainingBits != 0) {
            val hostMask = (1 shl (8 - remainingBits)) - 1
            if ((raw[fullBytes].toInt() and 0xFF and hostMask) != 0) return false
        }
        val hostStart = fullBytes + if (remainingBits == 0) 0 else 1
        return (hostStart until raw.size).all { raw[it].toInt() == 0 }
    }

    private inline fun <reified T : Enum<T>> enumValue(raw: String): T? =
        enumValues<T>().firstOrNull { it.name == raw }

    private fun sanitizeDiagnostic(raw: String): String = raw
        .map { character -> if (character.code < 0x20 || character == '\u007f') ' ' else character }
        .joinToString("")
        .replace(Regex(" +"), " ")
        .trim()
        .take(MAX_DIAGNOSTIC_CHARS)

    private const val MAX_LATENCY_MS = 300_000L
    private const val MAX_DIAGNOSTIC_CHARS = 240
}

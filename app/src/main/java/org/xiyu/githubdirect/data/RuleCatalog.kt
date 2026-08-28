package org.xiyu.githubdirect.data

import org.json.JSONArray
import org.json.JSONObject
import org.xiyu.githubdirect.core.dns.CidrFilter
import org.xiyu.githubdirect.core.rules.DomainMatcher
import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.HostsProviderSpec
import org.xiyu.githubdirect.core.rules.ResolverPolicy
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.SuffixMatcher
import org.xiyu.githubdirect.core.rules.TransportPolicy
import org.xiyu.githubdirect.core.rules.VerifyStatus

/**
 * 规则目录加载器：assets/rules/profiles.json → Map<String, ServiceProfile>。
 * 解析用 Android 内置 org.json。非法条目跳过（数据容错），profile 至少 1 条 domain 才保留。
 */
object RuleCatalog {

    fun load(json: String): Map<String, ServiceProfile> {
        val root = JSONObject(json)
        val arr = root.optJSONArray("profiles") ?: return emptyMap()
        val result = LinkedHashMap<String, ServiceProfile>()
        for (i in 0 until arr.length()) {
            try {
                val profile = parseProfile(arr.getJSONObject(i)) ?: continue
                result[profile.id] = profile
            } catch (_: Exception) {
                // 单个 profile 解析失败不影响其它
            }
        }
        return result
    }

    private fun parseProfile(obj: JSONObject): ServiceProfile? {
        val id = obj.optString("id").takeIf { it.isNotBlank() } ?: return null
        val displayName = obj.optString("displayName", id)
        val category = obj.optString("category", "")
        val enabledByDefault = obj.optBoolean("enabledByDefault", false)
        val priority = obj.optInt("priority", 0)
        val verifyStatus = VerifyStatus.fromJson(obj.optString("verifyStatus")) ?: VerifyStatus.NEEDS_VERIFY
        val aaaaSuppress = obj.optBoolean("aaaaSuppress", false)
        val idleTimeoutSec = obj.optInt("idleTimeoutSec", 60)
        val notes = obj.optString("notes", "")

        val cidr = parseCidr(obj.optJSONObject("cidr"))
        val testEndpoints = obj.optJSONArray("testEndpoints")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotBlank() } }
        } ?: emptyList()

        val providers = parseProviders(obj.optJSONArray("providers"))
        val domains = parseDomains(obj.optJSONArray("domains"))
        if (domains.isEmpty()) return null

        return ServiceProfile(
            id = id,
            displayName = displayName,
            category = category,
            enabledByDefault = enabledByDefault,
            priority = priority,
            verifyStatus = verifyStatus,
            domains = domains,
            testEndpoints = testEndpoints,
            cidr = cidr,
            aaaaSuppress = aaaaSuppress,
            idleTimeoutSec = idleTimeoutSec,
            providers = providers,
            notes = notes,
        )
    }

    private fun parseCidr(obj: JSONObject?): CidrFilter? {
        if (obj == null) return null
        val v4 = obj.optJSONArray("v4")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotBlank() } }
        } ?: emptyList()
        val v6 = obj.optJSONArray("v6")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotBlank() } }
        } ?: emptyList()
        if (v4.isEmpty() && v6.isEmpty()) return null
        return CidrFilter.parse(v4, v6)
    }

    private fun parseProviders(arr: JSONArray?): List<HostsProviderSpec> {
        if (arr == null) return emptyList()
        val result = ArrayList<HostsProviderSpec>(arr.length())
        for (i in 0 until arr.length()) {
            try {
                val o = arr.getJSONObject(i)
                val providerId = o.optString("providerId").takeIf { it.isNotBlank() } ?: continue
                val intervalHours = o.optLong("intervalHours", 6)
                val port = o.optInt("tcpProbePort", 443)
                result.add(HostsProviderSpec(providerId, intervalHours, port))
            } catch (_: Exception) {
            }
        }
        return result
    }

    private fun parseDomains(arr: JSONArray?): List<DomainRule> {
        if (arr == null) return emptyList()
        val result = ArrayList<DomainRule>(arr.length())
        for (i in 0 until arr.length()) {
            try {
                parseDomain(arr.getJSONObject(i))?.let { result.add(it) }
            } catch (_: Exception) {
            }
        }
        return result
    }

    private fun parseDomain(obj: JSONObject): DomainRule? {
        val id = obj.optString("id").takeIf { it.isNotBlank() } ?: return null
        val matchObj = obj.optJSONObject("match") ?: return null
        val matcher: DomainMatcher = parseMatcher(matchObj) ?: return null

        val transport = TransportPolicy.fromJson(obj.optString("transport"))
            ?: return null
        val resolver = ResolverPolicy.fromJson(obj.optString("resolver")) ?: ResolverPolicy.DOH

        val aaaaSuppress = optNullableBoolean(obj, "aaaaSuppress")
        val fragmentTls = optNullableBoolean(obj, "fragmentTls")
        val fixedIp = obj.optString("fixedIp").takeIf { it.isNotBlank() }
        val cidr = parseCidr(obj.optJSONObject("cidr"))
        val endpointGroup = safeReference(obj.optString("endpointGroup"))
        val cidrRef = safeReference(obj.optString("cidrRef"))
        val candidatePool = safeReference(obj.optString("candidatePool"))
        val echConfigDomain = DnsNames.normalize(obj.optString("echConfigDomain"))
        val nat64FallbackEligible = obj.optBoolean("nat64FallbackEligible", false)

        return DomainRule(
            id = id,
            matcher = matcher,
            transport = transport,
            resolver = resolver,
            aaaaSuppress = aaaaSuppress,
            fragmentTls = fragmentTls,
            cidr = cidr,
            fixedIp = fixedIp,
            endpointGroup = endpointGroup,
            cidrRef = cidrRef,
            candidatePool = candidatePool,
            echConfigDomain = echConfigDomain,
            nat64FallbackEligible = nat64FallbackEligible,
        )
    }

    private fun parseMatcher(obj: JSONObject): DomainMatcher? {
        val type = obj.optString("type").uppercase()
        val value = obj.optString("value").takeIf { it.isNotBlank() } ?: return null
        return when (type) {
            "EXACT" -> ExactMatcher(value.lowercase())
            "SUFFIX" -> SuffixMatcher(if (value.startsWith(".")) value.lowercase() else ".${value.lowercase()}")
            else -> null
        }
    }

    /** org.json 中 JSONObject.NULL / 缺省 → null；true/false → 布尔。 */
    private fun optNullableBoolean(obj: JSONObject, key: String): Boolean? {
        if (!obj.has(key)) return null
        return if (obj.isNull(key)) null else obj.optBoolean(key)
    }

    private fun safeReference(value: String): String? =
        value.takeIf { it.matches(REFERENCE_RE) }

    private val REFERENCE_RE = Regex("^[A-Za-z0-9._-]{1,64}$")
}

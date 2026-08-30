package org.xiyu.githubdirect.data

import org.json.JSONArray
import org.json.JSONObject
import org.xiyu.githubdirect.core.dns.CidrFilter
import org.xiyu.githubdirect.core.data.Nat64FallbackActivation
import org.xiyu.githubdirect.core.data.Nat64FallbackConfig
import org.xiyu.githubdirect.core.rules.DomainMatcher
import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.HostsProviderSpec
import org.xiyu.githubdirect.core.rules.HttpSemanticProbePolicy
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
        val defaultTlsFrontSni = DnsNames.normalize(obj.optString("tlsFrontSni"))
        val defaultTlsFrontSniReflectUpstream =
            obj.optBoolean("tlsFrontSniReflectUpstream", false)
        val defaultTlsFrontSniProbeDomain =
            DnsNames.normalize(obj.optString("tlsFrontSniProbeDomain"))
        val defaultTlsFrontSniNat64Egress =
            parseNat64Egress(obj.optJSONObject("tlsFrontSniNat64Egress"))
        val defaultNat64FallbackEligible = obj.optBoolean("nat64FallbackEligible", false)

        val cidr = parseCidr(obj.optJSONObject("cidr"))
        val testEndpoints = obj.optJSONArray("testEndpoints")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotBlank() } }
        } ?: emptyList()

        val providers = parseProviders(obj.optJSONArray("providers"))
        val domains = parseDomains(
            obj.optJSONArray("domains"),
            defaultTlsFrontSni,
            defaultTlsFrontSniReflectUpstream,
            defaultTlsFrontSniProbeDomain,
            defaultTlsFrontSniNat64Egress,
            defaultNat64FallbackEligible,
        )
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

    private fun parseDomains(
        arr: JSONArray?,
        defaultTlsFrontSni: String?,
        defaultTlsFrontSniReflectUpstream: Boolean,
        defaultTlsFrontSniProbeDomain: String?,
        defaultTlsFrontSniNat64Egress: Nat64FallbackActivation?,
        defaultNat64FallbackEligible: Boolean,
    ): List<DomainRule> {
        if (arr == null) return emptyList()
        val result = ArrayList<DomainRule>(arr.length())
        for (i in 0 until arr.length()) {
            try {
                parseDomain(
                    arr.getJSONObject(i),
                    defaultTlsFrontSni,
                    defaultTlsFrontSniReflectUpstream,
                    defaultTlsFrontSniProbeDomain,
                    defaultTlsFrontSniNat64Egress,
                    defaultNat64FallbackEligible,
                )?.let { result.add(it) }
            } catch (_: Exception) {
            }
        }
        return result
    }

    private fun parseDomain(
        obj: JSONObject,
        defaultTlsFrontSni: String?,
        defaultTlsFrontSniReflectUpstream: Boolean,
        defaultTlsFrontSniProbeDomain: String?,
        defaultTlsFrontSniNat64Egress: Nat64FallbackActivation?,
        defaultNat64FallbackEligible: Boolean,
    ): DomainRule? {
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
        val candidatePoolScope = safeReference(obj.optString("candidatePoolScope"))
        val echConfigDomain = DnsNames.normalize(obj.optString("echConfigDomain"))
        val tlsFrontSni = DnsNames.normalize(obj.optString("tlsFrontSni"))
            ?: defaultTlsFrontSni
        val tlsFrontSniReflectUpstream = if (obj.has("tlsFrontSniReflectUpstream")) {
            obj.optBoolean("tlsFrontSniReflectUpstream", false)
        } else {
            defaultTlsFrontSniReflectUpstream
        }
        val tlsFrontSniProbeDomain = DnsNames.normalize(obj.optString("tlsFrontSniProbeDomain"))
            ?: defaultTlsFrontSniProbeDomain
        val tlsFrontSniNat64Egress = if (obj.has("tlsFrontSniNat64Egress")) {
            parseNat64Egress(obj.optJSONObject("tlsFrontSniNat64Egress"))
        } else {
            defaultTlsFrontSniNat64Egress
        }
        val nat64FallbackEligible = if (obj.has("nat64FallbackEligible")) {
            obj.optBoolean("nat64FallbackEligible", false)
        } else {
            defaultNat64FallbackEligible
        }
        val semanticProbe = parseSemanticProbe(obj.optJSONObject("semanticProbe"))

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
            tlsFrontSni = tlsFrontSni,
            tlsFrontSniReflectUpstream = tlsFrontSniReflectUpstream,
            tlsFrontSniProbeDomain = tlsFrontSniProbeDomain,
            tlsFrontSniNat64Egress = tlsFrontSniNat64Egress,
            nat64FallbackEligible = nat64FallbackEligible,
            semanticProbe = semanticProbe,
            candidatePoolScope = candidatePoolScope,
        )
    }

    private fun parseSemanticProbe(obj: JSONObject?): HttpSemanticProbePolicy? {
        obj ?: return null
        return HttpSemanticProbePolicy.create(
            path = obj.optString("path"),
            statusMin = obj.optInt("statusMin", 200),
            statusMax = obj.optInt("statusMax", 399),
        )
    }

    /** Bundled/signed rule metadata still has to pass the same strict /96 and label validation. */
    private fun parseNat64Egress(obj: JSONObject?): Nat64FallbackActivation? {
        obj ?: return null
        return Nat64FallbackConfig(
            enabled = true,
            prefix = obj.optString("prefix"),
            operator = obj.optString("operator"),
            expectedAsn = obj.optString("expectedAsn"),
            expectedRegion = obj.optString("expectedRegion"),
            riskAccepted = true,
        ).activationOrNull()
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

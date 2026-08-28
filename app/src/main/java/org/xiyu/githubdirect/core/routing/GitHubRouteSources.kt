package org.xiyu.githubdirect.core.routing

import org.json.JSONObject
import org.xiyu.githubdirect.core.dns.CidrFilter
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.rules.DnsNames
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

data class GitHubMetaData(
    val groups: Map<String, Set<String>>,
) {
    val allCidrs: Set<String> = groups.values.flatten().toSet()
    private val filter: CidrFilter? = runCatching {
        CidrFilter.parse(
            allCidrs.filter { IpAddresses.parseIpAddress(it.substringBefore('/'))?.size == 4 },
            allCidrs.filter { IpAddresses.parseIpAddress(it.substringBefore('/'))?.size == 16 },
        )
    }.getOrNull()

    fun literalAddresses(group: String): Set<String> = groups[group].orEmpty().mapNotNullTo(LinkedHashSet()) {
        val address = it.substringBefore('/')
        val bytes = IpAddresses.parseIpAddress(address) ?: return@mapNotNullTo null
        val prefix = it.substringAfter('/', "").toIntOrNull() ?: return@mapNotNullTo null
        if (prefix == if (bytes.size == 4) 32 else 128) address else null
    }

    fun contains(address: String): Boolean {
        val bytes = IpAddresses.parseIpAddress(address) ?: return false
        val current = filter ?: return false
        return if (bytes.size == 4) current.allowsIpv4(bytes) else current.allowsIpv6(bytes)
    }
}

object GitHubMetaParser {
    private val GROUPS = listOf("web", "api", "git", "pages")

    fun parse(json: String?): GitHubMetaData? {
        if (json.isNullOrBlank()) return null
        return try {
            val root = JSONObject(json)
            val groups = LinkedHashMap<String, Set<String>>()
            for (group in GROUPS) {
                val array = root.optJSONArray(group) ?: continue
                val cidrs = LinkedHashSet<String>()
                for (i in 0 until minOf(array.length(), 256)) {
                    val value = array.optString(i)
                    if (RouteSnapshotCodec.isRoutableCidr(value)) cidrs += value
                }
                if (cidrs.isNotEmpty()) groups[group] = cidrs
            }
            if (groups.isEmpty()) null else GitHubMetaData(groups)
        } catch (_: Throwable) {
            null
        }
    }
}

data class CommunityHostsData(
    val updatedAt: Long,
    val hosts: Map<String, List<String>>,
)

object CommunityHostsParser {
    private val UPDATE = Regex(
        "(?im)^\\s*#?\\s*Update\\s+Time\\s*:\\s*(\\d{4}-\\d{2}-\\d{2})(?:[ T](\\d{2}:\\d{2}(?::\\d{2})?))?",
    )
    private val DATE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

    fun parse(data: String?, now: Long, maxAgeMs: Long): CommunityHostsData? {
        if (data.isNullOrBlank()) return null
        val match = UPDATE.find(data) ?: return null
        val time = (match.groupValues.getOrNull(2)?.takeIf { it.isNotBlank() } ?: "00:00:00")
            .let { if (it.length == 5) "$it:00" else it }
        val updatedAt = runCatching {
            LocalDateTime.parse("${match.groupValues[1]} $time", DATE_TIME)
                .toInstant(ZoneOffset.ofHours(8)).toEpochMilli()
        }.getOrNull() ?: return null
        if (updatedAt > now + 24 * 60 * 60 * 1000L || now - updatedAt > maxAgeMs) return null

        val hosts = LinkedHashMap<String, MutableList<String>>()
        for (raw in data.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            val fields = line.split(Regex("\\s+"))
            if (fields.size < 2) continue
            val address = IpAddresses.parseIpAddress(fields[0]) ?: continue
            if (IpAddresses.isBogonOrPoisoned(address)) continue
            for (host in fields.drop(1)) {
                val domain = DnsNames.normalize(host) ?: continue
                if (!GitHubDomainPolicy.isTrustedSni(domain)) continue
                hosts.getOrPut(domain) { ArrayList(2) }.add(fields[0])
            }
        }
        if (hosts.isEmpty()) return null
        return CommunityHostsData(updatedAt, hosts.mapValues { it.value.distinct().take(32) })
    }

}

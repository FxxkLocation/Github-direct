package org.xiyu.githubdirect.core.routing

import org.json.JSONObject
import org.xiyu.githubdirect.core.dns.CidrFilter
import org.xiyu.githubdirect.core.dns.IpAddresses

/**
 * Google 官方 goog.json 地址归属快照。
 *
 * 这里只做 DNS 候选的归属校验，不会展开 CIDR、扫描网段或把宽前缀直接交给防火墙。
 * 即使地址属于 Google，仍必须用目标真实 SNI、系统信任链和主机名完成独立 TLS 探测。
 */
data class GoogleIpRanges(
    val syncToken: String,
    val creationTime: String,
    val ipv4Cidrs: Set<String>,
    val ipv6Cidrs: Set<String>,
) {
    private val filter = CidrFilter.parse(ipv4Cidrs.toList(), ipv6Cidrs.toList())

    fun contains(address: ByteArray): Boolean = when (address.size) {
        4 -> filter.allowsIpv4(address)
        16 -> filter.allowsIpv6(address)
        else -> false
    }

    fun contains(address: String): Boolean =
        IpAddresses.parseIpAddress(address)?.let(::contains) == true
}

object GoogleIpRangesParser {
    fun parse(json: String?): GoogleIpRanges? {
        if (json.isNullOrBlank() || json.length > MAX_JSON_CHARS) return null
        return try {
            val root = JSONObject(json)
            val prefixes = root.optJSONArray("prefixes") ?: return null
            val v4 = LinkedHashSet<String>()
            val v6 = LinkedHashSet<String>()
            for (index in 0 until minOf(prefixes.length(), MAX_PREFIXES)) {
                val entry = prefixes.optJSONObject(index) ?: continue
                val ipv4 = entry.optString("ipv4Prefix").trim()
                val ipv6 = entry.optString("ipv6Prefix").trim()
                when {
                    ipv4.isNotEmpty() && ipv6.isEmpty() && isSafePrefix(ipv4, 4) -> v4 += ipv4
                    ipv6.isNotEmpty() && ipv4.isEmpty() && isSafePrefix(ipv6, 16) -> v6 += ipv6
                }
            }
            if (v4.isEmpty() && v6.isEmpty()) return null
            GoogleIpRanges(
                syncToken = root.optString("syncToken").take(MAX_METADATA_CHARS),
                creationTime = root.optString("creationTime").take(MAX_METADATA_CHARS),
                ipv4Cidrs = v4,
                ipv6Cidrs = v6,
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun isSafePrefix(value: String, expectedAddressBytes: Int): Boolean {
        val slash = value.lastIndexOf('/')
        if (slash <= 0 || slash == value.lastIndex) return false
        val raw = IpAddresses.parseIpAddress(value.substring(0, slash)) ?: return false
        if (raw.size != expectedAddressBytes || IpAddresses.isBogonOrPoisoned(raw)) return false
        val bits = value.substring(slash + 1).toIntOrNull() ?: return false
        val minimum = if (raw.size == 4) MIN_IPV4_PREFIX else MIN_IPV6_PREFIX
        if (bits !in minimum..raw.size * 8) return false
        return hasZeroHostBits(raw, bits)
    }

    private fun hasZeroHostBits(raw: ByteArray, prefix: Int): Boolean {
        val fullBytes = prefix / 8
        val remainingBits = prefix % 8
        if (remainingBits != 0) {
            val hostMask = (1 shl (8 - remainingBits)) - 1
            if ((raw[fullBytes].toInt() and 0xff and hostMask) != 0) return false
        }
        val hostStart = fullBytes + if (remainingBits == 0) 0 else 1
        return (hostStart until raw.size).all { raw[it].toInt() == 0 }
    }

    private const val MAX_JSON_CHARS = 1_000_000
    private const val MAX_PREFIXES = 4_096
    private const val MAX_METADATA_CHARS = 128
    private const val MIN_IPV4_PREFIX = 8
    private const val MIN_IPV6_PREFIX = 16
}

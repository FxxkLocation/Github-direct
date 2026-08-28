package org.xiyu.githubdirect.core.data

import org.xiyu.githubdirect.core.dns.IpAddresses

/**
 * 第三方公共 NAT64 的显式、非严格直连配置。
 *
 * 这里只接受全局单播 /96。运营商本地的 64:ff9b::/96 必须由网络探测单独证明，不能
 * 被误当作一条可在公网路由的自定义前缀。配置完整仍不代表路径可信；运行时还必须通过
 * 实际目标的 ECH、公开证书与主机名验证。
 */
data class Nat64FallbackConfig(
    val enabled: Boolean = false,
    val prefix: String = "",
    val operator: String = "",
    val expectedAsn: String = "",
    val expectedRegion: String = "",
    val riskAccepted: Boolean = false,
) {
    fun normalized(): Nat64FallbackConfig = copy(
        prefix = normalizePublicNat64Prefix96(prefix).orEmpty(),
        operator = normalizeLabel(operator, MAX_OPERATOR_CHARS),
        expectedAsn = normalizeAsn(expectedAsn).orEmpty(),
        expectedRegion = normalizeLabel(expectedRegion, MAX_REGION_CHARS),
    )

    /** 返回 null 表示配置不能进入数据面。 */
    fun activationOrNull(): Nat64FallbackActivation? {
        if (!enabled || !riskAccepted) return null
        val normalized = normalized()
        if (normalized.prefix.isEmpty() || normalized.operator.isEmpty() ||
            normalized.expectedAsn.isEmpty() || normalized.expectedRegion.isEmpty()
        ) return null
        return Nat64FallbackActivation(
            prefix = normalized.prefix,
            operator = normalized.operator,
            expectedAsn = normalized.expectedAsn,
            expectedRegion = normalized.expectedRegion,
        )
    }

    companion object {
        val DISABLED = Nat64FallbackConfig()
        private const val MAX_OPERATOR_CHARS = 80
        private const val MAX_REGION_CHARS = 80
    }
}

data class Nat64FallbackActivation(
    val prefix: String,
    val operator: String,
    val expectedAsn: String,
    val expectedRegion: String,
)

/**
 * 规范化为未压缩 IPv6 + /96。拒绝低 32 位非零、非 2000::/3、特殊用途和本地 WKP。
 */
fun normalizePublicNat64Prefix96(raw: String?): String? {
    val value = raw?.trim()?.lowercase()?.takeIf { it.endsWith("/96") } ?: return null
    if (value.count { it == '/' } != 1) return null
    val bytes = IpAddresses.parseIpv6(value.substringBefore('/')) ?: return null
    if (bytes.size != 16 || bytes.sliceArray(12 until 16).any { it.toInt() != 0 }) return null
    val first = bytes[0].toInt() and 0xff
    if (first !in 0x20..0x3f) return null // 2000::/3 global unicast only
    if (IpAddresses.isBogonOrPoisoned(bytes)) return null
    return IpAddresses.ipv6ToString(bytes) + "/96"
}

private fun normalizeLabel(raw: String, maxChars: Int): String = raw
    .trim()
    .replace(Regex("\\s+"), " ")
    .take(maxChars)
    .takeIf { it.isNotEmpty() && it.none { ch -> ch == '\u0000' || ch == '\r' || ch == '\n' } }
    .orEmpty()

private fun normalizeAsn(raw: String): String? {
    val digits = raw.trim().uppercase().removePrefix("AS")
    if (!digits.matches(Regex("[0-9]{1,10}"))) return null
    val number = digits.toLongOrNull()?.takeIf { it in 1..4_294_967_295L } ?: return null
    return "AS$number"
}

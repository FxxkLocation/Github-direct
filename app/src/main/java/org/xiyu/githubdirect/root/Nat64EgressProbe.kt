package org.xiyu.githubdirect.root

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import org.json.JSONObject
import org.xiyu.githubdirect.core.data.Nat64FallbackActivation
import org.xiyu.githubdirect.core.data.normalizePublicNat64Prefix96
import org.xiyu.githubdirect.core.dns.IpAddresses
import java.io.Reader
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * 第三方 NAT64 的服务端视角观测。
 *
 * [verified] 只表示本轮通过指定 /96 完成了公开 TLS、出口 IPv4、BGP origin ASN 与
 * Cloudflare 地区的交叉校验，并且 ASN/地区符合用户填写的预期；它不表示公共转换器可信，
 * 也不把该路径提升为严格直连。
 */
data class Nat64EgressObservation(
    val verified: Boolean = false,
    val publicIp: String = "",
    val asn: String = "",
    val operator: String = "",
    val region: String = "",
    val observedAt: Long = 0L,
    val detail: String = "",
) {
    companion object {
        val NONE = Nat64EgressObservation()
    }
}

internal data class Nat64Trace(
    val publicIp: String,
    val regionCode: String,
    val colo: String,
    val tls: String,
) {
    val region: String get() = "$regionCode/$colo"
}

/**
 * 低频、fail-closed 的 NAT64 出口探测。所有 HTTP 请求都把实时 A 记录合成为用户选择的
 * /96，再由 OkHttp 的默认 TrustManager 和主机名验证完成公开 TLS；没有 TrustAll、代理或
 * 全局路由。DNS 污染最多令探测失败，不能令错误证书通过。
 */
class Nat64EgressProbe(
    private val systemLookup: (String) -> List<InetAddress> = { Dns.SYSTEM.lookup(it) },
    private val clock: () -> Long = System::currentTimeMillis,
) {
    fun probe(activation: Nat64FallbackActivation): Nat64EgressObservation {
        val observedAt = clock()
        val prefix = normalizePublicNat64Prefix96(activation.prefix)
            ?: return failed(observedAt, "NAT64 /96 前缀无效")
        return try {
            val client = OkHttpClient.Builder()
                .dns(Nat64PrefixDns(prefix, systemLookup))
                .connectTimeout(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .readTimeout(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .callTimeout(CALL_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(false)
                .followRedirects(false)
                .protocols(listOf(Protocol.HTTP_1_1))
                .build()

            val trace = parseNat64Trace(get(client, CLOUDFLARE_TRACE_URL, MAX_TRACE_CHARS))
                ?: return failed(observedAt, "Cloudflare 出口回显格式无效")
            val asn = parseRipeOriginAsn(
                get(
                    client,
                    "$RIPE_NETWORK_INFO_URL${trace.publicIp}&sourceapp=github-direct",
                    MAX_RIPE_CHARS,
                ),
            ) ?: return failed(observedAt, "RIPE RIS 未返回出口 origin ASN")
            val holder = parseRipeAsHolder(
                get(
                    client,
                    "$RIPE_AS_OVERVIEW_URL$asn&sourceapp=github-direct",
                    MAX_RIPE_CHARS,
                ),
            ) ?: return failed(observedAt, "RIPEstat 未返回出口 ASN 运营主体")

            val expectedRegion = expectedNat64RegionCode(activation.expectedRegion)
            val mismatches = buildList {
                if (!asn.equals(activation.expectedAsn, ignoreCase = true)) {
                    add("ASN 不符：预期 ${activation.expectedAsn}，实测 $asn")
                }
                when {
                    expectedRegion == null -> add("预期地区必须包含两位 ISO 国家/地区代码")
                    trace.regionCode != expectedRegion ->
                        add("地区不符：预期 $expectedRegion，实测 ${trace.regionCode}")
                }
            }
            Nat64EgressObservation(
                verified = mismatches.isEmpty(),
                publicIp = trace.publicIp,
                asn = asn,
                operator = holder,
                region = trace.region,
                observedAt = observedAt,
                detail = if (mismatches.isEmpty()) {
                    "已通过指定 /96 实测 HTTPS 出口、BGP ASN 与地区"
                } else {
                    mismatches.joinToString("；")
                },
            )
        } catch (t: Throwable) {
            failed(
                observedAt,
                "${t.javaClass.simpleName}: ${t.message.orEmpty()}".take(MAX_DETAIL_CHARS),
            )
        }
    }

    private fun get(client: OkHttpClient, url: String, maxChars: Int): String {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", "GitHub-direct NAT64 verifier/1")
            .get()
            .build()
        client.newCall(request).execute().use { response ->
            check(response.code == 200) { "${response.request.url.host} HTTP ${response.code}" }
            val body = checkNotNull(response.body) { "empty response body" }
            return body.charStream().use { readBounded(it, maxChars) }
        }
    }

    private fun failed(observedAt: Long, detail: String) = Nat64EgressObservation(
        observedAt = observedAt,
        detail = detail.ifBlank { "NAT64 出口探测失败" }.take(MAX_DETAIL_CHARS),
    )

    companion object {
        private const val CLOUDFLARE_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
        private const val RIPE_NETWORK_INFO_URL =
            "https://stat.ripe.net/data/network-info/data.json?resource="
        private const val RIPE_AS_OVERVIEW_URL =
            "https://stat.ripe.net/data/as-overview/data.json?resource="
        private const val CONNECT_TIMEOUT_MS = 7_000L
        private const val READ_TIMEOUT_MS = 7_000L
        private const val CALL_TIMEOUT_MS = 9_000L
        private const val MAX_TRACE_CHARS = 16 * 1024
        private const val MAX_RIPE_CHARS = 64 * 1024
        private const val MAX_DETAIL_CHARS = 300
    }
}

private class Nat64PrefixDns(
    prefix: String,
    private val systemLookup: (String) -> List<InetAddress>,
) : Dns {
    private val prefixBytes = checkNotNull(
        IpAddresses.parseIpv6(prefix.substringBefore('/')),
    )

    override fun lookup(hostname: String): List<InetAddress> {
        val synthesized = systemLookup(hostname).asSequence()
            .map(InetAddress::getAddress)
            .filter { it.size == 4 && !IpAddresses.isBogonOrPoisoned(it) }
            .distinctBy { it.joinToString(":") }
            .take(MAX_SYNTHESIZED_ADDRESSES)
            .map { ipv4 ->
                val bytes = prefixBytes.copyOf()
                ipv4.copyInto(bytes, destinationOffset = 12)
                InetAddress.getByAddress(hostname, bytes)
            }
            .toList()
        if (synthesized.isEmpty()) {
            throw UnknownHostException("$hostname has no acceptable IPv4 address for NAT64")
        }
        return synthesized
    }

    companion object {
        private const val MAX_SYNTHESIZED_ADDRESSES = 4
    }
}

internal fun synthesizeNat64Address(prefix: String, ipv4: String): InetAddress? {
    val normalized = normalizePublicNat64Prefix96(prefix) ?: return null
    val prefixBytes = IpAddresses.parseIpv6(normalized.substringBefore('/')) ?: return null
    val ipv4Bytes = IpAddresses.parseIpv4(ipv4)
        ?.takeIf { !IpAddresses.isBogonOrPoisoned(it) }
        ?: return null
    ipv4Bytes.copyInto(prefixBytes, destinationOffset = 12)
    return InetAddress.getByAddress(prefixBytes)
}

internal fun parseNat64Trace(raw: String): Nat64Trace? {
    val values = raw.lineSequence()
        .map(String::trim)
        .filter { it.isNotEmpty() && '=' in it }
        .map { line -> line.substringBefore('=') to line.substringAfter('=') }
        .associate { (key, value) -> key.trim().lowercase(Locale.US) to value.trim() }
    val ip = values["ip"]?.takeIf { address ->
        IpAddresses.parseIpv4(address)?.let { !IpAddresses.isBogonOrPoisoned(it) } == true
    } ?: return null
    val loc = values["loc"]?.uppercase(Locale.US)
        ?.takeIf { it.matches(Regex("[A-Z]{2}")) }
        ?: return null
    val colo = values["colo"]?.uppercase(Locale.US)
        ?.takeIf { it.matches(Regex("[A-Z0-9]{3,4}")) }
        ?: return null
    val tls = values["tls"]?.takeIf { it.startsWith("TLSv") } ?: return null
    return Nat64Trace(ip, loc, colo, tls)
}

internal fun parseRipeOriginAsn(raw: String): String? = runCatching {
    val values = JSONObject(raw).optJSONObject("data")?.optJSONArray("asns") ?: return null
    val digits = values.opt(0)?.toString()?.uppercase(Locale.US)?.removePrefix("AS")
        ?: return null
    val number = digits.toLongOrNull()?.takeIf { it in 1..4_294_967_295L } ?: return null
    "AS$number"
}.getOrNull()

internal fun parseRipeAsHolder(raw: String): String? = runCatching {
    JSONObject(raw).optJSONObject("data")?.optString("holder")
        ?.trim()
        ?.take(120)
        ?.takeIf(String::isNotEmpty)
}.getOrNull()

internal fun expectedNat64RegionCode(raw: String): String? =
    Regex("(?<![A-Za-z])([A-Za-z]{2})(?![A-Za-z])")
        .find(raw)
        ?.groupValues
        ?.get(1)
        ?.uppercase(Locale.US)

private fun readBounded(reader: Reader, maxChars: Int): String {
    require(maxChars > 0)
    val result = StringBuilder(minOf(maxChars, 4096))
    val buffer = CharArray(2048)
    while (true) {
        val count = reader.read(buffer)
        if (count < 0) return result.toString()
        check(result.length + count <= maxChars) { "response exceeds $maxChars characters" }
        result.append(buffer, 0, count)
    }
}

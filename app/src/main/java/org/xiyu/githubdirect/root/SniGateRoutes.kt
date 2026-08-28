package org.xiyu.githubdirect.root

import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.data.Nat64FallbackActivation
import org.xiyu.githubdirect.core.data.normalizePublicNat64Prefix96
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.routing.CandidateSource
import org.xiyu.githubdirect.core.routing.EndpointCandidate
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference

enum class TlsTerminationMethod {
    /** RFC 9849 ECH；没有可用 ECHConfig 时 sni-gate 必须 fail-close。 */
    ECH,

    /** 不发送上游 SNI，但仍按原始域名验证公开证书。 */
    NO_SNI,
}

data class TlsTerminationRoute(
    val domain: String,
    val includeSubdomains: Boolean,
    val method: TlsTerminationMethod,
    val localAddress: InetSocketAddress = InetSocketAddress(
        InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)),
        SniGateRuntime.LOCAL_PORT,
    ),
    /** NO_SNI/ECH 路由的当前已验证上游 IP；不从规则资产写死。 */
    val upstreamAddress: String? = null,
    /** 固定 ECH 上游；为空时反射每次连接的原始 SNI。 */
    val upstreamHost: String? = null,
    /** 固定 HTTPS RR 名称；为空时查询每次连接的真实内层域名。 */
    val echConfigDomain: String? = null,
    /** 用户显式选择的第三方公共 NAT64 /96；仅 ECH + 固定 IPv4 上游可用。 */
    val nat64Prefix: String? = null,
    val nat64Operator: String? = null,
    val nat64ExpectedAsn: String? = null,
    val nat64ExpectedRegion: String? = null,
)

data class TlsTerminationPlan(
    val generation: Long,
    val routes: List<TlsTerminationRoute>,
) {
    fun routeFor(rawDomain: String?): TlsTerminationRoute? {
        val domain = rawDomain?.let(DnsNames::normalize) ?: return null
        routes.firstOrNull { it.domain == domain }?.let { return it }
        return routes.asSequence()
            .filter { it.includeSubdomains && domain.endsWith(".${it.domain}") }
            .maxByOrNull { it.domain.length }
    }

    companion object {
        val EMPTY = TlsTerminationPlan(0L, emptyList())
    }
}

/**
 * 只把两类连接交给本机 TLS 终止器：
 * - 已经通过系统链 + 原主机名校验的 NO_SNI 候选；显式后缀规则还会在发布前
 *   对代表子域做一次本机端到端握手，成功后才允许动态子域命中；
 * - 当前启用规则的目标原生 HTTPS/ECH 记录；没有可用 ECHConfig 时 fail-close。
 *
 * 这里只生成“待验证计划”；SniGateRouteVerifier 必须完成真实 ECH/证书握手后，
 * SniGateRuntime 才会发布对应路由。ECH 查询和上游拨号都反射每次真实 SNI，不把
 * 非 Cloudflare 平台硬转发到 Cloudflare 公共边缘。
 */
object TlsTerminationPlanner {
    fun plan(
        snapshot: RouteSnapshot,
        now: Long = System.currentTimeMillis(),
        enabledRelayDomains: Set<String> = emptySet(),
        enabledRelaySuffixes: Set<String> = emptySet(),
        enabledEchConfigDomains: Map<String, String> = emptyMap(),
        nat64FallbackEligibleDomains: Set<String> = emptySet(),
        nat64Fallback: Nat64FallbackActivation? = null,
    ): TlsTerminationPlan {
        val managedDomains = enabledRelayDomains.asSequence()
            .mapNotNull(DnsNames::normalize)
            .toSet()
        val managedSuffixes = enabledRelaySuffixes.asSequence()
            .mapNotNull(DnsNames::normalize)
            .filter(managedDomains::contains)
            .toSet()
        val managedEchConfigDomains = enabledEchConfigDomains.entries.asSequence()
            .mapNotNull { (rawDomain, rawEchDomain) ->
                val domain = DnsNames.normalize(rawDomain) ?: return@mapNotNull null
                val echDomain = DnsNames.normalize(rawEchDomain) ?: return@mapNotNull null
                if (domain in managedDomains) domain to echDomain else null
            }
            .toMap(LinkedHashMap())
        val managedNat64Domains = nat64FallbackEligibleDomains.asSequence()
            .mapNotNull(DnsNames::normalize)
            .filter(managedDomains::contains)
            .filter(managedEchConfigDomains::containsKey)
            .toSet()
        val routes = ArrayList<TlsTerminationRoute>()
        for (endpoint in snapshot.plans.values.sortedBy { it.domain }) {
            val domain = DnsNames.normalize(endpoint.domain) ?: continue
            val usableCandidates = endpoint.candidates.asSequence()
                .filter { candidate ->
                    candidate.usable(now) && IpAddresses.parseIpAddress(candidate.address) != null
                }
                .sortedWith(
                    compareBy<EndpointCandidate> {
                        if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE
                    }.thenBy { it.address },
                )
                .toList()
            val echCandidates = endpoint.candidates.asSequence()
                .filter { candidate -> candidate.eligibleForStrictEchPreflight(now) }
                .sortedWith(
                    compareBy<EndpointCandidate> { if (it.usable(now)) 0 else 1 }
                        // IPv4 remains the universal baseline. A previously proven usable IPv6
                        // candidate still wins above; otherwise ECH preflight can fall back on the
                        // current trusted IPv4 observation instead of an unroutable stale AAAA.
                        .thenBy { if (IpAddresses.parseIpv4(it.address) != null) 0 else 1 }
                        .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
                        .thenBy { it.address },
                )
                .toList()
            val noSni = usableCandidates.firstOrNull(EndpointCandidate::noSniCapable)
            val useNat64 = nat64Fallback != null && domain in managedNat64Domains
            if (noSni != null && !useNat64) {
                routes += TlsTerminationRoute(
                    domain = domain,
                    // 后缀边界来自当前启用规则，不从观测 SNI 扩张。SniGateRouteVerifier
                    // 还会验证一个代表子域；失败时整条后缀路由不会发布。
                    includeSubdomains = domain in managedSuffixes,
                    method = TlsTerminationMethod.NO_SNI,
                    upstreamAddress = noSni.address,
                )
                continue
            }
            val echConfigDomain = managedEchConfigDomains[domain]
            if (echConfigDomain != null) {
                // 规则只声明 ECH 公共配置名。固定拨号地址必须来自当前目标自己的严格 TLS
                // 候选；sni-gate 启动后还会以真实内层域名完成 ECH + 公开证书预检，失败
                // 的路由不会发布，因此这里不需要硬编码平台域名或 CDN IP。
                val upstream = if (useNat64) {
                    // NAT64 合成只接受当前目标自己的可信 IPv4 候选；本机 DNS 污染、AAAA
                    // 和其他平台地址都不能进入这条第三方数据面。
                    echCandidates.firstOrNull { IpAddresses.parseIpv4(it.address) != null }
                } else {
                    echCandidates.firstOrNull()
                } ?: continue
                routes += TlsTerminationRoute(
                    domain = domain,
                    includeSubdomains = domain in managedSuffixes,
                    method = TlsTerminationMethod.ECH,
                    upstreamAddress = upstream.address,
                    echConfigDomain = echConfigDomain,
                    nat64Prefix = nat64Fallback?.prefix.takeIf { useNat64 },
                    nat64Operator = nat64Fallback?.operator.takeIf { useNat64 },
                    nat64ExpectedAsn = nat64Fallback?.expectedAsn.takeIf { useNat64 },
                    nat64ExpectedRegion = nat64Fallback?.expectedRegion.takeIf { useNat64 },
                )
                continue
            }
            // 未声明公共配置名的规则保留目标原生 ECH：省略固定 upstream/echConfigDomain，
            // sni-gate 会按每次真实内层 SNI 查询目标自身 HTTPS RR并严格 fail-close。
            if (domain in managedDomains) {
                routes += TlsTerminationRoute(
                    domain = domain,
                    // 只对已启用 profile 显式声明的一方后缀发布动态匹配。
                    includeSubdomains = domain in managedSuffixes,
                    method = TlsTerminationMethod.ECH,
                )
            }
        }
        return TlsTerminationPlan(snapshot.generation, routes.distinct())
    }

    fun caBootstrapPlan(): TlsTerminationPlan = TlsTerminationPlan(
        generation = 0L,
        routes = listOf(
            TlsTerminationRoute(
                domain = "ca-init.invalid",
                includeSubdomains = false,
                method = TlsTerminationMethod.ECH,
            ),
        ),
    )
}

/**
 * 明文 SNI/分片探测失败不能提前否定 ECH：这两条路径的可见握手特征不同。只有来自
 * 可信解析/受控候选系统且仍新鲜的公网地址可以进入 ECH 重新资格验证；本机 DNS、独立
 * 观察器和社区地址即使看似可达也绝不进入。最终发布仍要求真实 ECH 接受与目标证书通过。
 */
private fun EndpointCandidate.eligibleForStrictEchPreflight(now: Long): Boolean {
    if (expiresAt > 0L && now >= expiresAt) return false
    val raw = IpAddresses.parseIpAddress(address) ?: return false
    if (IpAddresses.isBogonOrPoisoned(raw)) return false
    return source == CandidateSource.WIRE_DOH ||
        source == CandidateSource.CANDIDATE_POOL ||
        source == CandidateSource.BUNDLED ||
        source == CandidateSource.GITHUB_META
}

/** 运行时发布点；关闭/故障时原子清空，透明监听器立即回到不解密路径。 */
object TlsTerminationRouteRegistry {
    private val active = AtomicReference(TlsTerminationPlan.EMPTY)

    fun publish(plan: TlsTerminationPlan) {
        active.set(plan)
    }

    fun clear() {
        active.set(TlsTerminationPlan.EMPTY)
    }

    fun routeFor(domain: String?): TlsTerminationRoute? = active.get().routeFor(domain)

    fun snapshot(): TlsTerminationPlan = active.get()
}

data class SniGateConfigPaths(
    val caCert: String,
    val caKey: String,
    val certStore: String,
)

/** 纯函数配置渲染器，便于单测约束 fail-close、证书路径和域名/IP 转义。 */
object SniGateConfigRenderer {
    fun render(plan: TlsTerminationPlan, paths: SniGateConfigPaths): String {
        val noSniRoutes = plan.routes
            .filter { it.method == TlsTerminationMethod.NO_SNI && it.upstreamAddress != null }
            .distinctBy { it.domain to it.includeSubdomains }
            // sni-gate 按 exact > wildcard > suffix 匹配；这里仍显式把专用精确路由写在
            // 通用后缀路由前，便于审计并兼容旧版本实现。
            .sortedWith(compareBy<TlsTerminationRoute> { it.includeSubdomains }.thenBy { it.domain })
        val echGroups = plan.routes
            .filter { it.method == TlsTerminationMethod.ECH }
            .groupBy {
                EchRouteProfile(
                    upstreamAddress = it.upstreamAddress,
                    upstreamHost = it.upstreamHost,
                    echConfigDomain = it.echConfigDomain,
                    nat64Prefix = it.nat64Prefix,
                )
            }

        return buildString {
            appendLine("[global]")
            appendLine("log = \"warn\"")
            appendLine("resolver = \"@clean\"")
            appendLine("address_family = \"dual\"")
            appendLine("connect_timeout = \"3s\"")
            appendLine("unmatched = \"close\"")
            appendLine()
            appendLine("[global.ech]")
            appendLine("mode = \"doh\"")
            appendLine("require_ech = true")
            appendLine("max_retries = 2")
            appendLine("ech_refresh = \"1h\"")
            appendLine()
            appendLine("[global.http2]")
            appendLine("enabled = true")
            appendLine()
            appendLine("[resolvers.clean]")
            appendLine("endpoint = \"https://doh.cleanbrowsing.org/doh/security-filter/\"")
            appendLine("upstream = \"185.228.168.9:443\"")
            appendLine("address_family = \"dual\"")
            appendLine("connect_timeout = \"3s\"")
            appendLine()
            appendLine("[ca]")
            appendLine("cert_path = \"${toml(paths.caCert)}\"")
            appendLine("key_path = \"${toml(paths.caKey)}\"")
            appendLine("common_name = \"GitHub-direct Per-Device Local CA\"")
            appendLine("organization = \"GitHub-direct\"")
            appendLine("country = \"\"")
            appendLine("leaf_validity_days = 90")
            appendLine("install_to_system_root = false")
            appendLine()
            appendLine("[store]")
            appendLine("enabled = true")
            appendLine("dir = \"${toml(paths.certStore)}\"")
            appendLine("renew_margin_days = 15")
            appendLine()
            appendLine("[cache]")
            appendLine("capacity = 2048")
            appendLine("ttl_secs = 21600")
            appendLine()
            appendLine("[psl]")
            appendLine("source = \"embedded\"")
            appendLine()
            appendLine("[[listener]]")
            appendLine("addr = \"127.0.0.1:${SniGateRuntime.LOCAL_PORT}\"")
            appendLine("connect_timeout = \"3s\"")
            appendLine()

            noSniRoutes.forEachIndexed { index, route ->
                appendLine("  [[listener.route]]")
                appendLine("  name = \"no-sni-$index\"")
                appendLine("  type = \"tls\"")
                val pattern = if (route.includeSubdomains) ".${route.domain}" else route.domain
                appendLine("  match_sni = [\"${toml(pattern)}\"]")
                appendLine("  upstream = \"${toml(upstream(route.upstreamAddress!!))}\"")
                appendLine("  override_sni = \"\"")
                appendLine("  fail = \"close\"")
                appendLine()
            }

            echGroups.entries.forEachIndexed { index, (profile, routes) ->
                val upstreamAddress = profile.upstreamAddress
                val upstreamHost = profile.upstreamHost
                val echConfigDomain = profile.echConfigDomain
                val nat64Prefix = profile.nat64Prefix
                appendLine("  [[listener.route]]")
                appendLine("  name = \"strict-ech-$index\"")
                appendLine("  type = \"ech\"")
                append("  match_sni = [")
                append(
                    routes.asSequence()
                        .map { if (it.includeSubdomains) ".${it.domain}" else it.domain }
                        .distinct()
                        .sorted()
                        .joinToString(", ") { "\"${toml(it)}\"" },
                )
                appendLine("]")
                if (upstreamAddress != null) {
                    requireNotNull(IpAddresses.parseIpAddress(upstreamAddress))
                    appendLine("  upstream = \"${toml(upstream(upstreamAddress))}\"")
                } else if (upstreamHost != null) {
                    val normalized = requireNotNull(DnsNames.normalize(upstreamHost))
                    appendLine("  upstream = \"${toml(normalized)}:443\"")
                }
                if (nat64Prefix != null) {
                    requireNotNull(IpAddresses.parseIpv4(upstreamAddress)) {
                        "NAT64 routes require a fixed IPv4 upstream"
                    }
                    val normalized = requireNotNull(normalizePublicNat64Prefix96(nat64Prefix))
                    appendLine("  # NON_STRICT_NAT64: third-party data plane; runtime preflight required")
                    appendLine("  address_family = \"ipv4\"")
                    appendLine("  nat64_prefix = \"${toml(normalized)}\"")
                }
                appendLine("  fail = \"close\"")
                appendLine()
                appendLine("    [listener.route.ech]")
                appendLine("    mode = \"doh\"")
                if (echConfigDomain != null) {
                    val normalized = requireNotNull(DnsNames.normalize(echConfigDomain))
                    appendLine("    ech_domain = \"${toml(normalized)}\"")
                }
                appendLine("    require_ech = true")
                appendLine()
            }
        }
    }

    private data class EchRouteProfile(
        val upstreamAddress: String?,
        val upstreamHost: String?,
        val echConfigDomain: String?,
        val nat64Prefix: String?,
    )

    private fun upstream(address: String): String =
        if (IpAddresses.parseIpv6(address) != null) "[$address]:443" else "$address:443"

    private fun toml(value: String): String {
        require(value.none { it == '\u0000' || it == '\r' || it == '\n' })
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
    }
}

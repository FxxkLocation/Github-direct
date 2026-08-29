package org.xiyu.githubdirect.data

import android.content.Context
import android.util.Log
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.OkHttpWireDohTransport
import org.xiyu.githubdirect.core.dns.PlainDnsClient
import org.xiyu.githubdirect.core.dns.SelectiveDnsEngine
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.VirtualIpPool
import org.xiyu.githubdirect.core.rules.HostsProvider
import org.xiyu.githubdirect.core.rules.IndexedRule
import org.xiyu.githubdirect.core.rules.MatcherIndex
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.SuffixMatcher
import org.xiyu.githubdirect.core.rules.TransportPolicy
import org.xiyu.githubdirect.core.routing.AdaptiveRouteCatalog
import org.xiyu.githubdirect.core.routing.AdaptiveRouteTarget
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.core.routing.RouteSnapshotCodec
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.vpn.VpnNetworkBinder
import java.util.concurrent.ConcurrentHashMap

/**
 * 引擎装配（进程内静态单例；VPN 服务进程与 Xposed 目标进程各自初始化一份）。
 *
 * - 规则目录：assets/rules/profiles.json → RuleCatalog → MatcherIndex → RuleRegistry
 * - 组件：EndpointResolver / EndpointCache / VirtualIpPool / RelayIpTable / NetworkBinder
 * - providers：VPN 与 Root 透明模式都启动（withProviders=true）；GitHub 依赖 github-hosts 探活 IP
 */
object DirectEngine {

    private val TAG = "DirectEngine"

    @Volatile
    private var initialized = false

    @Volatile
    private var registry: RuleRegistry? = null

    @Volatile
    private var resolver: EndpointResolver? = null

    @Volatile
    private var cache: EndpointCache? = null

    @Volatile
    private var pool: VirtualIpPool? = null

    @Volatile
    private var relayTable: RelayIpTable? = null

    @Volatile
    private var dnsEngine: SelectiveDnsEngine? = null

    @Volatile
    private var binder: NetworkBinder? = null

    @Volatile
    private var settings: SettingsStore? = null

    @Volatile
    private var profiles: Map<String, ServiceProfile> = emptyMap()

    @Volatile
    private var routeSnapshot: RouteSnapshot = RouteSnapshot.EMPTY

    @Volatile
    private var engineContext: Context? = null

    @Volatile
    private var settingsSubscription: java.io.Closeable? = null

    @Volatile
    private var providersMode = false

    private data class VerifiedNat64DnsScope(
        val exactDomains: Set<String>,
        val suffixDomains: Set<String>,
    ) {
        fun contains(domain: String): Boolean =
            domain in exactDomains || suffixDomains.any { root ->
                domain == root || domain.endsWith(".$root")
            }

        companion object {
            val EMPTY = VerifiedNat64DnsScope(emptySet(), emptySet())
        }
    }

    /** 只由同进程 SNI 运行时在真实出口及 TLS 路由验证通过并发布后更新。 */
    @Volatile
    private var verifiedNat64DnsScope = VerifiedNat64DnsScope.EMPTY

    /** Root IPv4/vIP 规则安装成功前保持 false，避免 AAAA 提前回落到尚未就绪的数据面。 */
    @Volatile
    private var verifiedNat64DnsDataPlaneReady = false

    private val providers = ConcurrentHashMap<String, HostsProvider>()

    /**
     * 幂等初始化。withProviders=true 时允许从“仅核心”升级为“核心 + providers”。
     * 解决 UI 先 ensureInit(false)、随后 VPN ensureInit(true) 时 provider 永远不启动的问题。
     *
     * @param settingsOverride Xposed 目标进程应传入远程 SharedPreferences 包装的 SettingsStore，
     * 否则 createPackageContext 读不到模块自己的配置。资产始终从传入的 context 读取。
     */
    @JvmStatic
    @JvmOverloads
    fun ensureInit(
        context: Context,
        withProviders: Boolean,
        settingsOverride: SettingsStore? = null,
    ): Boolean {
        if (initialized) {
            if (withProviders && !providersMode) {
                synchronized(this) {
                    if (initialized && !providersMode) {
                        providersMode = true
                        reconcileProviders()
                    }
                }
            }
            return true
        }
        synchronized(this) {
            if (initialized) {
                if (withProviders && !providersMode) {
                    providersMode = true
                    reconcileProviders()
                }
                return true
            }
            try {
                val appCtx = context.applicationContext ?: context
                val settings = settingsOverride ?: AndroidSettingsStore(appCtx)
                val json = loadProfilesJson(context)
                val profiles = RuleCatalog.load(json)

                val index = MatcherIndex()
                for (p in profiles.values) {
                    for (r in p.domains) {
                        index.add(IndexedRule(r, p.id, p.priority))
                    }
                }
                index.build()

                val binder = VpnNetworkBinder(appCtx)
                val reg = RuleRegistry(settings, profiles, index)
                val wireDoh = OkHttpWireDohTransport.createClient(binder)
                val resolver = EndpointResolver(binder, wireClient = wireDoh)
                val cache = EndpointCache()
                val pool = VirtualIpPool()
                val relayTable = RelayIpTable()
                val initialTargets = AdaptiveRouteCatalog.fromProfiles(profiles.values, reg::isEnabled)
                val initialRoutes = AdaptiveRouteCatalog.filterSnapshot(
                    loadRouteSnapshot(context, settings),
                    initialTargets,
                )
                relayTable.update(initialRoutes.relayHosts())
                registry = reg
                this.resolver = resolver
                this.cache = cache
                this.pool = pool
                this.relayTable = relayTable
                routeSnapshot = initialRoutes
                engineContext = appCtx
                // 共享 DNS 引擎单例：VPN 服务与 Root 透明后端复用同一实例（构造一次）
                dnsEngine = SelectiveDnsEngine(
                    reg, resolver, cache, pool, relayTable,
                    wireDoh, PlainDnsClient(),
                    suppressIpv6ForVerifiedNat64 = ::shouldSuppressIpv6ForVerifiedNat64,
                )
                this.binder = binder
                this.settings = settings
                this.profiles = profiles
                settingsSubscription = settings.addChangeListener { key ->
                    if (key == ROUTE_SNAPSHOT_KEY || key == ROUTE_GENERATION_KEY) {
                        reloadRemoteRouteSnapshot()
                    } else if (key == ADAPTIVE_CANDIDATES_KEY && providersMode) {
                        reconcileProviders()
                    }
                }
                providersMode = withProviders
                // 任意服务状态变化后统一 reconcile；批量开关只触发一次。
                reg.addChangeListener { _, _ ->
                    if (providersMode) {
                        reconcileProviders()
                        (providers[ADAPTIVE_PROVIDER_ID] as? GithubHostsProvider)?.requestRefresh()
                    }
                }
                initialized = true
                Log.i(TAG, "引擎初始化完成: ${profiles.size} 个 profile")
                if (withProviders) reconcileProviders()
                return true
            } catch (e: Exception) {
                Log.w(TAG, "引擎初始化失败: ${e.message}")
                initialized = false
                return false
            }
        }
    }

    private fun loadProfilesJson(context: Context): String {
        return context.assets.open("rules/profiles.json")
            .bufferedReader(Charsets.UTF_8)
            .use { it.readText() }
    }

    /** 兼容旧调用名；实际执行完整 provider 状态协调。 */
    fun startProviders() {
        reconcileProviders()
    }

    /** 前台服务的 REFRESH 动作；遵守候选年龄和退避策略。 */
    @JvmStatic
    fun refreshProviders(): Int = updateProviders(forceProbe = false)

    /** 前台服务的 REPROBE 动作；强制重探候选，但仍受每域/全局并发与 deadline 限制。 */
    @JvmStatic
    fun reprobeProviders(): Int = updateProviders(forceProbe = true)

    /**
     * Root 规则安装、可选 TLS 路由和远程 Hook 发布必须看到同一个候选 generation。
     * provider 不存在时直接执行，避免把非 Root/Xposed-only 初始化变成硬依赖。
     */
    fun <T> withRouteSnapshotBarrier(action: () -> T): T {
        val provider = providers[ADAPTIVE_PROVIDER_ID] as? GithubHostsProvider
        return provider?.withRefreshBarrier(action) ?: action()
    }

    private fun updateProviders(forceProbe: Boolean): Int {
        var refreshed = 0
        for (provider in providers.values) {
            try {
                val result = if (forceProbe) provider.reprobe() else provider.fetch()
                if (result != null) refreshed++
            } catch (t: Throwable) {
                Log.w(TAG, "provider ${if (forceProbe) "重探" else "刷新"}失败: ${t.message}")
            }
        }
        return refreshed
    }

    /**
     * 使 provider 运行集合与当前启用 profile 声明完全一致：
     * - 启用新服务：启动缺失 provider
     * - 禁用最后一个依赖该 provider 的服务：停止 provider
     */
    @Synchronized
    fun reconcileProviders() {
        if (!providersMode) return
        val reg = registry ?: return
        val t = relayTable ?: return
        val b = binder ?: return
        val s = settings ?: return

        val targets = adaptiveRouteTargets(reg)
        val required = LinkedHashMap<String, org.xiyu.githubdirect.core.rules.HostsProviderSpec>()
        for (p in profiles.values) {
            if (!reg.isEnabled(p.id)) continue
            for (spec in p.providers) required.putIfAbsent(spec.providerId, spec)
        }
        // github-hosts 保留旧 ID 以兼容已有设置/测试，实际刷新器已服务所有启用 profile。
        required.remove(ADAPTIVE_PROVIDER_ID)
        if (s.isAdaptiveCandidatesEnabled() && targets.isNotEmpty()) {
            val declared = profiles.values.asSequence()
                .flatMap { it.providers.asSequence() }
                .firstOrNull { it.providerId == ADAPTIVE_PROVIDER_ID }
            required[ADAPTIVE_PROVIDER_ID] = declared
                ?: org.xiyu.githubdirect.core.rules.HostsProviderSpec(ADAPTIVE_PROVIDER_ID, 6, 443)
        }

        val runningIds = providers.keys.toList()
        for (id in runningIds) {
            if (required.containsKey(id)) continue
            val provider = providers.remove(id) ?: continue
            try {
                provider.stop()
            } catch (_: Exception) {
            }
        }

        for ((id, spec) in required) {
            if (providers.containsKey(id)) continue
            val provider: HostsProvider? = when (id) {
                ADAPTIVE_PROVIDER_ID -> GithubHostsProvider(
                    spec = spec,
                    context = engineContext,
                    onSnapshot = { publishRouteSnapshot(it) },
                    targetsProvider = { adaptiveRouteTargets(reg) },
                )
                else -> null
            }
            if (provider == null) continue
            val existing = providers.putIfAbsent(id, provider)
            if (existing != null) continue
            try {
                provider.start(s, b, t)
            } catch (e: Exception) {
                providers.remove(id, provider)
                Log.w(TAG, "provider $id 启动失败: ${e.message}")
            }
        }

        if (targets.isEmpty()) publishEmptyRouteSnapshotIfNeeded()
    }

    @JvmStatic
    fun stopProviders() {
        // VPN/provider backend 已退出；下次 ensureInit(..., true) 必须允许重新升级并启动。
        providersMode = false
        for ((id, p) in providers) {
            try {
                p.stop()
            } catch (_: Exception) {
            }
        }
        providers.clear()
    }

    @JvmStatic
    fun isInitialized(): Boolean = initialized

    @JvmStatic
    fun registry(): RuleRegistry? = registry

    @JvmStatic
    fun resolver(): EndpointResolver? = resolver

    @JvmStatic
    fun cache(): EndpointCache? = cache

    @JvmStatic
    fun pool(): VirtualIpPool? = pool

    @JvmStatic
    fun relayTable(): RelayIpTable? = relayTable

    @JvmStatic
    fun dnsEngine(): SelectiveDnsEngine? = dnsEngine

    @JvmStatic
    fun binder(): NetworkBinder? = binder

    @JvmStatic
    fun settings(): SettingsStore? = settings

    @JvmStatic
    fun profiles(): Map<String, ServiceProfile> = profiles

    /**
     * 当前已启用服务显式声明的一方后缀边界。这里只返回规则资产中的后缀，不从页面内容
     * 或任意观测 SNI 推断归属；TLS 终止器还会再次与自身允许策略求交集。
     */
    @JvmStatic
    fun enabledRelaySuffixes(): Set<String> {
        val reg = registry ?: return emptySet()
        return profiles.values.asSequence()
            .filter { reg.isEnabled(it.id) }
            .flatMap(ServiceProfile::domains)
            .filter { rule ->
                rule.transport == TransportPolicy.TLS_FRAGMENT_RELAY ||
                    rule.transport == TransportPolicy.DIRECT_IP ||
                    rule.transport == TransportPolicy.CLEAN_DNS
            }
            .mapNotNull { (it.matcher as? SuffixMatcher)?.suffix?.removePrefix(".") }
            .mapNotNull(DnsNames::normalize)
            .filter { domain -> isRelayTransport(reg.match(domain)?.policy?.transport) }
            .toCollection(LinkedHashSet())
    }

    /**
     * 当前启用 profile 明确声明的全部路由根（精确 + 后缀 apex）。TLS 终止器只在这个集合内
     * 做运行时 ECH/证书探测；平台/CDN 能力不再由代码内平台域名表判定。
     */
    @JvmStatic
    fun enabledRelayDomains(): Set<String> {
        val reg = registry ?: return emptySet()
        return profiles.values.asSequence()
            .filter { reg.isEnabled(it.id) }
            .flatMap(ServiceProfile::domains)
            .filter { rule ->
                rule.transport == TransportPolicy.TLS_FRAGMENT_RELAY ||
                    rule.transport == TransportPolicy.DIRECT_IP ||
                    rule.transport == TransportPolicy.CLEAN_DNS
            }
            .mapNotNull { rule ->
                when (val matcher = rule.matcher) {
                    is ExactMatcher -> matcher.domain
                    is SuffixMatcher -> matcher.suffix.removePrefix(".")
                    else -> null
                }
            }
            .mapNotNull(DnsNames::normalize)
            .filter { domain -> isRelayTransport(reg.match(domain)?.policy?.transport) }
            .toCollection(LinkedHashSet())
    }

    /**
     * 规则资产声明的 ECH 公共配置名。这里只输出当前启用且仍由当前匹配策略接管的域名根；
     * 固定上游地址不属于规则资产，必须由当前 RouteSnapshot 的严格候选提供并再次预检。
     */
    @JvmStatic
    fun enabledEchConfigDomains(): Map<String, String> {
        val reg = registry ?: return emptyMap()
        val result = LinkedHashMap<String, String>()
        profiles.values.asSequence()
            .filter { reg.isEnabled(it.id) }
            .flatMap(ServiceProfile::domains)
            .forEach { rule ->
                val echDomain = rule.echConfigDomain?.let(DnsNames::normalize) ?: return@forEach
                val domain = when (val matcher = rule.matcher) {
                    is ExactMatcher -> matcher.domain
                    is SuffixMatcher -> matcher.suffix.removePrefix(".")
                    else -> null
                }?.let(DnsNames::normalize) ?: return@forEach
                if (isRelayTransport(reg.match(domain)?.policy?.transport)) {
                    result.putIfAbsent(domain, echDomain)
                }
            }
        return result
    }

    /**
     * 只返回规则资产明确授权的 NAT64 根。资格跟随当前启用 profile 与最终匹配策略，
     * 转发器中没有 OpenAI 域名常量，也不会把其他 ECH 平台顺带送入第三方数据面。
     */
    @JvmStatic
    fun enabledNat64FallbackDomains(): Set<String> {
        val reg = registry ?: return emptySet()
        return profiles.values.asSequence()
            .filter { reg.isEnabled(it.id) }
            .flatMap(ServiceProfile::domains)
            .filter { it.nat64FallbackEligible && it.echConfigDomain != null }
            .mapNotNull { rule ->
                when (val matcher = rule.matcher) {
                    is ExactMatcher -> matcher.domain
                    is SuffixMatcher -> matcher.suffix.removePrefix(".")
                    else -> null
                }
            }
            .mapNotNull(DnsNames::normalize)
            .filter { domain -> isRelayTransport(reg.match(domain)?.policy?.transport) }
            .toCollection(LinkedHashSet())
    }

    /**
     * 发布已实际验证的 NAT64 DNS 边界。精确和后缀语义分别保留，禁止把单个精确路由
     * 意外扩大为整个平台；所有输入再次规范化后以不可变快照原子替换。
     */
    @JvmStatic
    fun publishVerifiedNat64DnsScope(
        exactDomains: Collection<String>,
        suffixDomains: Collection<String>,
    ) {
        verifiedNat64DnsScope = VerifiedNat64DnsScope(
            exactDomains = exactDomains.mapNotNull(DnsNames::normalize).toSet(),
            suffixDomains = suffixDomains.mapNotNull(DnsNames::normalize).toSet(),
        )
    }

    /** 先恢复 AAAA 默认行为，再由 Root 运行时清空本机 TLS 路由。 */
    @JvmStatic
    fun clearVerifiedNat64DnsScope() {
        verifiedNat64DnsScope = VerifiedNat64DnsScope.EMPTY
        verifiedNat64DnsDataPlaneReady = false
    }

    /** Root 启动/刷新事务完成后才开放 DNS 回落；事务开始或失败时恢复原生 AAAA。 */
    @JvmStatic
    fun setVerifiedNat64DnsDataPlaneReady(ready: Boolean) {
        verifiedNat64DnsDataPlaneReady = ready
    }

    private fun shouldSuppressIpv6ForVerifiedNat64(rawDomain: String): Boolean {
        if (!verifiedNat64DnsDataPlaneReady) return false
        val domain = DnsNames.normalize(rawDomain) ?: return false
        return verifiedNat64DnsScope.contains(domain)
    }

    private fun isRelayTransport(transport: TransportPolicy?): Boolean = when (transport) {
        TransportPolicy.TLS_FRAGMENT_RELAY,
        TransportPolicy.DIRECT_IP,
        TransportPolicy.CLEAN_DNS,
        -> true
        else -> false
    }

    @JvmStatic
    fun routeSnapshot(): RouteSnapshot = routeSnapshot

    /** Root 真实 IP 入口只对当前启用规则中的可路由域应用候选/分片。 */
    @JvmStatic
    fun isTrustedRelayDomain(rawDomain: String?): Boolean {
        val domain = rawDomain?.let(DnsNames::normalize) ?: return false
        return when (registry?.match(domain)?.policy?.transport) {
            TransportPolicy.TLS_FRAGMENT_RELAY,
            TransportPolicy.DIRECT_IP,
            TransportPolicy.CLEAN_DNS,
            -> true
            else -> false
        }
    }

    /** UI/前台服务使用的显式降级原因；只读内存状态，不做网络 I/O。 */
    @JvmStatic
    fun routeDegradationReason(now: Long = System.currentTimeMillis()): String {
        if (settings?.isAdaptiveCandidatesEnabled() == false) {
            return "adaptive_candidates 已关闭；仅使用当前安全快照，不刷新或竞速新候选"
        }
        val snapshot = routeSnapshot
        if (snapshot.plans.isEmpty()) {
            return "没有可用的已启用平台安全路由快照"
        }
        val usable = snapshot.plans.values.sumOf { plan ->
            plan.candidates.count { candidate -> candidate.usable(now) }
        }
        if (usable == 0) {
            val diagnostics = snapshot.plans.values.asSequence()
                .flatMap { plan ->
                    plan.candidates.asSequence()
                        .filter { candidate -> candidate.lastError.isNotBlank() }
                        .map { candidate -> "${plan.domain}@${candidate.address}: ${candidate.lastError}" }
                }
                .distinct()
                .take(3)
                .toList()
            return buildString {
                append("所有平台候选均不可用、已过期或处于退避；连接将保护性失败/透传")
                if (diagnostics.isNotEmpty()) append("；最近探测：${diagnostics.joinToString(" | ")}")
            }.take(780)
        }
        if (snapshot.expiresAt > 0L && now >= snapshot.expiresAt) {
            return "平台路由快照已过期；刷新源当前不可达"
        }
        return (providers[ADAPTIVE_PROVIDER_ID] as? GithubHostsProvider)
            ?.refreshHealth()?.degradationReason.orEmpty()
    }

    /**
     * TCP 中继的被动健康反馈。只改变已存在候选，绝不把运行时观察到的任意地址提升为上游。
     *
     * 直接 TLS 失败会先降级为分片能力；分片也失败时按 1/5/30 分钟退避，连续三次失败
     * 标记为不可用，等待下一次主动探测恢复。没有状态变化的成功连接不触发持久化写入。
     */
    @JvmStatic
    @Synchronized
    fun reportRouteOutcome(domain: String, address: String, success: Boolean, fragmented: Boolean) {
        val current = routeSnapshot
        val matched = current.planFor(domain) ?: return
        val now = System.currentTimeMillis()
        var changed = false
        var persist = false
        val updatedCandidates = matched.candidates.map { candidate ->
            if (candidate.address != address || candidate.interceptOnly) return@map candidate

            val updated = if (success) {
                val capability = if (fragmented) {
                    RouteCapability.FRAGMENTED_TLS
                } else {
                    RouteCapability.DIRECT_TLS
                }
                candidate.copy(
                    capability = capability,
                    failures = 0,
                    backoffUntil = 0,
                    lastError = "",
                )
            } else if (!fragmented && candidate.capability == RouteCapability.DIRECT_TLS) {
                // 直接握手失败不淘汰该 IP，先让同一连接尝试已验证安全的 record 分片。
                candidate.copy(
                    capability = RouteCapability.FRAGMENTED_TLS,
                    failures = (candidate.failures + 1).coerceAtMost(MAX_ROUTE_FAILURES),
                    backoffUntil = 0,
                    lastError = "direct relay handshake failed",
                )
            } else {
                val failures = (candidate.failures + 1).coerceAtMost(MAX_ROUTE_FAILURES)
                candidate.copy(
                    capability = if (failures >= ROUTE_UNUSABLE_AFTER) {
                        RouteCapability.UNUSABLE
                    } else {
                        candidate.capability
                    },
                    failures = failures,
                    backoffUntil = now + routeBackoffMs(failures),
                    lastError = if (fragmented) {
                        "fragmented relay handshake failed"
                    } else {
                        "direct relay handshake failed"
                    },
                )
            }
            if (updated != candidate) {
                changed = true
                // 成功但状态本来健康时不会进入这里；状态恢复和所有失败都需同步给 Hook/服务进程。
                persist = true
            }
            updated
        }
        if (!changed) return

        val updatedPlan = matched.copy(candidates = updatedCandidates)
        val updatedPlans = current.plans.mapValues { (_, plan) ->
            if (plan.domain == matched.domain) updatedPlan else plan
        }
        val updatedSnapshot = current.copy(plans = updatedPlans)
        routeSnapshot = updatedSnapshot
        relayTable?.update(updatedSnapshot.relayHosts(now))
        if (persist && settings?.routeSnapshot()?.second == updatedSnapshot.generation) {
            settings?.saveRouteSnapshot(RouteSnapshotCodec.encode(updatedSnapshot), updatedSnapshot.generation)
        }
    }

    /** Provider 完成验证后原子发布；先持久化再替换内存，远程 Hook 只会看到完整 JSON。 */
    @JvmStatic
    @Synchronized
    fun publishRouteSnapshot(snapshot: RouteSnapshot) {
        if (snapshot.generation < routeSnapshot.generation) return
        routeSnapshot = snapshot
        relayTable?.update(snapshot.relayHosts())
        // Root 真实 IP 接管启用时先作为 staged generation；规则成功安装后再发布给 Hook。
        if (settings?.isRootServiceEnabled() != true) {
            settings?.saveRouteSnapshot(RouteSnapshotCodec.encode(snapshot), snapshot.generation)
        }
    }

    /** 防火墙已成功安装同一代路由后，原子发布给远程 LSPosed 进程。 */
    @JvmStatic
    @Synchronized
    fun activateRouteSnapshot(generation: Long): Boolean {
        val snapshot = routeSnapshot
        if (snapshot.generation != generation || generation <= 0L) return false
        val store = settings ?: return false
        store.saveRouteSnapshot(RouteSnapshotCodec.encode(snapshot), generation)
        return true
    }

    @Synchronized
    private fun reloadRemoteRouteSnapshot() {
        val pair = settings?.routeSnapshot() ?: return
        val decoded = RouteSnapshotCodec.decode(pair.first) ?: return
        if (decoded.generation < routeSnapshot.generation) return
        routeSnapshot = decoded
        relayTable?.update(decoded.relayHosts())
    }

    private fun loadRouteSnapshot(context: Context, settings: SettingsStore): RouteSnapshot {
        settings.routeSnapshot()?.first?.let { persisted ->
            RouteSnapshotCodec.decode(persisted)?.let { return it }
        }
        try {
            RouteSnapshotDiskStore(context).read()?.let { return it }
        } catch (_: Throwable) {
            // Xposed 目标 UID 通常不能直接读取模块私有目录，继续使用 bundled。
        }
        return try {
            val bundled = context.assets.open(BUNDLED_ROUTES_ASSET)
                .bufferedReader(Charsets.UTF_8)
                .use { it.readText() }
            RouteSnapshotCodec.decode(bundled) ?: RouteSnapshot.EMPTY
        } catch (t: Throwable) {
            Log.w(TAG, "内置路由快照加载失败: ${t.message}")
            RouteSnapshot.EMPTY
        }
    }

    private fun adaptiveRouteTargets(reg: RuleRegistry): List<AdaptiveRouteTarget> =
        AdaptiveRouteCatalog.fromProfiles(profiles.values, reg::isEnabled)

    @Synchronized
    private fun publishEmptyRouteSnapshotIfNeeded() {
        if (routeSnapshot.plans.isEmpty() && routeSnapshot.metaCidrs.isEmpty()) return
        val now = System.currentTimeMillis()
        publishRouteSnapshot(
            RouteSnapshot(
                generation = maxOf(routeSnapshot.generation + 1, now),
                createdAt = now,
                expiresAt = 0L,
                plans = emptyMap(),
                metaCidrs = emptySet(),
            ),
        )
    }

    private const val BUNDLED_ROUTES_ASSET = "routes/github_snapshot.json"
    private const val ADAPTIVE_PROVIDER_ID = "github-hosts"
    private const val ROUTE_SNAPSHOT_KEY = "route.snapshot.json"
    private const val ROUTE_GENERATION_KEY = "route.snapshot.generation"
    private const val ADAPTIVE_CANDIDATES_KEY = "feature.adaptive_candidates"
    private const val ROUTE_UNUSABLE_AFTER = 3
    private const val MAX_ROUTE_FAILURES = 1_000_000

    private fun routeBackoffMs(failures: Int): Long = when (failures) {
        0 -> 0L
        1 -> 60_000L
        2 -> 5 * 60_000L
        else -> 30 * 60_000L
    }
}

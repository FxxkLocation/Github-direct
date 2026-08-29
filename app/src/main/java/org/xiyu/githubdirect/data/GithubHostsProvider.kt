package org.xiyu.githubdirect.data

import android.content.Context
import android.util.Log
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.dns.OkHttpWireDohTransport
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.TlsEndpointProbe
import org.xiyu.githubdirect.core.routing.AdaptiveRouteCatalog
import org.xiyu.githubdirect.core.routing.AdaptiveRouteTarget
import org.xiyu.githubdirect.core.routing.CandidatePoolPlanner
import org.xiyu.githubdirect.core.routing.CandidateFailureStage
import org.xiyu.githubdirect.core.routing.CandidateSource
import org.xiyu.githubdirect.core.routing.CommunityHostsParser
import org.xiyu.githubdirect.core.routing.EndpointCandidate
import org.xiyu.githubdirect.core.routing.EndpointPlan
import org.xiyu.githubdirect.core.routing.GitHubMetaData
import org.xiyu.githubdirect.core.routing.GitHubMetaParser
import org.xiyu.githubdirect.core.routing.GoogleIpRanges
import org.xiyu.githubdirect.core.routing.GoogleIpRangesParser
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.core.routing.RouteSnapshotCodec
import org.xiyu.githubdirect.core.rules.HostsProvider
import org.xiyu.githubdirect.core.rules.HostsProviderSpec
import java.net.InetAddress
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock

/**
 * 多平台候选路由 provider。
 *
 * GitHub 额外使用官方 Meta 与限龄社区种子；所有启用平台都使用固定 IP Wire DoH、
 * 本机 DNS 污染观测和严格 TLS 探测。除内置/历史快照外，新地址必须用目标的精确域名
 * 或显式后缀代表子域，通过系统信任链与主机名验证后才能作为上游。
 * 本机 DNS/社区 hosts 中验证失败的地址仍作为 intercept-only 目标，用于接住浏览器的污染结果。
 */
class GithubHostsProvider(
    private val spec: HostsProviderSpec,
    private val context: Context? = null,
    private val onSnapshot: (RouteSnapshot) -> Unit = {},
    private val targetsProvider: () -> List<AdaptiveRouteTarget> = { DEFAULT_TARGETS },
) : HostsProvider {

    data class RefreshHealth(
        val lastAttemptAt: Long = 0L,
        val lastSuccessAt: Long = 0L,
        val degradationReason: String = "",
    )

    /** 一个地址当前被采用的来源语义；与历史 [EndpointCandidate] 的健康状态分开保存。 */
    internal data class CandidateProvenance(
        val source: CandidateSource,
        val upstreamEligible: Boolean,
        val observedThisRound: Boolean,
    )

    override val id: String = spec.providerId

    private var store: SettingsStore? = null
    private var binder: NetworkBinder? = null
    private var table: RelayIpTable? = null
    private var diskStore: RouteSnapshotDiskStore? = context?.let(::RouteSnapshotDiskStore)
    private var scheduler: ScheduledExecutorService? = null
    @Volatile private var retryFuture: ScheduledFuture<*>? = null
    private var networkSubscription: java.io.Closeable? = null
    // 网络切换可能连续排入多轮 syncNow。公平锁确保已经等待的数据面事务能在当前
    // 有界刷新结束后取得发布屏障，避免 Root 规则已安装但状态长期停在 STARTING。
    private val syncLock = ReentrantLock(true)
    private val refreshFailures = AtomicInteger(0)
    private val probeQueueCursor = AtomicInteger(0)
    private val lifecycleEpoch = AtomicLong()

    @Volatile
    private var running = false

    @Volatile
    private var currentSnapshot: RouteSnapshot = RouteSnapshot.EMPTY

    @Volatile
    private var refreshHealthState = RefreshHealth()

    @Volatile
    private var roundDegradation = ""

    private var roundNeedsRetry = false

    @Volatile
    private var googleIpRanges: GoogleIpRanges? = null

    fun refreshHealth(): RefreshHealth = refreshHealthState

    /** profile 开关变化后异步刷新；调用线程不执行网络 I/O。 */
    fun requestRefresh() {
        scheduler?.execute { syncNow() }
    }

    @Synchronized
    override fun start(store: SettingsStore, binder: NetworkBinder, table: RelayIpTable) {
        if (running) return
        val epoch = lifecycleEpoch.incrementAndGet()
        running = true
        this.store = store
        this.binder = binder
        this.table = table
        try {
            googleIpRanges = loadInitialGoogleIpRanges(store)
            val initialTargets = targetsProvider().take(AdaptiveRouteCatalog.MAX_TARGETS)
            currentSnapshot = AdaptiveRouteCatalog.filterSnapshot(
                loadInitialSnapshot(store),
                initialTargets,
            )
            if (currentSnapshot !== RouteSnapshot.EMPTY) {
                table.update(currentSnapshot.relayHosts())
                // 首次运行也把 bundled/disk 快照发布到远程偏好，供注入进程无网络读取。
                publish(currentSnapshot, epoch)
            }

            scheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
                Thread(runnable, "GHD-RouteRefresh").apply { isDaemon = true }
            }.also { executor ->
                executor.schedule({ syncNow() }, INITIAL_REFRESH_DELAY_SEC, TimeUnit.SECONDS)
                val interval = maxOf(MIN_REFRESH_HOURS, spec.intervalHours)
                executor.scheduleWithFixedDelay({ syncNow() }, interval, interval, TimeUnit.HOURS)
            }
            networkSubscription = binder.addNetworkChangeListener {
                scheduler?.schedule({ syncNow() }, NETWORK_DEBOUNCE_SEC, TimeUnit.SECONDS)
            }
        } catch (t: Throwable) {
            stop()
            throw t
        }
    }

    @Synchronized
    override fun stop() {
        running = false
        lifecycleEpoch.incrementAndGet()
        networkSubscription?.close()
        networkSubscription = null
        synchronized(this) {
            retryFuture?.cancel(true)
            retryFuture = null
        }
        scheduler?.shutdownNow()
        scheduler = null
        refreshFailures.set(0)
        store = null
        binder = null
        table = null
        googleIpRanges = null
    }

    override fun loadCached(): Map<String, List<String>> = currentSnapshot.relayHosts()

    override fun fetch(): Map<String, List<String>>? = fetchInternal(forceProbe = false)

    override fun reprobe(): Map<String, List<String>>? = fetchInternal(forceProbe = true)

    /**
     * 在规则与 Hook 快照完成同代事务前阻止新的 provider 发布。锁可重入，因此调用方
     * 可以在显式 refresh/reprobe 返回后立即进入屏障，不会和当前线程自锁。
     */
    internal fun <T> withRefreshBarrier(action: () -> T): T {
        syncLock.lock()
        return try {
            action()
        } finally {
            syncLock.unlock()
        }
    }

    private fun fetchInternal(
        forceProbe: Boolean,
        waitForRefreshBarrier: Boolean = false,
    ): Map<String, List<String>>? {
        if (forceProbe || waitForRefreshBarrier) {
            try {
                // 用户显式 REPROBE 必须真正执行；provider 自己的调度线程撞上数据面事务时
                // 也应等待屏障释放，不能把首次刷新静默丢到六小时后的周期任务。
                syncLock.lockInterruptibly()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return currentSnapshot.relayHosts().takeIf { it.isNotEmpty() }
            }
        } else if (!syncLock.tryLock()) {
            return currentSnapshot.relayHosts().takeIf { it.isNotEmpty() }
        }
        if (!running) {
            syncLock.unlock()
            return null
        }
        val epoch = lifecycleEpoch.get()
        val attemptedAt = System.currentTimeMillis()
        refreshHealthState = refreshHealthState.copy(lastAttemptAt = attemptedAt)
        return try {
            val fresh = refreshSnapshot(forceProbe)
            if (fresh == null) {
                refreshHealthState = refreshHealthState.copy(
                    degradationReason = roundDegradation.ifBlank {
                        "候选刷新未得到可信实时来源；正在沿用最后安全快照"
                    },
                )
                scheduleRefreshRetry()
                currentSnapshot.relayHosts().takeIf { it.isNotEmpty() }
            } else {
                if (!publish(fresh, epoch)) return null
                if (roundNeedsRetry) scheduleRefreshRetry() else markRefreshSuccessful()
                refreshHealthState = RefreshHealth(
                    lastAttemptAt = attemptedAt,
                    lastSuccessAt = System.currentTimeMillis(),
                    degradationReason = roundDegradation,
                )
                fresh.relayHosts()
            }
        } catch (t: Throwable) {
            Log.w(TAG, "多平台路由刷新失败", t)
            refreshHealthState = refreshHealthState.copy(
                degradationReason = "候选刷新异常；正在沿用最后安全快照：${t.message.orEmpty().take(120)}"
                    .trimEnd(':', ' '),
            )
            scheduleRefreshRetry()
            currentSnapshot.relayHosts().takeIf { it.isNotEmpty() }
        } finally {
            syncLock.unlock()
        }
    }

    override fun validateIp(ip: String, port: Int): Boolean {
        if (port != 443) return false
        val b = binder ?: return false
        val probeTargets = runCatching {
            targetsProvider().associateBy(AdaptiveRouteTarget::domain)
        }.getOrDefault(emptyMap())
        val targets = currentSnapshot.plans.values.asSequence()
            .filter { plan -> plan.candidates.any { it.address == ip && !it.interceptOnly } }
            .mapNotNull { plan -> probeTargets[plan.domain] }
            .distinctBy(AdaptiveRouteTarget::domain)
            .take(4)
            .toList()
        if (targets.isEmpty()) return false
        val probe = TlsEndpointProbe(b, TLS_PROBE_TIMEOUT_MS)
        val allowNoSni = store?.isTlsTerminationEnabled() == true
        return targets.any { target ->
            probe.probe(
                target.probeDomain,
                ip,
                allowNoSni,
                target.semanticProbe,
            ).capability != RouteCapability.UNUSABLE
        }
    }

    private fun syncNow() {
        fetchInternal(forceProbe = false, waitForRefreshBarrier = true)?.let {
            table?.update(it)
        }
    }

    /** 整轮刷新失败后按 1/5/30 分钟重试；同一时刻最多保留一个 retry future。 */
    @Synchronized
    private fun scheduleRefreshRetry() {
        val executor = scheduler ?: return
        if (executor.isShutdown || retryFuture?.isDone == false) return
        val failure = refreshFailures.incrementAndGet()
        val delay = refreshFailureBackoffMs(failure)
        retryFuture = try {
            executor.schedule({
                synchronized(this) { retryFuture = null }
                syncNow()
            }, delay, TimeUnit.MILLISECONDS)
        } catch (_: Throwable) {
            null
        }
    }

    @Synchronized
    private fun markRefreshSuccessful() {
        refreshFailures.set(0)
        retryFuture?.cancel(false)
        retryFuture = null
    }

    private fun refreshSnapshot(forceProbe: Boolean): RouteSnapshot? {
        val b = binder ?: return null
        val targets = targetsProvider().take(AdaptiveRouteCatalog.MAX_TARGETS)
        if (targets.isEmpty()) {
            val now = System.currentTimeMillis()
            val generation = maxOf(currentSnapshot.generation + 1, now)
            return RouteSnapshot(generation, now, 0L, emptyMap(), emptySet())
        }
        // 每轮独立计算健康状态。若 source 收集在计算详细原因前即超时/失败，
        // fetchInternal 会发布通用降级说明，不能泄漏上一轮的告警。
        roundDegradation = ""
        roundNeedsRetry = false
        val now = System.currentTimeMillis()
        val base = currentSnapshot
        // 只从上一代已严格验证的安全快照共享 IP；目标仍会用自身 probeDomain 重新探测。
        val pooledSeeds = CandidatePoolPlanner.sharedSeeds(targets, base, now)
        val activePoolMembers = CandidatePoolPlanner.activeMemberDomains(targets)
        val githubEnabled = targets.any { it.serviceId == GITHUB_PROFILE_ID }
        val googleOwnershipRequired = targets.any {
            it.candidatePool == GOOGLE_CANDIDATE_POOL
        }
        val auxiliary = fetchAuxiliarySources(
            binder = b,
            githubEnabled = githubEnabled,
            googleOwnershipRequired = googleOwnershipRequired,
            now = now,
        )
        val meta = auxiliary.meta
        val community = auxiliary.community
        val googleRanges = auxiliary.googleRanges
        val wireResolver = EndpointResolver(
            binder = b,
            wireClient = OkHttpWireDohTransport.createClient(b),
            wireTimeoutMs = WIRE_RESOLVE_TIMEOUT_MS,
            mergeIndependentWireAnswers = true,
        )

        val sourcePool = Executors.newFixedThreadPool(SOURCE_WORKERS) { runnable ->
            Thread(runnable, "GHD-RouteSource").apply { isDaemon = true }
        }
        val seedPlans = try {
            val calls = targets.map { target ->
                Callable {
                    collectSeeds(
                        target,
                        base,
                        meta,
                        community,
                        wireResolver,
                        pooledSeeds[target.domain].orEmpty(),
                        target.domain in activePoolMembers,
                        googleRanges,
                        now,
                    )
                }
            }
            sourcePool.invokeAll(calls, SOURCE_DEADLINE_SEC, TimeUnit.SECONDS)
                .mapNotNull { future ->
                    if (future.isCancelled) null else runCatching { future.get() }.getOrNull()
                }
        } finally {
            sourcePool.shutdownNow()
        }
        if (seedPlans.isEmpty()) return null

        val networkKey = b.networkKey()
        val probeRequests = selectProbeRequests(seedPlans, now, networkKey, forceProbe)
        val probeResults = probeCandidates(b, probeRequests, now, networkKey)
        val missingSourceResult = seedPlans.size < targets.size
        val missingProbeResult = probeResults.size < probeRequests.size
        val retryableProbeFailure = probeResults.values.any { candidate ->
            candidate.capability == RouteCapability.UNUSABLE && candidate.failures <= MAX_FAST_PROBE_FAILURES
        }
        roundNeedsRetry = missingSourceResult ||
            probeRequests.isNotEmpty() && (missingProbeResult || retryableProbeFailure)
        val metaAvailable = meta != null
        val communityAvailable = community.isNotEmpty()
        val wireSourceAvailable = seedPlans.any(SeedPlan::wireSourceObserved)
        val verifiedProbeAvailable = probeResults.values.any { it.usable(now) }
        roundDegradation = sourceDegradation(
            metaAvailable = metaAvailable,
            communityAvailable = communityAvailable,
            wireSourceAvailable = wireSourceAvailable,
            verifiedProbeAvailable = verifiedProbeAvailable,
        )
        if (roundNeedsRetry) {
            val probeFailure = probeFailureDegradation(probeResults.values)
            roundDegradation = listOf(
                roundDegradation,
                probeFailure.ifBlank { "部分候选探测未完成" } +
                    "；将按 1/5/30 分钟有限重试",
            ).filter(String::isNotBlank).joinToString("；")
        }
        val liveSourceSucceeded = refreshHasLiveSource(
            metaAvailable = metaAvailable,
            communityAvailable = communityAvailable,
            wireSourceAvailable = wireSourceAvailable,
            verifiedProbeAvailable = verifiedProbeAvailable,
        )
        // 仅复用 base 快照不算一次成功刷新；保留当前 generation，并启动 1/5/30 分钟重试。
        if (!liveSourceSucceeded) return null
        val plans = LinkedHashMap<String, EndpointPlan>()
        for (seedPlan in seedPlans) {
            val candidates = finalizeCandidates(seedPlan, probeResults, now, networkKey)
            plans[seedPlan.target.domain] = EndpointPlan(
                domain = seedPlan.target.domain,
                endpointGroup = seedPlan.target.endpointGroup,
                includeSubdomains = seedPlan.target.includeSubdomains,
                candidates = candidates,
            )
        }

        // 未在本轮完成 source 收集的目标保留旧计划，不能因局部超时清空已有路由。
        val activeDomains = targets.mapTo(HashSet(), AdaptiveRouteTarget::domain)
        for ((domain, plan) in base.plans) {
            if (domain in activeDomains) plans.putIfAbsent(domain, plan)
        }
        val generation = maxOf(base.generation + 1, now)
        return RouteSnapshot(
            generation = generation,
            createdAt = now,
            expiresAt = now + SNAPSHOT_TTL_MS,
            plans = plans,
            metaCidrs = if (githubEnabled) {
                meta?.allCidrs?.takeIf { it.isNotEmpty() } ?: base.metaCidrs
            } else {
                emptySet()
            },
        )
    }

    private fun collectSeeds(
        target: AdaptiveRouteTarget,
        base: RouteSnapshot,
        meta: GitHubMetaData?,
        community: Map<String, List<String>>,
        resolver: EndpointResolver,
        pooledAddresses: List<String>,
        retainPooledHistory: Boolean,
        googleRanges: GoogleIpRanges?,
        now: Long,
    ): SeedPlan {
        val seeds = LinkedHashMap<String, Seed>()
        var wireSourceObserved = false
        fun add(
            address: String,
            source: CandidateSource,
            previous: EndpointCandidate? = null,
            upstreamEligible: Boolean = sourceCanBecomeUpstream(source),
            poolShared: Boolean = false,
            observedThisRound: Boolean = true,
        ) {
            val raw = IpAddresses.parseIpAddress(address) ?: return
            if (IpAddresses.isBogonOrPoisoned(raw)) return
            val ownershipEligible = candidateOwnershipAllowsUpstream(
                candidatePool = target.candidatePool,
                address = raw,
                googleRanges = googleRanges,
                previouslyVerified = previous?.usable(now) == true && !previous.interceptOnly,
            )
            val existing = seeds[address]
            val effectiveSource = effectiveCandidateSource(
                candidatePool = target.candidatePool,
                source = source,
                ownershipEligible = ownershipEligible,
            )
            val incoming = CandidateProvenance(
                source = effectiveSource,
                upstreamEligible = upstreamEligible && ownershipEligible &&
                    sourceCanBecomeUpstream(effectiveSource),
                observedThisRound = observedThisRound,
            )
            val merged = mergeCandidateProvenance(
                existing = existing?.let {
                    CandidateProvenance(it.source, it.upstreamEligible, it.observedThisRound)
                },
                previousUsable = existing?.previous?.let {
                    it.usable(now) && !it.interceptOnly
                } == true,
                incoming = incoming,
            )
            seeds[address] = Seed(
                target = target,
                address = address,
                source = merged.source,
                previous = previous ?: existing?.previous,
                upstreamEligible = merged.upstreamEligible,
                poolShared = poolShared || existing?.poolShared == true,
                observedThisRound = merged.observedThisRound,
            )
        }

        // 已验证历史先进入，保证无网络启动与刷新失败时仍可工作。
        base.planFor(target.domain)?.candidates.orEmpty()
            // v1 的宽 google-edge 池曾把仅证书兼容、应用后端不兼容的地址跨组发布。
            // 新配置中没有同 pool+verificationScope 伙伴或跨组语义锚点时，
            // 立即淘汰这类池历史，不能等 24h TTL。
            .filter { it.source != CandidateSource.CANDIDATE_POOL || retainPooledHistory }
            // 语义策略新增/变更后，旧候选只能等待实时来源重新发现并探测。
            .filter(target::matchesSemanticPolicy)
            .take(MAX_CANDIDATES_PER_DOMAIN)
            .forEach { candidate ->
                add(
                    candidate.address,
                    candidate.source,
                    candidate,
                    upstreamEligible = !candidate.interceptOnly &&
                        sourceCanBecomeUpstream(candidate.source),
                    observedThisRound = false,
                )
            }

        // 池成员只贡献已经在另一个成员上验证过的 IP 种子。这里不继承源域能力，
        // previous 也只能取目标根自己的历史结果，随后必须用目标 probeDomain 再验证。
        pooledAddresses.forEach { address ->
            add(
                address = address,
                source = CandidateSource.CANDIDATE_POOL,
                previous = baseCandidate(base, target.domain, address),
                upstreamEligible = true,
                poolShared = true,
            )
        }

        resolver.discover(target.domain, cidr = null)?.let { discovery ->
            val trustedAddresses = (discovery.trusted.v4 + discovery.trusted.v6)
                .take(MAX_CANDIDATES_PER_SOURCE)
            val ownershipEligibleTrustedAnswer = trustedAddresses.any { raw ->
                !IpAddresses.isBogonOrPoisoned(raw) && candidateOwnershipAllowsUpstream(
                    candidatePool = target.candidatePool,
                    address = raw,
                    googleRanges = googleRanges,
                    previouslyVerified = baseCandidate(base, target.domain, raw)
                        ?.let { it.usable(now) && !it.interceptOnly } == true,
                )
            }
            wireSourceObserved = trustedResponseCountsAsLiveSource(
                candidatePool = target.candidatePool,
                responseObserved = discovery.trustedResponseObserved,
                ownershipEligibleAnswerObserved = ownershipEligibleTrustedAnswer,
            )
            trustedAddresses.forEach { raw ->
                add(
                    if (raw.size == 4) IpAddresses.ipv4ToString(raw) else IpAddresses.ipv6ToString(raw),
                    CandidateSource.WIRE_DOH,
                    baseCandidate(base, target.domain, raw),
                )
            }
            (discovery.observed.v4 + discovery.observed.v6)
                .take(MAX_OBSERVER_ADDRESSES_PER_SOURCE)
                .forEach { raw ->
                    add(
                        if (raw.size == 4) {
                            IpAddresses.ipv4ToString(raw)
                        } else {
                            IpAddresses.ipv6ToString(raw)
                        },
                        CandidateSource.DNS_OBSERVER,
                        baseCandidate(base, target.domain, raw),
                        upstreamEligible = false,
                    )
                }
        }
        target.githubMetaGroup?.let { metaGroup ->
            meta?.literalAddresses(metaGroup)?.take(MAX_META_LITERALS_PER_DOMAIN)?.forEach { address ->
                add(address, CandidateSource.GITHUB_META, baseCandidate(base, target.domain, address))
            }
        }
        resolveSystem(target.domain).take(MAX_CANDIDATES_PER_SOURCE).forEach { address ->
            add(
                address,
                CandidateSource.LOCAL_DNS,
                baseCandidate(base, target.domain, address),
                upstreamEligible = false,
            )
        }
        community[target.domain].orEmpty().take(MAX_CANDIDATES_PER_SOURCE).forEach { address ->
            add(address, CandidateSource.COMMUNITY, baseCandidate(base, target.domain, address))
        }
        return SeedPlan(target, seeds.values.toList(), now, wireSourceObserved)
    }

    private fun selectProbeRequests(
        plans: List<SeedPlan>,
        now: Long,
        networkKey: String,
        forceProbe: Boolean,
    ): List<Seed> {
        val requireNoSniProbe = store?.isTlsTerminationEnabled() == true
        val queues = plans.map { plan ->
            val requiredSemanticSignature = plan.target.semanticProbe?.verificationSignature()
            plan.seeds.asSequence()
                .filter(Seed::upstreamEligible)
                .filter { seed ->
                    candidateProbeDue(
                        seed.previous,
                        now,
                        networkKey,
                        forceProbe,
                        requireNoSniProbe,
                        requiredSemanticSignature,
                    )
                }
                .sortedWith(
                    compareBy<Seed> { if (it.poolShared) 0 else 1 }
                        .thenBy { if (it.previous == null) 0 else 1 }
                        .thenBy { sourceRank(it.source) }
                        .thenBy { it.address },
                )
                .take(MAX_PROBES_PER_DOMAIN)
                .toMutableList()
        }
        val selected = ArrayList<Seed>(MAX_PROBES_PER_REFRESH)
        val cursor = probeQueueCursor.getAndAdd(MAX_PROBES_PER_REFRESH)
        // 先给每个没有可用历史上游的目标一个验证槽；池种子仍属紧急，但不再让“是否配置
        // 候选池”决定公平性。这样收紧错误池后，目标自己的 Wire DoH 地址会立即得到探测。
        val urgentQueues = queues.indices.filter { index ->
            queues[index].isNotEmpty() && (
                queues[index].any(Seed::poolShared) ||
                    plans[index].seeds.none { seed ->
                        seed.upstreamEligible && seed.previous?.let { previous ->
                            previous.usable(now) &&
                                plans[index].target.matchesSemanticPolicy(previous)
                        } == true
                    }
                )
        }
        rotatingIndexes(urgentQueues.size, cursor).forEach { urgentIndex ->
            if (selected.size >= MAX_PROBES_PER_REFRESH) return@forEach
            val queue = queues[urgentQueues[urgentIndex]]
            val seedIndex = queue.indexOfFirst(Seed::poolShared)
            if (queue.isNotEmpty()) selected += queue.removeAt(if (seedIndex >= 0) seedIndex else 0)
        }
        val queueOrder = rotatingIndexes(
            queues.size,
            cursor,
        )
        if (queueOrder.isEmpty()) return selected
        var index = 0
        while (selected.size < MAX_PROBES_PER_REFRESH && queues.any { it.isNotEmpty() }) {
            val queue = queues[queueOrder[index % queueOrder.size]]
            if (queue.isNotEmpty()) selected += queue.removeAt(0)
            index++
        }
        return selected
    }

    private fun probeCandidates(
        binder: NetworkBinder,
        seeds: List<Seed>,
        now: Long,
        networkKey: String,
    ): Map<ProbeKey, EndpointCandidate> {
        if (seeds.isEmpty()) return emptyMap()
        val pool = Executors.newFixedThreadPool(PROBE_WORKERS) { runnable ->
            Thread(runnable, "GHD-TlsProbe").apply { isDaemon = true }
        }
        return try {
            val probe = TlsEndpointProbe(binder, TLS_PROBE_TIMEOUT_MS)
            val allowNoSni = store?.isTlsTerminationEnabled() == true
            val tasks = seeds.map { seed ->
                Callable {
                    val result = probe.probe(
                        seed.target.probeDomain,
                        seed.address,
                        allowNoSni,
                        seed.target.semanticProbe,
                    )
                    val previousOnNetwork = seed.previous?.takeIf { it.networkKey == networkKey }
                    val oldFailures = previousOnNetwork?.failures ?: 0
                    val failures = if (result.capability == RouteCapability.UNUSABLE) oldFailures + 1 else 0
                    val backoff = if (failures > 0) now + failureBackoff(failures) else 0L
                    val previousLatency = previousOnNetwork?.latencyMs ?: 0L
                    val latency = if (result.capability == RouteCapability.UNUSABLE) {
                        0L
                    } else {
                        latencyEwmaMs(previousLatency, result.latencyMs)
                    }
                    ProbeKey(seed.target.domain, seed.address) to EndpointCandidate(
                        domain = seed.target.domain,
                        address = seed.address,
                        source = seed.source,
                        fetchedAt = now,
                        expiresAt = now + CANDIDATE_TTL_MS,
                        latencyMs = latency,
                        capability = result.capability,
                        failures = failures,
                        backoffUntil = backoff,
                        networkKey = networkKey,
                        interceptOnly = result.capability == RouteCapability.UNUSABLE,
                        noSniCapable = result.noSniCapable,
                        noSniProbed = result.noSniProbed,
                        lastError = result.error,
                        failureStage = result.failureStage,
                        // capability/interceptOnly 表示语义是否成功；签名也写入失败结果，
                        // 使相同策略继续遵守退避，而策略变化仍可立即触发一次新探测。
                        semanticProbeSignature =
                            seed.target.semanticProbe?.verificationSignature().orEmpty(),
                    )
                }
            }
            pool.invokeAll(tasks, PROBE_GLOBAL_DEADLINE_SEC, TimeUnit.SECONDS)
                .mapNotNull { future ->
                    if (future.isCancelled) null else runCatching { future.get() }.getOrNull()
                }
                .toMap()
        } finally {
            pool.shutdownNow()
        }
    }

    private fun finalizeCandidates(
        plan: SeedPlan,
        results: Map<ProbeKey, EndpointCandidate>,
        now: Long,
        networkKey: String,
    ): List<EndpointCandidate> {
        val final = LinkedHashMap<String, EndpointCandidate>()
        for (seed in plan.seeds) {
            val probed = results[ProbeKey(plan.target.domain, seed.address)]
            if (probed != null) {
                final[seed.address] = probed
                continue
            }
            val previous = seed.previous
            val previousSemanticProofValid = previous?.let(
                plan.target::matchesSemanticPolicy,
            ) == true
            val carried = if (seed.upstreamEligible && previousSemanticProofValid) {
                carryVerifiedCandidateAcrossNetwork(previous, now, networkKey)
            } else {
                null
            }
            if (
                seed.upstreamEligible && previous != null &&
                previousSemanticProofValid && previous.networkKey == networkKey &&
                previous.usable(now)
            ) {
                final[seed.address] = previous
            } else if (carried != null) {
                // 网络切换只清空延迟/失败健康分。由于全局探测有上限，未在本轮轮到的
                // 已验证地址仍可保护性保留，并保持旧 networkKey 以便下一轮继续强制探测。
                final[seed.address] = carried
            } else {
                if (!seed.observedThisRound && previous != null) {
                    // 未在本轮任何实时来源中再次出现的 intercept-only 地址只沿用原 TTL，
                    // 不能每次刷新都把旧污染样本续命六小时。过期历史直接丢弃。
                    unobservedCandidateBeforeExpiry(previous, now)?.let {
                        final[seed.address] = it
                    }
                    continue
                }
                // 未完成验证的新地址只能用于拦截污染/浏览器结果，绝不作为上游。
                val previousOnNetwork = previous?.takeIf { it.networkKey == networkKey }
                final[seed.address] = EndpointCandidate(
                    domain = plan.target.domain,
                    address = seed.address,
                    source = seed.source,
                    fetchedAt = now,
                    expiresAt = now + UNVERIFIED_INTERCEPT_TTL_MS,
                    latencyMs = 0,
                    capability = RouteCapability.UNUSABLE,
                    failures = previousOnNetwork?.failures ?: 0,
                    backoffUntil = previousOnNetwork?.backoffUntil ?: 0,
                    networkKey = networkKey,
                    interceptOnly = true,
                )
            }
        }

        // 全部当前探测失败时保留最多三个历史已验证候选，避免一次网络抖动摧毁启动快照。
        if (final.values.none { it.usable(now) }) {
            plan.seeds.asSequence()
                .filter(Seed::upstreamEligible)
                .mapNotNull { it.previous }
                .filter {
                    it.networkKey == networkKey &&
                        it.capability != RouteCapability.UNUSABLE && !it.interceptOnly &&
                        plan.target.matchesSemanticPolicy(it)
                }
                .take(3)
                .forEach { previous -> final[previous.address] = previous.copy(source = CandidateSource.HISTORICAL) }
        }
        val reservedProbeAddresses = plan.seeds.asSequence()
            .filter { it.poolShared && it.upstreamEligible }
            .mapTo(HashSet(), Seed::address)
        return rankAndLimitCandidates(
            final.values,
            reservedProbeAddresses,
            now,
        )
    }

    @Synchronized
    private fun publish(snapshot: RouteSnapshot, epoch: Long): Boolean {
        if (!running || lifecycleEpoch.get() != epoch) return false
        currentSnapshot = snapshot
        diskStore?.write(snapshot)
        table?.update(snapshot.relayHosts())
        try {
            onSnapshot(snapshot)
        } catch (t: Throwable) {
            Log.w(TAG, "发布路由快照回调失败", t)
        }
        return true
    }

    private fun loadInitialSnapshot(store: SettingsStore): RouteSnapshot {
        val persisted = store.routeSnapshot()?.first?.let(RouteSnapshotCodec::decode)
            ?: diskStore?.read()
        val ctx = context ?: return persisted ?: RouteSnapshot.EMPTY
        val bundled = try {
            ctx.assets.open(BUNDLED_ASSET).bufferedReader(Charsets.UTF_8).use { reader ->
                RouteSnapshotCodec.decode(reader.readText()) ?: RouteSnapshot.EMPTY
            }
        } catch (_: Throwable) {
            RouteSnapshot.EMPTY
        }
        return mergeBundledFallback(persisted, bundled, System.currentTimeMillis())
    }

    /** GitHub Meta、社区 hosts 与 Google 官方前缀并发获取，共享一个硬截止时间。 */
    private fun fetchAuxiliarySources(
        binder: NetworkBinder,
        githubEnabled: Boolean,
        googleOwnershipRequired: Boolean,
        now: Long,
    ): AuxiliarySources {
        if (!githubEnabled && !googleOwnershipRequired) {
            return AuxiliarySources(null, emptyMap(), null)
        }
        val pool = Executors.newFixedThreadPool(3) { runnable ->
            Thread(runnable, "GHD-RouteAux").apply { isDaemon = true }
        }
        val deadline = System.nanoTime() +
            TimeUnit.SECONDS.toNanos(SOURCE_AUXILIARY_DEADLINE_SEC)
        return try {
            val metaFuture = if (githubEnabled) {
                pool.submit<GitHubMetaData?> { fetchMeta(binder) }
            } else {
                null
            }
            val communityFuture = if (githubEnabled) {
                pool.submit<Map<String, List<String>>> { fetchCommunity(binder, now) }
            } else {
                null
            }
            val googleFuture = if (googleOwnershipRequired) {
                pool.submit<GoogleIpRanges?> { fetchGoogleIpRanges(binder, now) }
            } else {
                null
            }
            val meta = awaitBeforeDeadline(metaFuture, deadline)
            val community = awaitBeforeDeadline(communityFuture, deadline).orEmpty()
            val fetchedGoogle = awaitBeforeDeadline(googleFuture, deadline)
            if (fetchedGoogle != null) googleIpRanges = fetchedGoogle
            AuxiliarySources(
                meta = meta,
                community = community,
                googleRanges = if (googleOwnershipRequired) {
                    fetchedGoogle ?: googleIpRanges
                } else {
                    null
                },
            )
        } finally {
            pool.shutdownNow()
        }
    }

    private fun <T> awaitBeforeDeadline(future: Future<T>?, deadlineNanos: Long): T? {
        if (future == null) return null
        val remaining = deadlineNanos - System.nanoTime()
        if (remaining <= 0L) {
            future.cancel(true)
            return null
        }
        return try {
            future.get(remaining, TimeUnit.NANOSECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            future.cancel(true)
            null
        } catch (_: Throwable) {
            future.cancel(true)
            null
        }
    }

    private fun loadInitialGoogleIpRanges(store: SettingsStore): GoogleIpRanges? {
        store.hostsData(GOOGLE_IP_RANGES_CACHE_ID)?.first
            ?.let(GoogleIpRangesParser::parse)
            ?.let { return it }
        val ctx = context ?: return null
        return try {
            ctx.assets.open(GOOGLE_IP_RANGES_ASSET).bufferedReader(Charsets.UTF_8).use { reader ->
                GoogleIpRangesParser.parse(reader.readText())
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun fetchGoogleIpRanges(binder: NetworkBinder, now: Long): GoogleIpRanges? {
        val json = binder.httpGet(
            GOOGLE_IP_RANGES_URL,
            HTTP_CONNECT_TIMEOUT_MS,
            HTTP_READ_TIMEOUT_MS,
            mapOf("Accept" to "application/json", "User-Agent" to "GitHub-direct/1"),
        ) ?: return null
        val parsed = GoogleIpRangesParser.parse(json) ?: return null
        store?.saveHostsData(GOOGLE_IP_RANGES_CACHE_ID, json, now)
        return parsed
    }

    private fun fetchMeta(binder: NetworkBinder): GitHubMetaData? {
        val json = binder.httpGet(
            META_URL,
            HTTP_CONNECT_TIMEOUT_MS,
            HTTP_READ_TIMEOUT_MS,
            mapOf("Accept" to "application/vnd.github+json", "User-Agent" to "GitHub-direct/1"),
        )
        return GitHubMetaParser.parse(json)
    }

    private fun fetchCommunity(binder: NetworkBinder, now: Long): Map<String, List<String>> {
        for (url in COMMUNITY_URLS) {
            val raw = binder.httpGet(
                url,
                HTTP_CONNECT_TIMEOUT_MS,
                HTTP_READ_TIMEOUT_MS,
                mapOf("Accept" to "text/plain", "User-Agent" to "GitHub-direct/1"),
            ) ?: continue
            CommunityHostsParser.parse(raw, now, COMMUNITY_MAX_AGE_MS)?.let { return it.hosts }
        }
        return emptyMap()
    }

    private fun resolveSystem(domain: String): List<String> {
        val pool = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "GHD-SystemDns").apply { isDaemon = true }
        }
        return try {
            val future = pool.submit<List<String>> {
                InetAddress.getAllByName(domain).mapNotNull { address ->
                    val raw = address.address ?: return@mapNotNull null
                    if (raw.size == 4) IpAddresses.ipv4ToString(raw) else IpAddresses.ipv6ToString(raw)
                }.distinct()
            }
            runCatching { future.get(SYSTEM_DNS_TIMEOUT_MS, TimeUnit.MILLISECONDS) }.getOrElse {
                future.cancel(true)
                emptyList()
            }
        } finally {
            pool.shutdownNow()
        }
    }

    private fun baseCandidate(base: RouteSnapshot, domain: String, raw: ByteArray): EndpointCandidate? {
        val address = if (raw.size == 4) IpAddresses.ipv4ToString(raw) else IpAddresses.ipv6ToString(raw)
        return baseCandidate(base, domain, address)
    }

    private fun baseCandidate(base: RouteSnapshot, domain: String, address: String): EndpointCandidate? =
        base.planFor(domain)?.candidates?.firstOrNull { it.address == address }

    private fun failureBackoff(failures: Int): Long = when (failures) {
        1 -> TimeUnit.MINUTES.toMillis(1)
        2 -> TimeUnit.MINUTES.toMillis(5)
        else -> TimeUnit.MINUTES.toMillis(30)
    }

    private data class Seed(
        val target: AdaptiveRouteTarget,
        val address: String,
        val source: CandidateSource,
        val previous: EndpointCandidate?,
        val upstreamEligible: Boolean,
        val poolShared: Boolean,
        val observedThisRound: Boolean,
    )
    private data class SeedPlan(
        val target: AdaptiveRouteTarget,
        val seeds: List<Seed>,
        val fetchedAt: Long,
        val wireSourceObserved: Boolean,
    )
    private data class AuxiliarySources(
        val meta: GitHubMetaData?,
        val community: Map<String, List<String>>,
        val googleRanges: GoogleIpRanges?,
    )
    private data class ProbeKey(val domain: String, val address: String)

    companion object {
        private const val TAG = "GithubRoutes"
        private const val BUNDLED_ASSET = "routes/github_snapshot.json"
        private const val GOOGLE_IP_RANGES_ASSET = "routes/google_frontend_prefixes.json"
        private const val GOOGLE_IP_RANGES_URL = "https://www.gstatic.com/ipranges/goog.json"
        private const val GOOGLE_IP_RANGES_CACHE_ID = "google-official-ip-ranges"
        private const val GOOGLE_CANDIDATE_POOL = "google-edge"
        private const val META_URL = "https://api.github.com/meta"
        private val COMMUNITY_URLS = listOf(
            "https://raw.githubusercontent.com/maxiaof/github-hosts/master/hosts",
            "https://gitee.com/TheDarkStar/github-hosts/raw/master/hosts",
        )
        private const val GITHUB_PROFILE_ID = "github"
        private val DEFAULT_TARGETS = listOf(
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "github.com", "web", false, "web"),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "api.github.com", "api", false, "api"),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "gist.github.com", "web", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "codeload.github.com", "web", false),
            // GitHub App/登录链会直接访问这些域名；必须同时观察本机污染结果，
            // 不能只把它们留在 profiles.json 而漏出 Root 拦截目标集。
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "alive.github.com", "web", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "central.github.com", "web", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "collector.github.com", "api", false, "api"),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "github.githubassets.com", "assets", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "github.blog", "web", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "copilot-proxy.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "raw.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "objects.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "release-assets.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "avatars.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "user-images.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "media.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "camo.githubusercontent.com", "usercontent", false),
            AdaptiveRouteTarget(GITHUB_PROFILE_ID, "github.io", "pages", true, "pages"),
        )

        private const val INITIAL_REFRESH_DELAY_SEC = 2L
        private const val NETWORK_DEBOUNCE_SEC = 2L
        private const val MIN_REFRESH_HOURS = 6L
        // Wire DoH 内部还会并行 A/AAAA 与多个加密上游；实机提高到 16 会放大底层
        // 请求并发并挤压随后 TLS 验证，保持保守的 8 路与 30s 全局边界。
        private const val SOURCE_WORKERS = 8
        private const val SOURCE_DEADLINE_SEC = 30L
        private const val SOURCE_AUXILIARY_DEADLINE_SEC = 8L
        private const val PROBE_WORKERS = 4
        private const val PROBE_GLOBAL_DEADLINE_SEC = 45L
        private const val MAX_PROBES_PER_REFRESH = 32
        private const val MAX_PROBES_PER_DOMAIN = 4
        private const val MAX_CANDIDATES_PER_DOMAIN = 32
        private const val MAX_CANDIDATES_PER_SOURCE = 32
        private const val MAX_OBSERVER_ADDRESSES_PER_SOURCE = 8
        private const val MAX_META_LITERALS_PER_DOMAIN = 12
        private const val MAX_FAST_PROBE_FAILURES = 3
        private const val HTTP_CONNECT_TIMEOUT_MS = 4_000
        private const val HTTP_READ_TIMEOUT_MS = 6_000
        private const val WIRE_RESOLVE_TIMEOUT_MS = 2_500
        private const val SYSTEM_DNS_TIMEOUT_MS = 1_500L
        private const val TLS_PROBE_TIMEOUT_MS = 2_200
        private val REPROBE_AFTER_MS = TimeUnit.HOURS.toMillis(6)
        private val CANDIDATE_TTL_MS = TimeUnit.HOURS.toMillis(24)
        private val SNAPSHOT_TTL_MS = TimeUnit.HOURS.toMillis(24)
        private val UNVERIFIED_INTERCEPT_TTL_MS = TimeUnit.HOURS.toMillis(6)
        private val COMMUNITY_MAX_AGE_MS = TimeUnit.DAYS.toMillis(7)

        internal fun refreshFailureBackoffMs(failures: Int): Long = when (failures) {
            1 -> TimeUnit.MINUTES.toMillis(1)
            2 -> TimeUnit.MINUTES.toMillis(5)
            else -> TimeUnit.MINUTES.toMillis(30)
        }

        internal fun refreshHasLiveSource(
            metaAvailable: Boolean,
            communityAvailable: Boolean,
            wireSourceAvailable: Boolean,
            verifiedProbeAvailable: Boolean,
        ): Boolean = metaAvailable || communityAvailable || wireSourceAvailable || verifiedProbeAvailable

        /** 本机/观察器 DNS 只提供污染拦截目标，任何情况下都不能升级为中继上游。 */
        internal fun sourceCanBecomeUpstream(source: CandidateSource): Boolean = when (source) {
            CandidateSource.LOCAL_DNS,
            CandidateSource.DNS_OBSERVER,
            -> false
            else -> true
        }

        /**
         * Google 官方归属校验失败的地址仍可作为污染观测，但不能继续带着可信来源标签。
         * 这样它不会占用 TLS 探测槽，也不会挤掉候选硬上限内的官方地址。
         */
        internal fun effectiveCandidateSource(
            candidatePool: String?,
            source: CandidateSource,
            ownershipEligible: Boolean,
        ): CandidateSource = if (
            candidatePool == GOOGLE_CANDIDATE_POOL &&
            sourceCanBecomeUpstream(source) && !ownershipEligible
        ) {
            CandidateSource.DNS_OBSERVER
        } else {
            source
        }

        /**
         * 来源优先级只在同一观测代内比较。旧的高可信标签不能被本轮低可信观测续期；
         * 但尚有效的严格验证历史会保留到原 TTL，由后续轮次重新验证或自然过期。
         */
        internal fun mergeCandidateProvenance(
            existing: CandidateProvenance?,
            previousUsable: Boolean,
            incoming: CandidateProvenance,
        ): CandidateProvenance {
            if (existing == null) return incoming
            val incomingRank = sourceRank(incoming.source)
            val existingRank = sourceRank(existing.source)
            val preferIncoming = when {
                incoming.observedThisRound && !existing.observedThisRound ->
                    incomingRank <= existingRank || !previousUsable
                !incoming.observedThisRound && existing.observedThisRound -> false
                else -> incomingRank < existingRank
            }
            if (preferIncoming) return incoming
            if (incoming.source != existing.source) return existing
            return existing.copy(
                upstreamEligible = existing.upstreamEligible || incoming.upstreamEligible,
                observedThisRound = existing.observedThisRound || incoming.observedThisRound,
            )
        }

        /** Google 平台不能把只有 NODATA/归属异常答案的响应计作可用候选来源。 */
        internal fun trustedResponseCountsAsLiveSource(
            candidatePool: String?,
            responseObserved: Boolean,
            ownershipEligibleAnswerObserved: Boolean,
        ): Boolean = responseObserved && (
            candidatePool != GOOGLE_CANDIDATE_POOL || ownershipEligibleAnswerObserved
        )

        internal fun probeFailureDegradation(
            candidates: Collection<EndpointCandidate>,
        ): String {
            val counts = candidates.asSequence()
                .filter { it.capability == RouteCapability.UNUSABLE }
                .filter { it.failureStage != CandidateFailureStage.NONE }
                .groupingBy(EndpointCandidate::failureStage)
                .eachCount()
            if (counts.isEmpty()) return ""
            val details = FAILURE_STAGE_ORDER.mapNotNull { stage ->
                val count = counts[stage] ?: return@mapNotNull null
                "${FAILURE_STAGE_LABELS.getValue(stage)}×$count"
            }
            return "候选探测失败：${details.joinToString("、")}"
        }

        /**
         * Google/YouTube 新候选必须落在 Google 官方 goog.json 前缀内才可消耗 TLS 探测槽。
         * 已在同一目标域严格验证过且尚有效的历史候选可继续使用，避免一次地址源更新造成
         * 运行中断；其他平台不受此归属策略影响。
         */
        internal fun candidateOwnershipAllowsUpstream(
            candidatePool: String?,
            address: ByteArray,
            googleRanges: GoogleIpRanges?,
            previouslyVerified: Boolean,
        ): Boolean = candidatePool != GOOGLE_CANDIDATE_POOL ||
            previouslyVerified || googleRanges?.contains(address) == true

        /**
         * 全局探测预算小于域名数时，每轮从不同域开始，避免固定列表尾部永久拿不到探测槽。
         */
        internal fun rotatingIndexes(size: Int, start: Int): IntArray {
            if (size <= 0) return IntArray(0)
            val normalized = Math.floorMod(start, size)
            return IntArray(size) { offset -> (normalized + offset) % size }
        }

        internal fun sourceDegradation(
            metaAvailable: Boolean,
            communityAvailable: Boolean,
            wireSourceAvailable: Boolean,
            verifiedProbeAvailable: Boolean,
        ): String = when {
            !metaAvailable && !communityAvailable && !wireSourceAvailable && !verifiedProbeAvailable ->
                "官方地址源、严格 Wire DoH 与可验证 TLS 候选均不可达；正在沿用最后安全快照"
            !wireSourceAvailable ->
                "严格 Wire DoH 不可达；当前仅使用官方地址源、已验证候选或低信任种子"
            else -> ""
        }

        /** 回归测试使用：规则目录中的 GitHub App 核心域必须进入自适应观测清单。 */
        internal fun targetDomains(): Set<String> =
            DEFAULT_TARGETS.mapTo(LinkedHashSet(), AdaptiveRouteTarget::domain)

        internal fun candidateProbeDue(
            previous: EndpointCandidate?,
            now: Long,
            networkKey: String,
            forceProbe: Boolean,
            requireNoSniProbe: Boolean = false,
            requiredSemanticSignature: String? = null,
        ): Boolean {
            if (forceProbe || previous == null || previous.networkKey != networkKey) return true
            if (
                requiredSemanticSignature != null &&
                previous.semanticProbeSignature != requiredSemanticSignature
            ) return true
            if (now < previous.backoffUntil) return false
            if (requireNoSniProbe && previous.usable(now) && !previous.noSniProbed) return true
            return previous.interceptOnly || previous.capability == RouteCapability.UNUSABLE ||
                now - previous.fetchedAt >= REPROBE_AFTER_MS
        }

        internal fun carryVerifiedCandidateAcrossNetwork(
            previous: EndpointCandidate?,
            now: Long,
            networkKey: String,
        ): EndpointCandidate? {
            if (previous == null || previous.networkKey == networkKey) return null
            if (previous.interceptOnly || previous.capability == RouteCapability.UNUSABLE) return null
            if (previous.expiresAt > 0L && now >= previous.expiresAt) return null
            return previous.copy(
                latencyMs = 0L,
                failures = 0,
                backoffUntil = 0L,
            )
        }

        /**
         * 升级/离线启动合并：持久化快照保留运行时健康与污染观测，当前 APK 的内置计划
         * 补齐新增域；某域已无任何可用上游时，才让内置已验证候选先行兜底。
         */
        internal fun mergeBundledFallback(
            persisted: RouteSnapshot?,
            bundled: RouteSnapshot,
            now: Long,
        ): RouteSnapshot {
            if (persisted == null || persisted === RouteSnapshot.EMPTY) return bundled
            if (bundled.plans.isEmpty()) return persisted
            if (persisted.plans.isEmpty()) {
                return bundled.copy(
                    generation = maxOf(persisted.generation, bundled.generation).coerceAtLeast(1L),
                    metaCidrs = (persisted.metaCidrs + bundled.metaCidrs).toCollection(LinkedHashSet()),
                )
            }
            val plans = LinkedHashMap<String, EndpointPlan>()
            val domains = LinkedHashSet<String>().apply {
                addAll(persisted.plans.keys)
                addAll(bundled.plans.keys)
            }
            for (domain in domains) {
                val saved = persisted.plans[domain]
                val fallback = bundled.plans[domain]
                if (saved == null) {
                    if (fallback != null) plans[domain] = fallback
                    continue
                }
                if (fallback == null) {
                    plans[domain] = saved
                    continue
                }
                val savedHasUsable = saved.candidates.any { it.usable(now) }
                val ordered = if (savedHasUsable) {
                    saved.candidates + fallback.candidates
                } else {
                    fallback.candidates + saved.candidates
                }
                plans[domain] = saved.copy(
                    endpointGroup = saved.endpointGroup.ifBlank { fallback.endpointGroup },
                    includeSubdomains = saved.includeSubdomains || fallback.includeSubdomains,
                    candidates = ordered.distinctBy(EndpointCandidate::address)
                        .take(MAX_CANDIDATES_PER_DOMAIN),
                )
            }
            return persisted.copy(
                generation = maxOf(persisted.generation, bundled.generation).coerceAtLeast(1L),
                plans = plans,
                metaCidrs = (persisted.metaCidrs + bundled.metaCidrs).toCollection(LinkedHashSet()),
            )
        }

        /** alpha=0.25；网络切换由调用方传入 0，避免跨网络污染健康评分。 */
        internal fun latencyEwmaMs(previous: Long, sample: Long): Long {
            val current = sample.coerceIn(0, MAX_EWMA_LATENCY_MS)
            val old = previous.coerceIn(0, MAX_EWMA_LATENCY_MS)
            if (current == 0L) return old
            if (old == 0L) return current
            return (old * 3L + current + 2L) / 4L
        }

        /**
         * 快照硬上限内优先保留本轮显式共享、但可能尚未得到全局探测槽的池种子。
         * 否则大量 Wire DoH 观察地址会按 sourceRank 把这些种子截断，下一轮也就无法继续
         * NO-SNI 轮换。已验证候选始终优先于保留槽，普通候选仍维持原排序语义。
         */
        internal fun rankAndLimitCandidates(
            candidates: Collection<EndpointCandidate>,
            reservedProbeAddresses: Set<String>,
            now: Long,
            limit: Int = MAX_CANDIDATES_PER_DOMAIN,
        ): List<EndpointCandidate> {
            if (limit <= 0) return emptyList()
            return candidates.sortedWith(
                compareBy<EndpointCandidate> { if (it.usable(now)) 0 else 1 }
                    .thenBy {
                        if (!it.usable(now) && it.address in reservedProbeAddresses) 0 else 1
                    }
                    .thenBy { capabilityRank(it.capability) }
                    .thenBy { if (it.latencyMs > 0) it.latencyMs else Long.MAX_VALUE }
                    .thenBy { sourceRank(it.source) }
                    .thenBy { it.failures }
                    .thenBy { it.address },
            ).take(limit)
        }

        /** 未被实时来源重见的历史仅可沿用原对象和原 TTL，禁止刷新 fetchedAt/expiresAt。 */
        internal fun unobservedCandidateBeforeExpiry(
            previous: EndpointCandidate,
            now: Long,
        ): EndpointCandidate? = previous.takeIf { it.expiresAt > now }

        private val MAX_EWMA_LATENCY_MS = TimeUnit.MINUTES.toMillis(5)

        private val FAILURE_STAGE_ORDER = listOf(
            CandidateFailureStage.TCP_CONNECT,
            CandidateFailureStage.TLS_RESET,
            CandidateFailureStage.CERTIFICATE,
            CandidateFailureStage.TLS_HANDSHAKE,
            CandidateFailureStage.HTTP_SEMANTIC,
            CandidateFailureStage.INVALID_ADDRESS,
        )
        private val FAILURE_STAGE_LABELS = mapOf(
            CandidateFailureStage.TCP_CONNECT to "TCP/443 建连超时或拒绝",
            CandidateFailureStage.TLS_RESET to "ClientHello 后连接重置（疑似 SNI 过滤）",
            CandidateFailureStage.CERTIFICATE to "证书链或主机名校验失败",
            CandidateFailureStage.TLS_HANDSHAKE to "TLS 握手失败",
            CandidateFailureStage.HTTP_SEMANTIC to "HTTPS 可达但业务响应不匹配",
            CandidateFailureStage.INVALID_ADDRESS to "地址格式无效",
        )

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

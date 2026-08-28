package org.xiyu.githubdirect.core.routing

import org.xiyu.githubdirect.core.dns.IpAddresses

/**
 * 从上一代安全快照生成受控的同后端候选种子。
 *
 * [AdaptiveRouteTarget.candidatePool] 只声明 CDN/运营方池，[AdaptiveRouteTarget.endpointGroup]
 * 进一步声明应用后端。两者必须同时相同才允许共享 IP：同一证书覆盖多个域并不代表 HTTP
 * 虚拟主机可互换。这里仍只共享 IP，不共享源域的 TLS 验证结论；调用方必须使用目标域
 * 真实主机名、系统信任链再次探测后才能发布。观察型/本机 DNS、过期、intercept-only
 * 和失败候选均不会进入池，因此该机制不是网段扫描或证书绕过。
 */
object CandidatePoolPlanner {

    fun sharedSeeds(
        targets: Collection<AdaptiveRouteTarget>,
        snapshot: RouteSnapshot,
        now: Long,
    ): Map<String, List<String>> {
        val result = LinkedHashMap<String, List<String>>()
        scopedMembers(targets)
            .toSortedMap(compareBy<PoolScope> { it.pool }.thenBy { it.endpointGroup })
            .forEach { (_, members) ->
                if (members.size < 2) return@forEach
                val poolCandidates = members.asSequence()
                    .flatMap { member ->
                        snapshot.plans[member.domain]?.candidates.orEmpty().asSequence()
                    }
                    .filter { candidate ->
                        candidate.usable(now) && candidate.source.canSeedCandidatePool() &&
                            candidate.hasPublicAddress()
                    }
                    .sortedWith(CANDIDATE_ORDER)
                    .distinctBy(EndpointCandidate::address)
                    .take(MAX_ADDRESSES_PER_POOL)
                    .map(EndpointCandidate::address)
                    .toList()
                if (poolCandidates.isEmpty()) return@forEach

                members.sortedBy(AdaptiveRouteTarget::domain).forEach { target ->
                    val targetCandidates = snapshot.plans[target.domain]?.candidates.orEmpty()
                    val targetUsable = targetCandidates
                        .filter { it.usable(now) }
                        .mapTo(LinkedHashSet(), EndpointCandidate::address)
                    val directMissing =
                        (TARGET_USABLE_CANDIDATES - targetUsable.size).coerceAtLeast(0)
                    // 直连候选与 NO-SNI 能力相互独立。即使已有三个 DIRECT_TLS，仍有限
                    // 轮换未尝试的池地址，直到找到一个按目标域验证过的 NO-SNI 上游。
                    val noSniMissing = if (targetCandidates.any {
                            it.usable(now) && it.noSniCapable
                        }
                    ) 0 else NO_SNI_SEARCH_PER_ROUND
                    val requested = maxOf(directMissing, noSniMissing)
                        .coerceAtMost(MAX_SHARED_PER_TARGET)
                    if (requested > 0) {
                        val targetByAddress = targetCandidates.associateBy(EndpointCandidate::address)
                        val shared = poolCandidates.asSequence()
                            .withIndex()
                            // 可用候选已经由目标自身严格验证，不需要再作为池种子重复加入。
                            // 不可用/仅拦截候选则可能只是受全局探测预算影响而尚未真正探测；
                            // 必须允许下一轮重新以 upstreamEligible 池种子进入队列。真正失败的
                            // 候选仍由 GithubHostsProvider.candidateProbeDue 执行网络隔离和退避。
                            .filter { (_, address) ->
                                targetByAddress[address]?.usable(now) != true
                            }
                            .sortedWith(
                                compareBy<IndexedValue<String>> { (_, address) ->
                                    targetRetryPriority(targetByAddress[address])
                                }.thenBy(IndexedValue<String>::index),
                            )
                            .map(IndexedValue<String>::value)
                            .take(requested)
                            .toList()
                        if (shared.isNotEmpty()) result[target.domain] = shared
                    }
                }
            }
        return result
    }

    /** 当前配置中仍有同池、同后端伙伴的目标；用于淘汰旧版本跨后端池历史。 */
    internal fun activeMemberDomains(targets: Collection<AdaptiveRouteTarget>): Set<String> =
        scopedMembers(targets).values.asSequence()
            .filter { it.size >= 2 }
            .flatten()
            .mapTo(LinkedHashSet(), AdaptiveRouteTarget::domain)

    private fun scopedMembers(
        targets: Collection<AdaptiveRouteTarget>,
    ): Map<PoolScope, List<AdaptiveRouteTarget>> = targets.asSequence()
        .filter { !it.candidatePool.isNullOrBlank() && it.endpointGroup.isNotBlank() }
        .groupBy {
            PoolScope(
                pool = requireNotNull(it.candidatePool),
                endpointGroup = it.endpointGroup,
            )
        }

    private data class PoolScope(
        val pool: String,
        val endpointGroup: String,
    )

    private fun CandidateSource.canSeedCandidatePool(): Boolean = when (this) {
        CandidateSource.LOCAL_DNS,
        CandidateSource.DNS_OBSERVER,
        -> false
        else -> true
    }

    private fun EndpointCandidate.hasPublicAddress(): Boolean {
        val raw = IpAddresses.parseIpAddress(address) ?: return false
        return !IpAddresses.isBogonOrPoisoned(raw)
    }

    /**
     * 先完成上一轮因预算未实际探测的地址，再尝试新地址，最后才重试已有失败记录的地址。
     * 这里只决定池种子顺序；失败退避仍由 provider 的统一状态机裁决。
     */
    private fun targetRetryPriority(candidate: EndpointCandidate?): Int = when {
        candidate == null -> 1
        candidate.failures <= 0 -> 0
        else -> 2
    }

    private val CANDIDATE_ORDER =
        compareByDescending<EndpointCandidate> { it.noSniCapable }
            .thenBy { capabilityRank(it.capability) }
            .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
            .thenByDescending(EndpointCandidate::fetchedAt)
            .thenBy(EndpointCandidate::address)

    private fun capabilityRank(capability: RouteCapability): Int = when (capability) {
        RouteCapability.DIRECT_TLS -> 0
        RouteCapability.FRAGMENTED_TLS -> 1
        RouteCapability.NO_SNI_TLS -> 2
        RouteCapability.UNUSABLE -> 3
    }

    internal const val MAX_ADDRESSES_PER_POOL = 12
    internal const val MAX_SHARED_PER_TARGET = 4
    internal const val TARGET_USABLE_CANDIDATES = RouteSnapshot.MAX_ACTIVE_PER_DOMAIN
    internal const val NO_SNI_SEARCH_PER_ROUND = 2
}

package org.xiyu.githubdirect.core.routing

import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.HttpSemanticProbePolicy
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.SuffixMatcher
import org.xiyu.githubdirect.core.rules.TransportPolicy

/**
 * 一个需要由严格 DoH + TLS 主机名验证维护候选的域名根。
 *
 * 候选必须以 [probeDomain] 的真实 SNI 通过系统信任链验证。[candidatePool] 只允许成员
 * 共享已验证 IP 作为待测种子，绝不共享验证结论。后缀规则使用固定的一层代表子域，避免
 * `*.googlevideo.com` 这类只覆盖子域、不服务裸根域的证书被误判；真实连接仍按原始 SNI
 * 逐次校验，模块不会把代表子域写入实际请求。
 */
data class AdaptiveRouteTarget(
    val serviceId: String,
    val domain: String,
    val endpointGroup: String,
    val includeSubdomains: Boolean,
    /** 仅 GitHub 官方 Meta 支持分组；其他平台保持 null。 */
    val githubMetaGroup: String? = null,
    /** 显式 CDN 候选池；仅与相同 [endpointGroup] 共享，且仍按 [domain] 独立验证。 */
    val candidatePool: String? = null,
    /** 仅用于候选能力探测；精确规则等于 [domain]，后缀规则为固定代表子域。 */
    val probeDomain: String = domain,
    /** 可选 ECH 公共配置名；上游地址仍必须来自该目标自己的严格验证候选。 */
    val echConfigDomain: String? = null,
    /** 可选业务语义探测；在同一候选 TLS 连接上校验 HTTP 状态。 */
    val semanticProbe: HttpSemanticProbePolicy? = null,
)

/** 从版本化 profile 生成动态路由目标，避免数据面继续硬编码单个平台。 */
object AdaptiveRouteCatalog {

    fun fromProfiles(
        profiles: Collection<ServiceProfile>,
        isEnabled: (String) -> Boolean,
    ): List<AdaptiveRouteTarget> {
        val targets = LinkedHashMap<String, AdaptiveRouteTarget>()
        profiles.asSequence()
            .filter { isEnabled(it.id) }
            .sortedWith(compareByDescending<ServiceProfile> { it.priority }.thenBy { it.id })
            .forEach { profile ->
                profile.domains.forEach { rule ->
                    if (!isRouteEligible(rule)) return@forEach
                    val matcher = rule.matcher
                    val domain = when (matcher) {
                        is ExactMatcher -> matcher.domain
                        is SuffixMatcher -> matcher.suffix.removePrefix(".")
                        else -> return@forEach
                    }
                    val probeDomain = when (matcher) {
                        is SuffixMatcher -> suffixProbeDomain(domain) ?: return@forEach
                        else -> domain
                    }
                    // 候选快照仍不发布宽通配地址；动态子域由受控后缀 TLS 路由逐连接验证。
                    val includeSubdomains = false
                    val group = rule.endpointGroup?.takeIf(String::isNotBlank)
                        ?: "${profile.id}:$domain"
                    val candidate = AdaptiveRouteTarget(
                        serviceId = profile.id,
                        domain = domain,
                        endpointGroup = group,
                        includeSubdomains = includeSubdomains,
                        githubMetaGroup = if (
                            profile.id == GITHUB_PROFILE && rule.cidrRef == GITHUB_META_REF
                        ) rule.endpointGroup ?: DEFAULT_GITHUB_META_GROUP else null,
                        candidatePool = rule.candidatePool,
                        probeDomain = probeDomain,
                        echConfigDomain = rule.echConfigDomain,
                        semanticProbe = rule.semanticProbe,
                    )
                    val existing = targets[domain]
                    if (existing == null) {
                        targets[domain] = candidate
                    } else if (existing.probeDomain == domain && probeDomain != domain) {
                        // 同一根域同时有 EXACT/SUFFIX 时，保留高优先级目标元数据，但后缀的
                        // 代表子域探测优先，避免裸域没有证书时阻断整个动态域族。
                        targets[domain] = existing.copy(
                            candidatePool = existing.candidatePool ?: candidate.candidatePool,
                            probeDomain = probeDomain,
                            echConfigDomain = existing.echConfigDomain ?: candidate.echConfigDomain,
                        )
                    }
                }
            }
        return targets.values.take(MAX_TARGETS)
    }

    fun filterSnapshot(
        snapshot: RouteSnapshot,
        targets: Collection<AdaptiveRouteTarget>,
        generation: Long = snapshot.generation,
    ): RouteSnapshot {
        val targetsByDomain = targets.associateBy(AdaptiveRouteTarget::domain)
        val githubEnabled = targets.any { it.serviceId == GITHUB_PROFILE }
        return snapshot.copy(
            generation = generation,
            plans = snapshot.plans.mapNotNull { (domain, plan) ->
                val target = targetsByDomain[domain] ?: return@mapNotNull null
                domain to plan.copy(
                    // 清理旧版本可能落盘的宽通配计划，禁止跨 SNI 复用候选。
                    includeSubdomains = plan.includeSubdomains && target.includeSubdomains,
                )
            }.toMap(LinkedHashMap()),
            // 当前 schema 的 metaCidrs 仅承载 GitHub Meta；其他平台使用已验证精确候选。
            metaCidrs = if (githubEnabled) snapshot.metaCidrs else emptySet(),
        )
    }

    private fun isRouteEligible(rule: DomainRule): Boolean = when (rule.transport) {
        TransportPolicy.TLS_FRAGMENT_RELAY,
        TransportPolicy.DIRECT_IP,
        TransportPolicy.CLEAN_DNS,
        -> true
        TransportPolicy.NXDOMAIN,
        TransportPolicy.PASSTHROUGH,
        -> false
    }

    private const val GITHUB_PROFILE = "github"
    private const val GITHUB_META_REF = "github-meta"
    private const val DEFAULT_GITHUB_META_GROUP = "web"
    const val MAX_TARGETS = 96
}

internal fun suffixProbeDomain(root: String): String? =
    DnsNames.normalize("$SUFFIX_PROBE_LABEL.$root")

private const val SUFFIX_PROBE_LABEL = "ghd-probe"

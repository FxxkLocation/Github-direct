package org.xiyu.githubdirect.core.rules

import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.dns.CidrFilter
import java.util.concurrent.ConcurrentHashMap

/**
 * 规则引擎唯一入口（VPN 与 Xposed 共用同一实例）。
 *
 * - index/profiles 构建后只读，match 全程无锁（O(1) + O(L)）
 * - enable 状态经 SettingsStore 惰性缓存（volatile ConcurrentHashMap），
 *   setEnabled 只写缓存 + 触发监听器，不改规则表
 */
class RuleRegistry(
    private val settings: SettingsStore,
    private val profiles: Map<String, ServiceProfile>,
    private val index: MatcherIndex,
) {

    private val enabledCache = ConcurrentHashMap<String, Boolean>()
    private val listeners = ConcurrentHashMap.newKeySet<(String, Boolean) -> Unit>()

    /**
     * 查询策略。null = 未命中任何启用规则 → 调用方走 PASSTHROUGH 语义。
     * 入参必须已 normalize。
     *
     * 仲裁（Agent E 域名验证仲裁需求）：
     * 1. priority 高者胜（NX 屏蔽域通常独占高优先级）
     * 2. 同 priority 下：NXDOMAIN（block）支配任何其他 transport（block 必须支配 allow）
     * 3. 仍并列：profile id 字典序小者胜（稳定排序）
     */
    fun match(normalizedDomain: String): RuleMatch? {
        val rules = index.matchAll(normalizedDomain)
        if (rules.isEmpty()) return null

        var best: IndexedRule? = null
        for (r in rules) {
            if (!isEnabled(r.serviceId)) continue
            if (best == null
                || r.priority > best.priority
                || (r.priority == best.priority && isBlocking(r) && !isBlocking(best))
                || (r.priority == best.priority
                && isBlocking(r) == isBlocking(best) && r.serviceId < best.serviceId)
            ) {
                best = r
            }
        }
        if (best == null) return null

        val profile = profiles[best.serviceId] ?: return null
        val policy = compileDomainPolicy(best.rule, profile)
        // PASSTHROUGH 规则等于未命中
        if (policy.transport == TransportPolicy.PASSTHROUGH) return null
        return RuleMatch(policy = policy, serviceId = best.serviceId)
    }

    /** NXDOMAIN = 屏蔽规则（block），仲裁时支配同 priority 下的 allow 规则。 */
    private fun isBlocking(r: IndexedRule): Boolean =
        r.rule.transport == TransportPolicy.NXDOMAIN

    fun profile(id: String): ServiceProfile? = profiles[id]

    fun enabledProfiles(): List<ServiceProfile> = profiles.values.filter { isEnabled(it.id) }

    fun isEnabled(id: String): Boolean {
        enabledCache[id]?.let { return it }
        val profile = profiles[id]
        val v = settings.isServiceEnabled(id, profile?.enabledByDefault ?: false)
        enabledCache[id] = v
        return v
    }

    fun setEnabled(id: String, enabled: Boolean) {
        if (profiles[id] == null) return
        settings.setServiceEnabled(id, enabled)
        enabledCache[id] = enabled
        notifyListeners(id, enabled)
    }

    /**
     * 批量启用/禁用。持久化只提交一次，监听器只收到一次批量事件，
     * 避免服务管理页“全部开启/关闭”触发几十次 UI/provider 重建。
     */
    fun setEnabledBatch(ids: Collection<String>, enabled: Boolean) {
        val validIds = ids.asSequence().filter { profiles.containsKey(it) }.distinct().toList()
        if (validIds.isEmpty()) return
        settings.setServicesEnabled(validIds, enabled)
        for (id in validIds) enabledCache[id] = enabled
        notifyListeners(BATCH_CHANGE_ID, enabled)
    }

    fun setAllEnabled(enabled: Boolean) {
        setEnabledBatch(profiles.keys, enabled)
    }

    private fun notifyListeners(id: String, enabled: Boolean) {
        for (l in listeners) {
            try {
                l(id, enabled)
            } catch (_: Throwable) {
            }
        }
    }

    fun addChangeListener(l: (serviceId: String, enabled: Boolean) -> Unit) {
        listeners.add(l)
    }

    fun invalidateEnabledCache() {
        enabledCache.clear()
    }

    companion object {
        /** 批量状态变更事件；监听方应重新读取 registry 状态，而不是把它当真实 service id。 */
        const val BATCH_CHANGE_ID = "*"
    }

    private fun compileDomainPolicy(rule: DomainRule, profile: ServiceProfile): DomainPolicy {
        val aaaaSuppress = rule.aaaaSuppress ?: profile.aaaaSuppress
        val fragmentTls = rule.fragmentTls ?: (rule.transport == TransportPolicy.TLS_FRAGMENT_RELAY)
        val cidr: CidrFilter? = rule.cidr ?: profile.cidr
        // 直通：0 = 不启用空闲超时（TcpRelay 处理）；<0 视为 0
        val idleTimeout = if (profile.idleTimeoutSec > 0) profile.idleTimeoutSec else 0
        return DomainPolicy(
            transport = rule.transport,
            resolver = rule.resolver,
            cidr = cidr,
            aaaaSuppress = aaaaSuppress,
            fragmentTls = fragmentTls,
            idleTimeoutSec = idleTimeout,
            fixedIp = rule.fixedIp,
        )
    }
}

/** match 的编译产物，天然不可变。 */
data class RuleMatch(
    val policy: DomainPolicy,
    val serviceId: String,
)

data class DomainPolicy(
    val transport: TransportPolicy,
    val resolver: ResolverPolicy,
    val cidr: CidrFilter?,
    val aaaaSuppress: Boolean,
    val fragmentTls: Boolean,
    val idleTimeoutSec: Int,
    val fixedIp: String?,
)

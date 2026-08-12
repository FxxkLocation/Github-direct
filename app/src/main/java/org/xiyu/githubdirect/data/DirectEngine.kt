package org.xiyu.githubdirect.data

import android.content.Context
import android.util.Log
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.PlainDnsClient
import org.xiyu.githubdirect.core.dns.SelectiveDnsEngine
import org.xiyu.githubdirect.core.dns.WireDohClient
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.VirtualIpPool
import org.xiyu.githubdirect.core.rules.HostsProvider
import org.xiyu.githubdirect.core.rules.IndexedRule
import org.xiyu.githubdirect.core.rules.MatcherIndex
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.vpn.VpnNetworkBinder
import java.util.concurrent.ConcurrentHashMap

/**
 * 引擎装配（进程内静态单例；VPN 服务进程与 Xposed 目标进程各自初始化一份）。
 *
 * - 规则目录：assets/rules/profiles.json → RuleCatalog → MatcherIndex → RuleRegistry
 * - 组件：EndpointResolver / EndpointCache / VirtualIpPool / RelayIpTable / NetworkBinder
 * - providers：仅 VPN 模式启动（withProviders=true），数据只服务声明它的 profile
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
    private var providersMode = false

    private val providers = ConcurrentHashMap<String, HostsProvider>()

    /**
     * 幂等初始化。withProviders=true 时允许从“仅核心”升级为“核心 + providers”。
     * 解决 UI 先 ensureInit(false)、随后 VPN ensureInit(true) 时 provider 永远不启动的问题。
     */
    @JvmStatic
    fun ensureInit(context: Context, withProviders: Boolean): Boolean {
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
                val ctx = context.applicationContext
                val settings = AndroidSettingsStore(ctx)
                val json = loadProfilesJson(ctx)
                val profiles = RuleCatalog.load(json)

                val index = MatcherIndex()
                for (p in profiles.values) {
                    for (r in p.domains) {
                        index.add(IndexedRule(r, p.id, p.priority))
                    }
                }
                index.build()

                val binder = VpnNetworkBinder(ctx)
                val reg = RuleRegistry(settings, profiles, index)
                val resolver = EndpointResolver(binder)
                val cache = EndpointCache()
                val pool = VirtualIpPool()
                val relayTable = RelayIpTable()
                registry = reg
                this.resolver = resolver
                this.cache = cache
                this.pool = pool
                this.relayTable = relayTable
                // 共享 DNS 引擎单例：VPN 服务与 Root 透明后端复用同一实例（构造一次）
                dnsEngine = SelectiveDnsEngine(
                    reg, resolver, cache, pool, relayTable,
                    WireDohClient(), PlainDnsClient(),
                )
                this.binder = binder
                this.settings = settings
                this.profiles = profiles
                providersMode = withProviders
                // 任意服务状态变化后统一 reconcile；批量开关只触发一次。
                reg.addChangeListener { _, _ ->
                    if (providersMode) reconcileProviders()
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

        val required = LinkedHashMap<String, org.xiyu.githubdirect.core.rules.HostsProviderSpec>()
        for (p in profiles.values) {
            if (!reg.isEnabled(p.id)) continue
            for (spec in p.providers) required.putIfAbsent(spec.providerId, spec)
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
                "github-hosts" -> GithubHostsProvider(spec)
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
}

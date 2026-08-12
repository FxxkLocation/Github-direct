package org.xiyu.githubdirect.data

import android.util.Log
import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.TcpProbe
import org.xiyu.githubdirect.core.rules.HostsProvider
import org.xiyu.githubdirect.core.rules.HostsProviderSpec
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * GitHub gitee-hosts 数据源 provider（原 HostsSyncer 改造，实现 HostsProvider）。
 *
 * - HOSTS_URL 保留 gitee 源，作为 github profile 的 provider 配置（非系统基础设施）
 * - RELAY_DOMAINS 常量已删除：relay 名单由规则驱动，探活对所有拉取条目生效
 * - 数据落地 RelayIpTable（copy-on-write）；失败回退 DoH（handler 链保证）
 */
class GithubHostsProvider(
    private val spec: HostsProviderSpec,
) : HostsProvider {

    private val TAG = "GithubHostsProvider"

    override val id: String = spec.providerId

    companion object {
        /** gitee github-hosts 源（github profile 的 provider 配置）。 */
        const val HOSTS_URL = "https://gitee.com/TheDarkStar/github-hosts/raw/master/hosts"
        private const val CONNECT_TIMEOUT_MS = 8000
        private const val READ_TIMEOUT_MS = 8000
        private const val PROBE_TIMEOUT_MS = 4000
    }

    private var store: SettingsStore? = null
    private var binder: NetworkBinder? = null
    private var table: RelayIpTable? = null
    private var scheduler: ScheduledExecutorService? = null

    override fun start(store: SettingsStore, binder: NetworkBinder, table: RelayIpTable) {
        this.store = store
        this.binder = binder
        this.table = table

        // 1. 启动快速路径：从缓存加载（不做探活）
        try {
            val cached = loadCached()
            if (cached.isNotEmpty()) {
                table.update(cached)
                Log.i(TAG, "从缓存加载 ${cached.size} 条 hosts 记录")
            }
        } catch (e: Exception) {
            Log.w(TAG, "加载缓存 hosts 失败: ${e.message}")
        }

        // 2. 立即异步同步 + 定期同步
        scheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "HostsSyncer").apply { isDaemon = true }
        }
        scheduler?.schedule({ syncNow() }, 0, TimeUnit.SECONDS)
        scheduler?.scheduleWithFixedDelay({ syncNow() }, spec.intervalHours, spec.intervalHours, TimeUnit.HOURS)
    }

    override fun stop() {
        scheduler?.shutdownNow()
        scheduler = null
        store = null
        binder = null
        table = null
    }

    override fun loadCached(): Map<String, List<String>> {
        val s = store ?: return emptyMap()
        val (data, _) = s.hostsData(id) ?: return emptyMap()
        return parseHosts(data)
    }

    /**
     * 拉取 + 解析 + TCP 探活验证。
     * @return domain → 可达候选 IP；失败返回 null
     */
    override fun fetch(): Map<String, List<String>>? {
        val b = binder ?: return null
        val data = b.httpGet(HOSTS_URL, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS)
        if (data.isNullOrEmpty()) {
            Log.w(TAG, "Hosts 拉取失败或为空")
            return null
        }

        val hosts = parseHosts(data)
        if (hosts.isEmpty()) {
            Log.w(TAG, "Hosts 解析结果为空")
            return null
        }

        // 探活：不可达 IP 不进入表（relay 域会走 DoH 回退）
        val validated = HashMap<String, List<String>>(hosts.size)
        for ((domain, ips) in hosts) {
            val ok = ips.filter { validateIp(it, spec.tcpProbePort) }
            if (ok.isNotEmpty()) validated[domain] = ok
        }

        val s = store
        if (s != null) {
            try {
                s.saveHostsData(id, data, System.currentTimeMillis())
            } catch (e: Exception) {
                Log.w(TAG, "持久化 hosts 失败: ${e.message}")
            }
        }
        Log.i(TAG, "Hosts 同步成功: ${validated.size} 条记录（探活后）")
        return validated
    }

    override fun validateIp(ip: String, port: Int): Boolean {
        val b = binder ?: return false
        return TcpProbe.isTcpReachable(ip, port, PROBE_TIMEOUT_MS, b)
    }

    private fun syncNow() {
        try {
            val t = table ?: return
            val hosts = fetch() ?: return
            t.update(hosts)
        } catch (e: Exception) {
            Log.w(TAG, "Hosts 同步失败: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * 解析 hosts 文件格式: "IP domain" 每行一条，忽略注释（#开头）和空行。
     * 同域多行聚合为候选 IP 列表；仅接受合法 IPv4。
     */
    private fun parseHosts(data: String?): Map<String, List<String>> {
        val result = HashMap<String, MutableList<String>>()
        if (data == null) return result

        for (rawLine in data.split("\n")) {
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#")) continue

            val parts = line.split("\\s+".toRegex(), limit = 2)
            if (parts.size != 2) continue

            val ip = parts[0].trim()
            val domain = parts[1].trim().lowercase()
            if (IpAddresses.parseIpv4(ip) == null) continue
            if (domain.isEmpty()) continue

            result.getOrPut(domain) { ArrayList(2) }.add(ip)
        }
        return result
    }
}

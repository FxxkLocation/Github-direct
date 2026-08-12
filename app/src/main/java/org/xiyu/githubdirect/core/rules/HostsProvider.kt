package org.xiyu.githubdirect.core.rules

import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.net.RelayIpTable

/**
 * 可选数据源抽象（GitHub gitee-hosts feed 是第一个实现，非基础设施）。
 *
 * 仅当 profile 声明 providers 且服务启用时才启动；数据只服务该 profile 的
 * PROVIDER_FIRST 域，失败自动回退 DoH——provider 不可用时目标服务照常工作。
 */
interface HostsProvider {
    /** provider id（与 HostsProviderSpec.providerId 对应，如 "github-hosts"） */
    val id: String

    /**
     * 启动：先 loadCached() 填充 table（启动快速路径），再异步 fetch()，
     * 之后按 intervalHours 定期 fetch。
     */
    fun start(store: SettingsStore, binder: NetworkBinder, table: RelayIpTable)

    fun stop()

    /** 从持久化缓存加载 domain → candidate IPs（失败返回空 map）。 */
    fun loadCached(): Map<String, List<String>>

    /** 拉取 + 解析 + 探活验证；返回 domain → candidate IPs；失败返回 null。 */
    fun fetch(): Map<String, List<String>>?

    /** TCP 探活（isTcpReachable 迁移）。 */
    fun validateIp(ip: String, port: Int): Boolean
}

package org.xiyu.githubdirect.core.rules

import org.xiyu.githubdirect.core.data.SettingsStore
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.net.RelayIpTable

/**
 * 可选可信候选数据源抽象。GitHub Meta/社区种子只是一个来源；其他平台只采用严格 Wire
 * DoH、系统 DNS 观测与 TLS 主机名/系统信任链探测，不因 provider id 的历史名称降级校验。
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

    /** 用户触发的强制重探；实现可绕过正常刷新周期和候选退避。 */
    fun reprobe(): Map<String, List<String>>? = fetch()

    /** TCP 探活（isTcpReachable 迁移）。 */
    fun validateIp(ip: String, port: Int): Boolean
}

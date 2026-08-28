package org.xiyu.githubdirect.core.net

import java.net.Socket

/**
 * 网络绑定抽象（接口语义；Android 实现见 vpn/VpnNetworkBinder）。
 *
 * - VPN 进程：httpGet 绑底层物理网络（NetworkCallback 维护 current，过滤 TRANSPORT_VPN），
 *   protect 由 VpnService 注入；Xposed 进程：无 TUN，走默认网络。
 * - 所有自发出流量（DoH/抓取/探活）必须经此接口——环回红线。
 */
interface NetworkBinder {

    /**
     * 发起绑定当前底层网络的 HTTP GET。
     * @return 响应体（UTF-8）；网络错误 / 非 200 / 超时 → null
     */
    fun httpGet(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): String?

    /** 普通 HTTPS JSON/文本请求可覆盖 Accept/User-Agent；旧实现自动退化到无自定义头请求。 */
    fun httpGet(
        url: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        headers: Map<String, String>,
    ): String? = httpGet(url, connectTimeoutMs, readTimeoutMs)

    /** 将 Socket 绑定到当前底层网络（无当前网络时 no-op）。 */
    fun bindSocket(socket: Socket)

    /** 用于按网络隔离候选健康状态；实现不可用时返回 stable default。 */
    fun networkKey(): String = "default"

    /** 网络切换通知；返回值关闭后停止监听。 */
    fun addNetworkChangeListener(listener: (String) -> Unit): java.io.Closeable? = null

    /** VPN 模式由 DnsVpnService 注入 VpnService::protect；Xposed 模式为 null。 */
    var protect: ((Socket) -> Boolean)?
}

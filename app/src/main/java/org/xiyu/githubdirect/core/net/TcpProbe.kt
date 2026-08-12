package org.xiyu.githubdirect.core.net

import org.xiyu.githubdirect.core.dns.IpAddresses
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * TCP 连通性探活（从原 HostsSyncer.isTcpReachable 迁移，bind 走 NetworkBinder）。
 */
object TcpProbe {

    /**
     * 检测 ip:port 的 TCP 连通性。
     * @param binder 绑定底层物理网络（VPN 进程防环回；Xposed 无 TUN 时 no-op）
     */
    fun isTcpReachable(ip: String, port: Int, timeoutMs: Int, binder: NetworkBinder): Boolean {
        val addrBytes = IpAddresses.parseIpv4(ip) ?: return false
        var socket: Socket? = null
        try {
            socket = Socket()
            binder.bindSocket(socket)
            socket.connect(InetSocketAddress(InetAddress.getByAddress(addrBytes), port), timeoutMs)
            return true
        } catch (_: Exception) {
            return false
        } finally {
            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }
}

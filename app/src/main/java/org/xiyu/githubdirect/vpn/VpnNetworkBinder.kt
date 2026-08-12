package org.xiyu.githubdirect.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log
import org.xiyu.githubdirect.core.net.NetworkBinder
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL

/**
 * NetworkBinder 的 Android 实现（vpn 进程）。
 *
 * - ConnectivityManager.NetworkCallback 维护 current（过滤 TRANSPORT_VPN），
 *   网络切换时自动更新（修复原一次性快照问题）
 * - httpGet / bindSocket 全部绑 current；无 current 时走默认网络
 * - protect 由 DnsVpnService 在 VPN 启动时注入（VpnService::protect）
 */
class VpnNetworkBinder(context: Context) : NetworkBinder {

    private val TAG = "VpnNetworkBinder"
    private val cm: ConnectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Volatile
    private var current: Network? = null

    @Volatile
    override var protect: ((Socket) -> Boolean)? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            updateCurrent()
        }

        override fun onLost(network: Network) {
            if (network == current) updateCurrent()
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            updateCurrent()
        }
    }

    /** 注册网络回调（VPN 启动时）。幂等。 */
    @Synchronized
    fun start() {
        try {
            cm.registerDefaultNetworkCallback(callback)
            updateCurrent()
        } catch (e: Exception) {
            Log.w(TAG, "注册网络回调失败: ${e.message}")
        }
    }

    /** 注销网络回调（VPN 停止时）。幂等。 */
    @Synchronized
    fun stop() {
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (_: Exception) {
        }
        current = null
    }

    private fun updateCurrent() {
        try {
            // 优先 activeNetwork（非 VPN）
            val n = cm.activeNetwork
            if (n != null) {
                val caps = cm.getNetworkCapabilities(n)
                if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    current = n
                    return
                }
            }
            // activeNetwork 是本服务的 TUN（VPN 已建立）→ 沿用上次已知的底层网络快照
            if (current != null) return
            // 快照缺失 → 遍历所有网络找任一非 VPN 且具 INTERNET 能力的底层网络
            for (net in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                ) {
                    current = net
                    return
                }
            }
            // 找不到任何底层网络则不更新（httpGet 回退默认网络，物理网络不可达时本就会失败）
        } catch (e: Exception) {
            Log.w(TAG, "更新当前网络失败: ${e.message}")
        }
    }

    override fun httpGet(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): String? {
        val conn: HttpURLConnection = try {
            val u = URL(url)
            (current?.openConnection(u) as? HttpURLConnection)
                ?: (u.openConnection() as HttpURLConnection)
        } catch (e: Exception) {
            Log.w(TAG, "httpGet 打开连接失败: ${e.message}")
            return null
        }
        try {
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/dns-json")
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            conn.instanceFollowRedirects = true

            val code = conn.responseCode
            if (code != 200) {
                Log.w(TAG, "httpGet HTTP $code: $url")
                return null
            }
            return conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (e: Exception) {
            Log.w(TAG, "httpGet 失败: ${e.message}")
            return null
        } finally {
            try {
                conn.disconnect()
            } catch (_: Exception) {
            }
        }
    }

    override fun bindSocket(socket: Socket) {
        try {
            current?.bindSocket(socket)
        } catch (e: Exception) {
            Log.w(TAG, "bindSocket 失败: ${e.message}")
        }
    }
}

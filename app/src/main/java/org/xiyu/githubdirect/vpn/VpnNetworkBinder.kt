package org.xiyu.githubdirect.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import org.xiyu.githubdirect.core.net.NetworkBinder
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.ConcurrentHashMap

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

    @Volatile
    private var started = false
    private val networkListeners = CopyOnWriteArraySet<(String) -> Unit>()
    private val physicalNetworks = ConcurrentHashMap<Network, NetworkCapabilities>()
    @Volatile private var lastNetworkKey = "default"

    private val callback = object : ConnectivityManager.NetworkCallback() {
        // API 26+ 会紧随 onAvailable 有序回调 onCapabilitiesChanged。官方明确
        // 不建议在 onAvailable 里同步查 capabilities，否则可能读到过期状态。
        override fun onAvailable(network: Network) = Unit

        override fun onLost(network: Network) {
            physicalNetworks.remove(network)
            if (network == current) {
                current = null
                updateCurrent(allowSynchronousLookup = false)
            }
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            physicalNetworks[network] = networkCapabilities
            updateCurrent(allowSynchronousLookup = false)
        }
    }

    /** 注册网络回调（VPN / Root 启动时）。幂等。 */
    @Synchronized
    fun start() {
        if (started) {
            updateCurrent(allowSynchronousLookup = true)
            return
        }
        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(request, callback)
            started = true
            // start() 不在 NetworkCallback 内，可用一次同步查询填补初始快照。
            updateCurrent(allowSynchronousLookup = true)
        } catch (e: Exception) {
            Log.w(TAG, "注册网络回调失败: ${e.message}")
        }
    }

    /** 注销网络回调（VPN 停止时）。幂等。 */
    @Synchronized
    fun stop() {
        if (started) {
            try {
                cm.unregisterNetworkCallback(callback)
            } catch (_: Exception) {
            }
        }
        started = false
        current = null
        physicalNetworks.clear()
    }

    private fun updateCurrent(allowSynchronousLookup: Boolean) {
        val before = networkKey()
        try {
            // 优先 activeNetwork（非 VPN）
            val n = cm.activeNetwork
            if (n != null) {
                val caps = physicalNetworks[n] ?: if (allowSynchronousLookup) {
                    cm.getNetworkCapabilities(n)?.also { physicalNetworks[n] = it }
                } else {
                    null
                }
                if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    current = n
                    notifyNetworkChanged(before)
                    return
                }
            }
            // activeNetwork 是 TUN 时，从持续回调维护的物理网络集合选择；不再轮询已废弃的 allNetworks。
            val selected = physicalNetworks.entries
                .asSequence()
                .filter { (_, caps) -> !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }
                .sortedWith(
                    compareByDescending<Map.Entry<Network, NetworkCapabilities>> {
                        it.value.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    }.thenByDescending { it.value.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }
                        .thenBy { it.key.networkHandle },
                )
                .map { it.key }
                .firstOrNull()
            current = selected
            notifyNetworkChanged(before)
        } catch (e: Exception) {
            Log.w(TAG, "更新当前网络失败: ${e.message}")
        }
    }

    override fun networkKey(): String {
        val network = current ?: return "default"
        val transport = try {
            // callback 路径已经传入有序 capabilities；只在极早的初始化窗口同步补查。
            val caps = physicalNetworks[network] ?: cm.getNetworkCapabilities(network)
            when {
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ethernet"
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) == true -> "bluetooth"
                else -> "other"
            }
        } catch (_: Throwable) {
            "unknown"
        }
        return "network:${network.networkHandle}:$transport"
    }

    override fun addNetworkChangeListener(listener: (String) -> Unit): java.io.Closeable {
        networkListeners += listener
        return java.io.Closeable { networkListeners -= listener }
    }

    private fun notifyNetworkChanged(previous: String) {
        val fresh = networkKey()
        if (fresh == previous && fresh == lastNetworkKey) return
        lastNetworkKey = fresh
        for (listener in networkListeners) {
            try {
                listener(fresh)
            } catch (_: Throwable) {
            }
        }
    }

    override fun httpGet(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): String? {
        return httpGet(url, connectTimeoutMs, readTimeoutMs, emptyMap())
    }

    override fun httpGet(
        url: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        headers: Map<String, String>,
    ): String? {
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
            if (headers.isEmpty()) {
                conn.setRequestProperty("Accept", "application/dns-json")
            } else {
                for ((name, value) in headers) conn.setRequestProperty(name, value)
            }
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
            protect?.let { callback ->
                if (!callback(socket)) Log.w(TAG, "VpnService.protect 失败，继续尝试绑定物理 Network")
            }
            current?.bindSocket(socket)
        } catch (e: Exception) {
            Log.w(TAG, "bindSocket 失败: ${e.message}")
        }
    }
}

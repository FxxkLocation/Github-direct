package org.xiyu.githubdirect.core.dns

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import org.xiyu.githubdirect.core.net.NetworkBinder
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

/**
 * Android Wire DoH 传输：用 OkHttp 提供 HTTP/2/ALPN，同时保持固定 IP bootstrap 与系统 TLS 校验。
 *
 * URL、SNI 和证书验证始终使用 endpoint.hostname；自定义 [Dns] 只把该主机解析到声明的 IP。
 * 不跟随重定向、不使用系统代理、不放宽 HostnameVerifier/TrustManager。
 */
class OkHttpWireDohTransport(private val binder: NetworkBinder) {

    private val clients = ConcurrentHashMap<WireDohClient.WireEndpoint, OkHttpClient>()
    private val baseClient = OkHttpClient.Builder()
        .socketFactory(BindingSocketFactory(binder))
        .proxy(Proxy.NO_PROXY)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
        .build()

    fun post(endpoint: WireDohClient.WireEndpoint, query: ByteArray, timeoutMs: Int): ByteArray? {
        if (query.size < 12 || timeoutMs <= 0) return null
        val client = try {
            clients.computeIfAbsent(endpoint, ::clientFor)
        } catch (_: Throwable) {
            return null
        }
        val request = try {
            Request.Builder()
                .url("https://${endpoint.hostname}:${endpoint.port}${endpoint.path}")
                .header("Accept", DNS_MEDIA_TYPE_VALUE)
                .post(query.toRequestBody(DNS_MEDIA_TYPE))
                .build()
        } catch (_: IllegalArgumentException) {
            return null
        }
        val call = client.newCall(request)
        call.timeout().timeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        return try {
            call.execute().use { response ->
                if (response.code != 200 || response.isRedirect) {
                    return null
                }
                val mediaType = response.body.contentType()?.toString()?.substringBefore(';')?.trim()
                if (!mediaType.equals(DNS_MEDIA_TYPE_VALUE, ignoreCase = true)) {
                    return null
                }
                val declared = response.body.contentLength()
                if (declared > MAX_RESPONSE_BYTES) {
                    return null
                }
                val bytes = readLimited(response.body.byteStream(), MAX_RESPONSE_BYTES) ?: return null
                bytes.takeIf { WireDohClient.isResponseForQuery(query, it) }
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun clientFor(endpoint: WireDohClient.WireEndpoint): OkHttpClient {
        val raw = IpAddresses.parseIpAddress(endpoint.ip)
            ?: throw IllegalArgumentException("invalid DoH endpoint IP")
        val fixed = InetAddress.getByAddress(endpoint.hostname, raw)
        val dns = Dns { hostname ->
            if (!hostname.equals(endpoint.hostname, ignoreCase = true)) {
                throw UnknownHostException("unexpected DoH hostname: $hostname")
            }
            listOf(fixed)
        }
        return baseClient.newBuilder().dns(dns).build()
    }

    private fun readLimited(input: java.io.InputStream, limit: Int): ByteArray? {
        input.use { stream ->
            val output = ByteArrayOutputStream(minOf(4096, limit))
            val buffer = ByteArray(4096)
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) return output.toByteArray()
                if (output.size() + count > limit) return null
                output.write(buffer, 0, count)
            }
        }
    }

    private class BindingSocketFactory(
        private val binder: NetworkBinder,
        private val delegate: SocketFactory = SocketFactory.getDefault(),
    ) : SocketFactory() {
        override fun createSocket(): Socket = bind(delegate.createSocket())

        override fun createSocket(host: String, port: Int): Socket =
            createSocket().apply { connect(InetSocketAddress(host, port)) }

        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
            createSocket().apply {
                bind(InetSocketAddress(localHost, localPort))
                connect(InetSocketAddress(host, port))
            }

        override fun createSocket(host: InetAddress, port: Int): Socket =
            createSocket().apply { connect(InetSocketAddress(host, port)) }

        override fun createSocket(
            address: InetAddress,
            port: Int,
            localAddress: InetAddress,
            localPort: Int,
        ): Socket = createSocket().apply {
            bind(InetSocketAddress(localAddress, localPort))
            connect(InetSocketAddress(address, port))
        }

        private fun bind(socket: Socket): Socket = socket.apply { binder.bindSocket(this) }
    }

    companion object {
        /** Android 生产入口：固定 IP bootstrap + 系统 TLS 校验 + HTTP/2/ALPN。 */
        @JvmStatic
        fun createClient(binder: NetworkBinder): WireDohClient {
            val transport = OkHttpWireDohTransport(binder)
            return WireDohClient(
                binder = binder,
                transport = transport::post,
            )
        }

        private const val DNS_MEDIA_TYPE_VALUE = "application/dns-message"
        private val DNS_MEDIA_TYPE = DNS_MEDIA_TYPE_VALUE.toMediaType()
        private const val MAX_RESPONSE_BYTES = 128 * 1024
    }
}

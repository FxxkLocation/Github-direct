package org.xiyu.githubdirect.core.net

import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.routing.RouteCapability
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLContext
import javax.net.ssl.HttpsURLConnection

/**
 * 对 domain@IP 执行系统信任链 + HTTPS 主机名验证，并分别测试原始和 TLS-record 分片握手。
 * 使用 SSLEngine 生成真实 ClientHello，不安装 CA、不关闭证书校验。
 */
class TlsEndpointProbe(
    private val binder: NetworkBinder,
    private val timeoutMs: Int = 3000,
    private val clockNanos: () -> Long = System::nanoTime,
) {
    data class Result(
        val capability: RouteCapability,
        val latencyMs: Long,
        val error: String = "",
        /** 主能力成功时仍单独记录同地址的无 SNI 能力。 */
        val noSniCapable: Boolean = capability == RouteCapability.NO_SNI_TLS,
        /** true 表示本轮确实完成过严格无 SNI 握手，而不是默认 false。 */
        val noSniProbed: Boolean = noSniCapable,
    )

    fun probe(domain: String, address: String, allowNoSni: Boolean = false): Result {
        if (IpAddresses.parseIpAddress(address) == null) {
            return Result(RouteCapability.UNUSABLE, 0, "invalid address")
        }
        val direct = handshake(domain, address, fragment = false, sendSni = true)
        if (direct.first) {
            return acceptedResult(
                domain,
                address,
                RouteCapability.DIRECT_TLS,
                direct.second,
                allowNoSni,
            )
        }
        val fragmentErrors = ArrayList<String>(MAX_FRAGMENT_ATTEMPTS)
        for (attempt in 0 until MAX_FRAGMENT_ATTEMPTS) {
            val fragmented = handshake(domain, address, fragment = true, sendSni = true)
            if (fragmented.first) {
                return acceptedResult(
                    domain,
                    address,
                    RouteCapability.FRAGMENTED_TLS,
                    fragmented.second,
                    allowNoSni,
                )
            }
            fragmentErrors += fragmented.third
            // TCP 已超时/不可达时随机重排 ClientHello 没有意义；只重试主动重置类失败。
            if (!fragmented.third.contains("reset", ignoreCase = true)) break
        }
        val noSni = if (allowNoSni) {
            handshake(domain, address, fragment = false, sendSni = false)
        } else {
            Triple(false, 0L, "no-SNI probe disabled")
        }
        if (noSni.first) {
            return Result(
                RouteCapability.NO_SNI_TLS,
                noSni.second,
                noSniCapable = true,
                noSniProbed = true,
            )
        }
        return Result(
            RouteCapability.UNUSABLE,
            0,
            (listOf(direct.third) + fragmentErrors + noSni.third)
                .filter { it.isNotBlank() && it != "no-SNI probe disabled" }
                .joinToString("; ")
                .take(240),
            noSniProbed = allowNoSni,
        )
    }

    private fun acceptedResult(
        domain: String,
        address: String,
        capability: RouteCapability,
        latencyMs: Long,
        allowNoSni: Boolean,
    ): Result {
        if (!allowNoSni) return Result(capability, latencyMs)
        val noSni = handshake(domain, address, fragment = false, sendSni = false)
        return Result(
            capability = capability,
            latencyMs = latencyMs,
            noSniCapable = noSni.first,
            noSniProbed = true,
        )
    }

    private fun handshake(
        domain: String,
        address: String,
        fragment: Boolean,
        sendSni: Boolean,
    ): Triple<Boolean, Long, String> {
        val started = clockNanos()
        val deadline = started + timeoutMs.toLong() * 1_000_000L
        val socket = Socket()
        try {
            binder.bindSocket(socket)
            socket.connect(InetSocketAddress(address, 443), remainingMs(deadline))
            socket.tcpNoDelay = true
            socket.soTimeout = remainingMs(deadline)

            val context = SSLContext.getDefault()
            val engine = (if (sendSni) context.createSSLEngine(domain, 443) else context.createSSLEngine()).apply {
                useClientMode = true
                sslParameters = sslParameters.apply {
                    if (sendSni) {
                        endpointIdentificationAlgorithm = "HTTPS"
                        serverNames = listOf(SNIHostName(domain))
                    } else {
                        // 不发送 server_name，但仍由默认 TrustManager 校验证书链；握手完成后
                        // 再按原始域名执行主机名校验，不能把“无 SNI”降级成 TrustAll。
                        endpointIdentificationAlgorithm = null
                        serverNames = emptyList()
                    }
                }
                beginHandshake()
            }
            var netIn = ByteBuffer.allocate(maxOf(64 * 1024, engine.session.packetBufferSize * 2))
            var netOut = ByteBuffer.allocate(maxOf(64 * 1024, engine.session.packetBufferSize * 2))
            var appIn = ByteBuffer.allocate(maxOf(32 * 1024, engine.session.applicationBufferSize * 2))
            val empty = ByteBuffer.allocate(0)
            val readBuffer = ByteArray(16 * 1024)
            var status = engine.handshakeStatus
            var firstWrap = true
            var needRead = true

            while (clockNanos() < deadline) {
                when (status) {
                    SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                        while (true) engine.delegatedTask?.run() ?: break
                        status = engine.handshakeStatus
                    }
                    SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                        netOut.clear()
                        var result = engine.wrap(empty, netOut)
                        if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                            netOut = ByteBuffer.allocate(netOut.capacity() * 2)
                            result = engine.wrap(empty, netOut)
                        }
                        if (result.status == SSLEngineResult.Status.CLOSED) {
                            return Triple(false, 0, "engine closed while wrapping")
                        }
                        netOut.flip()
                        val bytes = ByteArray(netOut.remaining())
                        netOut.get(bytes)
                        socket.soTimeout = remainingMs(deadline)
                        if (fragment && firstWrap) writeFragmented(socket, bytes, deadline)
                        else socket.getOutputStream().apply { write(bytes); flush() }
                        firstWrap = false
                        status = result.handshakeStatus
                    }
                    SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                        if (needRead) {
                            socket.soTimeout = remainingMs(deadline)
                            val count = socket.getInputStream().read(readBuffer)
                            if (count < 0) return Triple(false, 0, "peer closed during handshake")
                            if (netIn.remaining() < count) netIn = grow(netIn, count)
                            netIn.put(readBuffer, 0, count)
                        }
                        netIn.flip()
                        appIn.clear()
                        var result = engine.unwrap(netIn, appIn)
                        netIn.compact()
                        if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                            appIn = ByteBuffer.allocate(appIn.capacity() * 2)
                            netIn.flip()
                            result = engine.unwrap(netIn, appIn)
                            netIn.compact()
                        }
                        when (result.status) {
                            SSLEngineResult.Status.BUFFER_UNDERFLOW -> needRead = true
                            SSLEngineResult.Status.CLOSED -> return Triple(false, 0, "peer rejected handshake")
                            else -> needRead = netIn.position() == 0
                        }
                        status = result.handshakeStatus
                    }
                    SSLEngineResult.HandshakeStatus.FINISHED,
                    SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                        // sendSni 路径由 endpointIdentificationAlgorithm 校验；无 SNI 路径仍须
                        // 显式把上游证书绑定到原始域名。
                        engine.session.peerCertificates
                        if (!sendSni && !HttpsURLConnection.getDefaultHostnameVerifier()
                                .verify(domain, engine.session)
                        ) {
                            return Triple(false, 0, "hostname verification failed without SNI")
                        }
                        val elapsed = (clockNanos() - started) / 1_000_000L
                        return Triple(true, elapsed.coerceAtLeast(1), "")
                    }
                }
            }
            return Triple(false, 0, "TLS deadline exceeded")
        } catch (t: Throwable) {
            return Triple(false, 0, t.javaClass.simpleName + ": " + (t.message ?: "failed"))
        } finally {
            try {
                socket.close()
            } catch (_: Throwable) {
            }
        }
    }

    private fun writeFragmented(socket: Socket, bytes: ByteArray, deadline: Long) {
        val fragmented = TlsClientHelloRecords.fragment(bytes)
        if (fragmented == null) {
            socket.getOutputStream().apply { write(bytes); flush() }
            return
        }
        val output = socket.getOutputStream()
        val writePlan = TlsClientHelloRecords.tcpWritePlan(fragmented.bytes)
        val writeEnds = writePlan.writeEnds
        var start = 0
        for ((index, end) in writeEnds.withIndex()) {
            if (end <= start || end > fragmented.bytes.size) continue
            output.write(fragmented.bytes, start, end - start)
            output.flush()
            start = end
            if (index == writePlan.urgentAfterWriteIndex && start < fragmented.bytes.size) {
                // 与正常字节流分离的 TCP urgent byte；失败时退化为纯多层分片。
                runCatching { socket.sendUrgentData('a'.code) }
            }
            if (start < fragmented.bytes.size) {
                Thread.sleep(minOf(TlsClientHelloRecords.WRITE_INTERVAL_MS, remainingMs(deadline).toLong()))
            }
        }
    }

    private fun grow(buffer: ByteBuffer, incoming: Int): ByteBuffer {
        val needed = buffer.position() + incoming
        var capacity = buffer.capacity()
        while (capacity < needed && capacity < MAX_NET_BUFFER) capacity *= 2
        if (capacity < needed) throw IllegalStateException("TLS input exceeds $MAX_NET_BUFFER")
        val replacement = ByteBuffer.allocate(capacity)
        buffer.flip()
        replacement.put(buffer)
        return replacement
    }

    private fun remainingMs(deadline: Long): Int =
        ((deadline - clockNanos()) / 1_000_000L).toInt().coerceIn(1, timeoutMs)

    companion object {
        private const val MAX_NET_BUFFER = 256 * 1024
        private const val MAX_FRAGMENT_ATTEMPTS = 2
    }
}

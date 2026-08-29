package org.xiyu.githubdirect.core.net

import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.routing.CandidateFailureStage
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.rules.HttpSemanticProbePolicy
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLContext

/**
 * 对 domain@IP 执行系统信任链 + HTTPS 主机名验证，并分别测试原始和 TLS-record 分片握手。
 * 使用 SSLEngine 生成真实 ClientHello，不安装 CA、不关闭证书校验。可选业务探测在同一条
 * 已验证 TLS 连接上发送有界 HTTP/1.1 请求，避免证书兼容但虚拟主机不兼容的 CDN 地址。
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
        val failureStage: CandidateFailureStage = CandidateFailureStage.NONE,
    )

    fun probe(
        domain: String,
        address: String,
        allowNoSni: Boolean = false,
        semanticProbe: HttpSemanticProbePolicy? = null,
    ): Result {
        if (IpAddresses.parseIpAddress(address) == null) {
            return Result(
                RouteCapability.UNUSABLE,
                0,
                "invalid address",
                failureStage = CandidateFailureStage.INVALID_ADDRESS,
            )
        }
        val direct = handshake(domain, address, fragment = false, sendSni = true, semanticProbe)
        if (direct.success) {
            return acceptedResult(
                domain,
                address,
                RouteCapability.DIRECT_TLS,
                direct.latencyMs,
                allowNoSni,
                semanticProbe,
            )
        }
        // 分片与无 SNI 只会改变 ClientHello。若 TCP 尚未建立，重复连接只会把一次超时
        // 放大为三次；若严格 TLS 已完成但 HTTP 语义不匹配，改变 ClientHello 也不会把
        // 错误虚拟主机变成目标业务。交给后续有界退避重试，避免一轮重探被不可达候选拖慢。
        if (!tlsBypassMayChangeOutcome(direct.failureStage)) {
            return Result(
                capability = RouteCapability.UNUSABLE,
                latencyMs = 0,
                error = direct.error.take(240),
                noSniProbed = false,
                failureStage = direct.failureStage,
            )
        }
        val fragmentFailures = ArrayList<HandshakeResult>(MAX_FRAGMENT_ATTEMPTS)
        var noSni: HandshakeResult? = null
        for (attempt in 0 until MAX_FRAGMENT_ATTEMPTS) {
            val fragmented = handshake(domain, address, fragment = true, sendSni = true, semanticProbe)
            if (fragmented.success) {
                return acceptedResult(
                    domain,
                    address,
                    RouteCapability.FRAGMENTED_TLS,
                    fragmented.latencyMs,
                    allowNoSni,
                    semanticProbe,
                )
            }
            fragmentFailures += fragmented
            // 分片仍是无需 CA 的首选，但不要让第二个随机分片把严格 NO-SNI 探测推到
            // 全局 probe deadline 之后。第一种分片失败后立即确认 NO-SNI；若它也失败，
            // TLS_RESET 才继续第二种布局。成功结果仍完成公开链、原主机名和可选语义校验。
            if (allowNoSni && noSni == null) {
                val noSniAttempt =
                    handshake(domain, address, fragment = false, sendSni = false, semanticProbe)
                noSni = noSniAttempt
                if (noSniAttempt.success) {
                    return Result(
                        RouteCapability.NO_SNI_TLS,
                        noSniAttempt.latencyMs,
                        noSniCapable = true,
                        noSniProbed = true,
                    )
                }
            }
            // TCP 已超时/不可达时随机重排 ClientHello 没有意义；只重试主动重置类失败。
            if (fragmented.failureStage != CandidateFailureStage.TLS_RESET) break
        }
        if (allowNoSni && noSni == null) {
            // MAX_FRAGMENT_ATTEMPTS 当前至少为 1；保留此分支，避免未来调整探测次数后
            // 静默失去 NO-SNI 能力发现。
            noSni = handshake(domain, address, fragment = false, sendSni = false, semanticProbe)
        }
        val successfulNoSni = noSni?.takeIf(HandshakeResult::success)
        if (successfulNoSni != null) {
            return Result(
                RouteCapability.NO_SNI_TLS,
                successfulNoSni.latencyMs,
                noSniCapable = true,
                noSniProbed = true,
            )
        }
        val failures = buildList {
            add(direct)
            addAll(fragmentFailures)
            noSni?.let(::add)
        }
        return Result(
            RouteCapability.UNUSABLE,
            0,
            failures.map(HandshakeResult::error)
                .filter(String::isNotBlank)
                .distinct()
                .joinToString("; ")
                .take(240),
            noSniProbed = allowNoSni,
            failureStage = dominantFailureStage(failures.map(HandshakeResult::failureStage)),
        )
    }

    private fun acceptedResult(
        domain: String,
        address: String,
        capability: RouteCapability,
        latencyMs: Long,
        allowNoSni: Boolean,
        semanticProbe: HttpSemanticProbePolicy?,
    ): Result {
        if (!allowNoSni) return Result(capability, latencyMs)
        val noSni = handshake(domain, address, fragment = false, sendSni = false, semanticProbe)
        return Result(
            capability = capability,
            latencyMs = latencyMs,
            noSniCapable = noSni.success,
            noSniProbed = true,
        )
    }

    private fun handshake(
        domain: String,
        address: String,
        fragment: Boolean,
        sendSni: Boolean,
        semanticProbe: HttpSemanticProbePolicy?,
    ): HandshakeResult {
        val started = clockNanos()
        val deadline = started + timeoutMs.toLong() * 1_000_000L
        val socket = Socket()
        var connected = false
        var clientHelloWriteStarted = false
        var tlsIdentityValidated = false
        try {
            binder.bindSocket(socket)
            socket.connect(InetSocketAddress(address, 443), remainingMs(deadline))
            connected = true
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
                        runDelegatedTasks(engine)
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
                            return failed("engine closed while wrapping", CandidateFailureStage.TLS_HANDSHAKE)
                        }
                        netOut.flip()
                        val bytes = ByteArray(netOut.remaining())
                        netOut.get(bytes)
                        socket.soTimeout = remainingMs(deadline)
                        if (firstWrap) clientHelloWriteStarted = true
                        if (fragment && firstWrap) writeFragmented(socket, bytes, deadline)
                        else socket.getOutputStream().apply { write(bytes); flush() }
                        firstWrap = false
                        status = result.handshakeStatus
                    }
                    SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                        if (needRead) {
                            socket.soTimeout = remainingMs(deadline)
                            val count = socket.getInputStream().read(readBuffer)
                            if (count < 0) {
                                return failed("peer closed during handshake", CandidateFailureStage.TLS_HANDSHAKE)
                            }
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
                            SSLEngineResult.Status.CLOSED -> {
                                return failed("peer rejected handshake", CandidateFailureStage.TLS_HANDSHAKE)
                            }
                            else -> needRead = netIn.position() == 0
                        }
                        status = result.handshakeStatus
                    }
                    SSLEngineResult.HandshakeStatus.FINISHED,
                    SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                    -> {
                        // sendSni 路径由 endpointIdentificationAlgorithm 校验；无 SNI 路径仍须
                        // 显式把上游证书绑定到原始域名。
                        engine.session.peerCertificates
                        if (!sendSni && !HttpsURLConnection.getDefaultHostnameVerifier()
                                .verify(domain, engine.session)
                        ) {
                            return failed(
                                "hostname verification failed without SNI",
                                CandidateFailureStage.CERTIFICATE,
                            )
                        }
                        tlsIdentityValidated = true
                        if (semanticProbe != null) {
                            val semantic = probeHttpSemantic(
                                engine,
                                socket,
                                netIn,
                                netOut,
                                appIn,
                                domain,
                                semanticProbe,
                                deadline,
                            )
                            if (!semantic.success) {
                                return failed(semantic.error, CandidateFailureStage.HTTP_SEMANTIC)
                            }
                        }
                        val elapsed = (clockNanos() - started) / 1_000_000L
                        return HandshakeResult(true, elapsed.coerceAtLeast(1), "")
                    }
                }
            }
            return failed("TLS deadline exceeded", CandidateFailureStage.TLS_HANDSHAKE)
        } catch (t: Throwable) {
            val stage = when {
                !connected -> CandidateFailureStage.TCP_CONNECT
                isCertificateFailure(t) -> CandidateFailureStage.CERTIFICATE
                tlsIdentityValidated && semanticProbe != null -> CandidateFailureStage.HTTP_SEMANTIC
                clientHelloWriteStarted && isConnectionReset(t) -> CandidateFailureStage.TLS_RESET
                else -> CandidateFailureStage.TLS_HANDSHAKE
            }
            return failed(t.javaClass.simpleName + ": " + (t.message ?: "failed"), stage)
        } finally {
            try {
                socket.close()
            } catch (_: Throwable) {
            }
        }
    }

    private fun probeHttpSemantic(
        engine: SSLEngine,
        socket: Socket,
        initialNetIn: ByteBuffer,
        initialNetOut: ByteBuffer,
        initialAppIn: ByteBuffer,
        domain: String,
        policy: HttpSemanticProbePolicy,
        deadline: Long,
    ): SemanticResult {
        var netIn = initialNetIn
        var netOut = initialNetOut
        var appIn = initialAppIn
        val request = ByteBuffer.wrap(
            buildString {
                append("GET ").append(policy.path).append(" HTTP/1.1\r\n")
                append("Host: ").append(domain).append("\r\n")
                append("User-Agent: Github-direct-probe/1\r\n")
                append("Accept: */*\r\n")
                append("Connection: close\r\n\r\n")
            }.toByteArray(Charsets.US_ASCII),
        )
        while (request.hasRemaining() && clockNanos() < deadline) {
            netOut.clear()
            var result = engine.wrap(request, netOut)
            if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                netOut = ByteBuffer.allocate(netOut.capacity() * 2)
                result = engine.wrap(request, netOut)
            }
            if (result.status == SSLEngineResult.Status.CLOSED) {
                return SemanticResult(false, "TLS closed before semantic request")
            }
            if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runDelegatedTasks(engine)
            }
            netOut.flip()
            if (netOut.hasRemaining()) {
                val bytes = ByteArray(netOut.remaining())
                netOut.get(bytes)
                socket.soTimeout = remainingMs(deadline)
                socket.getOutputStream().apply { write(bytes); flush() }
            }
        }
        if (request.hasRemaining()) return SemanticResult(false, "semantic request deadline exceeded")

        val plaintext = ByteArrayOutputStream(MAX_HTTP_PREFIX)
        val readBuffer = ByteArray(16 * 1024)
        var needRead = netIn.position() == 0
        while (clockNanos() < deadline && plaintext.size() < MAX_HTTP_PREFIX) {
            if (needRead) {
                socket.soTimeout = remainingMs(deadline)
                val count = socket.getInputStream().read(readBuffer)
                if (count < 0) return SemanticResult(false, "peer closed before HTTP status")
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
            appIn.flip()
            if (appIn.hasRemaining()) {
                val count = minOf(appIn.remaining(), MAX_HTTP_PREFIX - plaintext.size())
                val bytes = ByteArray(count)
                appIn.get(bytes)
                plaintext.write(bytes)
                val prefix = plaintext.toByteArray()
                val status = parseHttpStatus(prefix)
                if (status != null) {
                    return if (policy.accepts(status)) {
                        SemanticResult(true, "")
                    } else {
                        SemanticResult(
                            false,
                            "HTTP status $status outside ${policy.statusMin}..${policy.statusMax}",
                        )
                    }
                }
                if (prefix.indexOf('\n'.code.toByte()) >= 0) {
                    return SemanticResult(false, "invalid HTTP status line")
                }
            }
            when (result.status) {
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> needRead = true
                SSLEngineResult.Status.CLOSED -> return SemanticResult(false, "TLS closed before HTTP status")
                else -> needRead = netIn.position() == 0
            }
            if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runDelegatedTasks(engine)
            }
        }
        return SemanticResult(false, "HTTP semantic probe deadline exceeded")
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

    private fun runDelegatedTasks(engine: SSLEngine) {
        while (true) engine.delegatedTask?.run() ?: break
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

    private data class HandshakeResult(
        val success: Boolean,
        val latencyMs: Long,
        val error: String,
        val failureStage: CandidateFailureStage = CandidateFailureStage.NONE,
    )

    private data class SemanticResult(val success: Boolean, val error: String)

    companion object {
        private const val MAX_NET_BUFFER = 256 * 1024
        private const val MAX_FRAGMENT_ATTEMPTS = 2
        private const val MAX_HTTP_PREFIX = 8 * 1024

        private fun failed(error: String, stage: CandidateFailureStage) =
            HandshakeResult(false, 0, error, stage)

        internal fun parseHttpStatus(prefix: ByteArray): Int? {
            val lineEnd = prefix.indexOf('\n'.code.toByte())
            if (lineEnd < 0 || lineEnd > MAX_STATUS_LINE) return null
            val line = String(prefix, 0, lineEnd, Charsets.US_ASCII).trimEnd('\r')
            val parts = line.split(' ', limit = 3)
            if (parts.size < 2 || parts[0] !in setOf("HTTP/1.0", "HTTP/1.1")) return null
            return parts[1].takeIf { it.length == 3 && it.all(Char::isDigit) }?.toIntOrNull()
                ?.takeIf { it in 100..599 }
        }

        internal fun dominantFailureStage(stages: Collection<CandidateFailureStage>): CandidateFailureStage {
            val values = stages.filterTo(HashSet()) { it != CandidateFailureStage.NONE }
            return FAILURE_PRIORITY.firstOrNull(values::contains) ?: CandidateFailureStage.NONE
        }

        internal fun tlsBypassMayChangeOutcome(stage: CandidateFailureStage): Boolean = when (stage) {
            CandidateFailureStage.TCP_CONNECT,
            CandidateFailureStage.HTTP_SEMANTIC,
            CandidateFailureStage.INVALID_ADDRESS,
            CandidateFailureStage.NONE,
            -> false
            CandidateFailureStage.TLS_RESET,
            CandidateFailureStage.CERTIFICATE,
            CandidateFailureStage.TLS_HANDSHAKE,
            -> true
        }

        private fun isConnectionReset(t: Throwable): Boolean = causeSequence(t).any { cause ->
            val message = cause.message.orEmpty()
            message.contains("reset", ignoreCase = true) ||
                message.contains("ECONNRESET", ignoreCase = true) ||
                message.contains("broken pipe", ignoreCase = true)
        }

        private fun isCertificateFailure(t: Throwable): Boolean = causeSequence(t).any { cause ->
            val name = cause.javaClass.name
            name.contains("Certificate", ignoreCase = true) ||
                name.contains("CertPath", ignoreCase = true) ||
                name.contains("SSLPeerUnverified", ignoreCase = true)
        }

        private fun causeSequence(t: Throwable): Sequence<Throwable> = generateSequence(t) { cause ->
            cause.cause?.takeUnless { it === cause }
        }.take(8)

        private val FAILURE_PRIORITY = listOf(
            CandidateFailureStage.HTTP_SEMANTIC,
            CandidateFailureStage.CERTIFICATE,
            CandidateFailureStage.TLS_RESET,
            CandidateFailureStage.TCP_CONNECT,
            CandidateFailureStage.TLS_HANDSHAKE,
            CandidateFailureStage.INVALID_ADDRESS,
        )
        private const val MAX_STATUS_LINE = 1024
    }
}

package org.xiyu.githubdirect.core.dns

import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * RFC8484 wire DoH 客户端（纯 JDK javax.net.ssl，无 android.* 依赖）。
 *
 * - POST /dns-query，请求体 = raw DNS 查询字节，响应 = raw DNS 响应字节（RCode 天然保留）
 * - SSLSocket 直连端点 IP:443，SNI 设为期望主机名；
 *   HostnameVerifier 按期望主机名校验证书（§31 bootstrap 安全，禁止 TrustAll）
 * - 健康状态（§32）：UNKNOWN/HEALTHY/DEGRADED/BACKOFF；
 *   连续 2 次失败 → BACKOFF（冷却 60s，冷却期跳过）；成功 → HEALTHY
 * - Hedging（§33）：按健康排序，先发 primary；350ms 未完成 → 发 secondary；
 *   第一个成功响应胜；全部失败 → null。绝不并发请求全部 endpoint。
 *
 * 线程安全：全部状态 @Volatile/原子，无网络全局锁。
 */
class WireDohClient @JvmOverloads constructor(
    private val endpoints: List<WireEndpoint> = DEFAULT_ENDPOINTS,
    private val hedgeDelayMs: Long = 350,
    private val backoffMs: Long = 60_000,
    private val maxFailuresBeforeBackoff: Int = 2,
    private val clock: () -> Long = System::currentTimeMillis,
    /** 测试注入：替代真实 TLS 网络 I/O（生产为 null）。 */
    private val transportOverride: ((WireEndpoint, ByteArray, Int) -> ByteArray?)? = null,
) {

    enum class Health { UNKNOWN, HEALTHY, DEGRADED, BACKOFF }

    /** wire DoH 端点：IP 字面量直连 + 期望主机名（SNI / 证书校验）。 */
    data class WireEndpoint(val ip: String, val hostname: String, val port: Int = 443)

    private class EndpointState {
        @Volatile var health: Health = Health.UNKNOWN
        val failures = AtomicInteger(0)
        val backoffUntil = AtomicLong(0)
    }

    private val states = ConcurrentHashMap<WireEndpoint, EndpointState>().apply {
        for (ep in endpoints) put(ep, EndpointState())
    }

    private val sslSocketFactory: SSLSocketFactory =
        SSLSocketFactory.getDefault() as SSLSocketFactory
    private val hostnameVerifier: HostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()

    /**
     * raw wire DoH 查询：发 primary，hedge 窗口未完成则发 secondary；
     * 第一个成功响应胜；全部失败 → null。
     * 实现：每次查询最多 2 个短命工作线程 + 阻塞队列收结果。
     */
    fun post(rawQuery: ByteArray, timeoutMs: Int): ByteArray? {
        if (rawQuery.size < 12) return null
        val candidates = orderedCandidates()
        if (candidates.isEmpty()) return null

        val queue = LinkedBlockingQueue<Pair<WireEndpoint, ByteArray?>>()
        val threads = ArrayList<Thread>()
        val openSockets = ConcurrentHashMap.newKeySet<Socket>()
        val deadline = clock() + timeoutMs
        var hedged = false

        submit(candidates[0], rawQuery, deadline, queue, threads, openSockets)

        while (true) {
            val remaining = deadline - clock()
            if (remaining <= 0) break
            val waitMs = if (hedged) remaining else minOf(remaining, hedgeDelayMs)
            val result = try {
                queue.poll(waitMs, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                break
            }
            if (result != null) {
                val (endpoint, body) = result
                if (body != null) {
                    recordSuccess(endpoint)
                    cancelAll(threads, openSockets)
                    return body
                }
                recordFailure(endpoint)
                // primary 快速失败 → 立即补发 secondary
                if (!hedged && candidates.size > 1) {
                    hedged = true
                    submit(candidates[1], rawQuery, deadline, queue, threads, openSockets)
                    continue
                }
                if (hedged) continue
                break
            }
            // hedge 窗口超时 → 发 secondary
            if (!hedged && candidates.size > 1) {
                hedged = true
                submit(candidates[1], rawQuery, deadline, queue, threads, openSockets)
                continue
            }
            break
        }
        cancelAll(threads, openSockets)
        return null
    }

    /** hostname → 健康状态（诊断/测试）。 */
    fun healthSnapshot(): Map<String, Health> =
        endpoints.associate { it.hostname to (states[it]?.health ?: Health.UNKNOWN) }

    // ==================== 健康状态（§32） ====================

    private fun recordSuccess(endpoint: WireEndpoint) {
        states[endpoint]?.let { s ->
            s.failures.set(0)
            s.health = Health.HEALTHY
        }
    }

    private fun recordFailure(endpoint: WireEndpoint) {
        states[endpoint]?.let { s ->
            if (s.failures.incrementAndGet() >= maxFailuresBeforeBackoff) {
                s.backoffUntil.set(clock() + backoffMs)
                s.health = Health.BACKOFF
            } else {
                s.health = Health.DEGRADED
            }
        }
    }

    /** 跳过冷却期端点，按健康程度排序（HEALTHY → UNKNOWN → DEGRADED）。 */
    private fun orderedCandidates(): List<WireEndpoint> {
        val now = clock()
        val fresh = endpoints.filter { ep ->
            val s = states[ep] ?: return@filter true
            if (s.health != Health.BACKOFF) return@filter true
            if (now >= s.backoffUntil.get()) {
                s.health = Health.UNKNOWN
                s.failures.set(0)
                return@filter true
            }
            false
        }
        return fresh.sortedBy { healthRank(states[it]!!.health) }
    }

    private fun healthRank(h: Health): Int = when (h) {
        Health.HEALTHY -> 0
        Health.UNKNOWN -> 1
        Health.DEGRADED -> 2
        Health.BACKOFF -> 3
    }

    // ==================== 查询执行 ====================

    private fun submit(
        endpoint: WireEndpoint,
        rawQuery: ByteArray,
        deadline: Long,
        queue: LinkedBlockingQueue<Pair<WireEndpoint, ByteArray?>>,
        threads: MutableList<Thread>,
        openSockets: MutableSet<Socket>,
    ) {
        val t = Thread({
            val body = try {
                wireRequest(endpoint, rawQuery, deadline, openSockets)
            } catch (_: Exception) {
                null
            }
            queue.offer(endpoint to body)
        }, "WireDoh-${endpoint.hostname}")
        t.isDaemon = true
        threads.add(t)
        t.start()
    }

    private fun wireRequest(
        endpoint: WireEndpoint,
        rawQuery: ByteArray,
        deadline: Long,
        openSockets: MutableSet<Socket>,
    ): ByteArray? {
        val override = transportOverride
        if (override != null) return override(endpoint, rawQuery, timeoutBudget(deadline))
        return realWireRequest(endpoint, rawQuery, deadline, openSockets)
    }

    private fun timeoutBudget(deadline: Long): Int =
        (deadline - clock()).toInt().coerceAtLeast(1)

    /** 真实 TLS 路径：SSLSocket → SNI → 握手 → HostnameVerifier → POST → 读响应。 */
    private fun realWireRequest(
        endpoint: WireEndpoint,
        rawQuery: ByteArray,
        deadline: Long,
        openSockets: MutableSet<Socket>,
    ): ByteArray? {
        val socket = sslSocketFactory.createSocket() as SSLSocket
        openSockets.add(socket)
        try {
            val params = socket.sslParameters
            params.serverNames = listOf(SNIHostName(endpoint.hostname))
            socket.sslParameters = params

            socket.connect(InetSocketAddress(endpoint.ip, endpoint.port), timeoutBudget(deadline))
            socket.soTimeout = timeoutBudget(deadline)
            socket.startHandshake()

            // §31：按期望主机名校验证书链（系统信任锚 + 主机名 SAN），禁止 TrustAll
            if (!hostnameVerifier.verify(endpoint.hostname, socket.session)) return null

            val out = socket.getOutputStream()
            out.write(buildHttpPost(endpoint.hostname, rawQuery))
            out.flush()

            val input = socket.getInputStream()
            val response = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                response.write(buf, 0, n)
            }

            val parsed = parseHttpResponse(response.toByteArray()) ?: return null
            if (parsed.first != 200) return null
            val body = parsed.second ?: return null
            return if (body.size >= 12) body else null
        } catch (_: Exception) {
            return null
        } finally {
            openSockets.remove(socket)
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    /** 成功返回后取消在途线程（关 socket 解阻塞 + interrupt）。 */
    private fun cancelAll(threads: List<Thread>, openSockets: MutableSet<Socket>) {
        for (s in openSockets) {
            try {
                s.close()
            } catch (_: Exception) {
            }
        }
        for (t in threads) t.interrupt()
    }

    companion object {

        /** 端点表（与 DoHServers.DEFAULT 同 IP；此处绑定 wire 端点期望主机名）。 */
        val DEFAULT_ENDPOINTS: List<WireEndpoint> = listOf(
            WireEndpoint("223.5.5.5", "dns.alidns.com"),
            WireEndpoint("1.12.12.12", "doh.pub"),
            WireEndpoint("120.53.53.53", "doh.pub"),
            WireEndpoint("1.1.1.1", "cloudflare-dns.com"),
            WireEndpoint("8.8.8.8", "dns.google"),
            WireEndpoint("9.9.9.9", "dns.quad9.net"),
        )

        /** 构造 RFC8484 wire DoH POST 请求字节（纯函数，测试直测字节格式）。 */
        fun buildHttpPost(host: String, body: ByteArray): ByteArray {
            val head = ("POST /dns-query HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "Accept: application/dns-message\r\n" +
                "Content-Type: application/dns-message\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Connection: close\r\n" +
                "\r\n").toByteArray(Charsets.US_ASCII)
            val req = ByteArray(head.size + body.size)
            System.arraycopy(head, 0, req, 0, head.size)
            System.arraycopy(body, 0, req, head.size, body.size)
            return req
        }

        /**
         * 解析 HTTP/1.1 响应字节 → (status, body)。
         * - 非 200 → (status, null)
         * - Transfer-Encoding: chunked → null（不支持）
         * - 无 Content-Length → 取剩余全部字节（Connection: close 帧）
         * - Content-Length 声明超出可用字节 → 截取可用部分
         * - 格式非法（无状态行 / 无空行）→ null
         */
        fun parseHttpResponse(bytes: ByteArray): Pair<Int, ByteArray?>? {
            if (bytes.isEmpty()) return null
            val headerEnd = indexOfDoubleCrLf(bytes) ?: return null
            val head = String(bytes, 0, headerEnd, Charsets.US_ASCII)
            val lines = head.split("\r\n")
            val status = lines.firstOrNull()?.let { parseStatusLine(it) } ?: return null
            val headers = HashMap<String, String>()
            for (line in lines.drop(1)) {
                val idx = line.indexOf(':')
                if (idx <= 0) continue
                headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
            }
            val bodyStart = headerEnd + 4
            if (status != 200) return status to null
            if (headers["transfer-encoding"]?.contains("chunked") == true) return null
            val declared = headers["content-length"]?.toIntOrNull()
            val available = (bytes.size - bodyStart).coerceAtLeast(0)
            val bodyLen = if (declared != null) minOf(declared, available) else available
            return status to bytes.copyOfRange(bodyStart, bodyStart + bodyLen)
        }

        private fun parseStatusLine(line: String): Int? {
            val code = line.split(" ").getOrNull(1)?.toIntOrNull() ?: return null
            return if (code in 100..599) code else null
        }

        private fun indexOfDoubleCrLf(bytes: ByteArray): Int? {
            var i = 0
            while (i + 3 < bytes.size) {
                if (bytes[i] == 0x0D.toByte() && bytes[i + 1] == 0x0A.toByte() &&
                    bytes[i + 2] == 0x0D.toByte() && bytes[i + 3] == 0x0A.toByte()
                ) {
                    return i
                }
                i++
            }
            return null
        }
    }
}

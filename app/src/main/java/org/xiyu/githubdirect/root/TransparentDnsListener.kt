package org.xiyu.githubdirect.root

import org.xiyu.githubdirect.core.dns.DnsPacketCodec
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * DNS 监听器抽象（测试注入点）。
 */
interface DnsListener {
    /** 绑定 127.0.0.1:udpPort / tcpPort 并启动收包循环；绑定失败返回 false（事务 ROLLBACK 依据）。 */
    fun start(handler: (ByteArray) -> ByteArray?): Boolean

    /** 关闭监听与全部活动连接；幂等。 */
    fun stop()

    /** 监听是否存活（socket 未关闭且线程运行）。 */
    fun alive(): Boolean
}

/**
 * 透明 DNS 拦截（REDIRECT 至本地监听，设计 §7）。
 *
 * - UDP 5354：`DatagramSocket` 绑 127.0.0.1:5354；单收线程逐包调 dnsHandler，
 *   非 null 响应回写源地址（回程由 conntrack 对 REDIRECT 条目做 un-NAT，客户端看到的是原 DNS 服务器地址）。
 *   处理异常 → 忽略（等价丢包，客户端重试）。
 * - TCP 5355：`ServerSocket` 绑 127.0.0.1:5355；每连接一线程（上限 32，超出直接断开）：
 *   读 2 字节大端长度 + payload → dnsHandler(payload) → 回写 2 字节长度 + 响应；SO_TIMEOUT 5s。
 *
 * 纯 JVM（java.net），无 Android 依赖。绑定失败 → start 返回 false。
 */
class TransparentDnsListener(
    private val udpPort: Int = 5354,
    private val tcpPort: Int = 5355,
    private val tcpMaxConnections: Int = 32,
    private val tcpTimeoutMs: Int = 5000,
) : DnsListener {

    @Volatile
    private var running = false
    private var handler: ((ByteArray) -> ByteArray?)? = null
    private var udpSocket: DatagramSocket? = null
    private var tcpServer: ServerSocket? = null
    private val activeConnections = ConcurrentHashMap<Socket, Boolean>()

    @Synchronized
    override fun start(handler: (ByteArray) -> ByteArray?): Boolean {
        if (running) return true
        requireNotNull(handler) { "handler 不能为 null" }

        // 先绑 UDP，再绑 TCP；任一失败 → 关闭已绑定的，返回 false
        val udp = try {
            DatagramSocket(null).apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getLoopbackAddress(), udpPort))
            }
        } catch (t: Throwable) {
            return false
        }
        val tcp = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getLoopbackAddress(), tcpPort), 16)
            }
        } catch (t: Throwable) {
            closeQuietly(udp)
            return false
        }

        this.handler = handler
        running = true
        udpSocket = udp
        tcpServer = tcp
        Thread({ udpLoop(udp) }, "GHD-DnsUdp").apply { isDaemon = true; start() }
        Thread({ tcpLoop(tcp) }, "GHD-DnsTcp").apply { isDaemon = true; start() }
        return true
    }

    @Synchronized
    override fun stop() {
        running = false
        handler = null
        closeQuietly(udpSocket)
        closeQuietly(tcpServer)
        udpSocket = null
        tcpServer = null
        activeConnections.keys.forEach { closeQuietly(it) }
        activeConnections.clear()
    }

    override fun alive(): Boolean =
        running && (udpSocket?.isClosed == false) && (tcpServer?.isClosed == false)

    private fun udpLoop(sock: DatagramSocket) {
        val buf = ByteArray(MAX_UDP_PACKET)
        while (running) {
            try {
                val pkt = DatagramPacket(buf, buf.size)
                sock.receive(pkt)
                val raw = ByteArray(pkt.length)
                System.arraycopy(buf, 0, raw, 0, pkt.length)
                val h = handler ?: continue
                val resp = try {
                    h(raw)
                } catch (t: Throwable) {
                    null // 处理异常 = 丢包，客户端重试
                }
                if (resp != null) {
                    sock.send(DatagramPacket(resp, resp.size, pkt.socketAddress))
                }
            } catch (e: SocketException) {
                if (!running) break else continue // 已关闭
            } catch (t: Throwable) {
                // 单包错误不终止循环
            }
        }
    }

    private fun tcpLoop(server: ServerSocket) {
        while (running) {
            val socket = try {
                server.accept()
            } catch (t: Throwable) {
                break
            }
            if (!running) {
                closeQuietly(socket)
                break
            }
            if (activeConnections.size >= tcpMaxConnections) {
                closeQuietly(socket) // 超限拒接
                continue
            }
            activeConnections[socket] = true
            Thread({ handleTcpDns(socket) }, "GHD-DnsTcpConn").apply {
                isDaemon = true
                start()
            }
        }
    }

    private fun handleTcpDns(socket: Socket) {
        try {
            socket.soTimeout = tcpTimeoutMs
            val input = BufferedInputStream(socket.getInputStream())
            val output = BufferedOutputStream(socket.getOutputStream())
            while (running) {
                val payload = readFramedPayload(input) ?: return // EOF/非法帧/超时 → 关闭连接
                val h = handler ?: return
                val resp = try {
                    h(payload)
                } catch (t: Throwable) {
                    null
                } ?: return
                val frame = ByteArray(2 + resp.size)
                DnsPacketCodec.writeU16(frame, 0, resp.size)
                System.arraycopy(resp, 0, frame, 2, resp.size)
                output.write(frame)
                output.flush()
            }
        } catch (t: Throwable) {
            // 连接级异常：关闭连接
        } finally {
            activeConnections.remove(socket)
            closeQuietly(socket)
        }
    }

    /**
     * 读 2 字节大端长度（DnsPacketCodec.readU16）+ 等长 payload。
     * EOF/长度越界（>MAX_TCP_PAYLOAD 或 0）/超时 → null（调用方关连接）。
     */
    private fun readFramedPayload(input: InputStream): ByteArray? {
        val lenBytes = ByteArray(2)
        if (!readFully(input, lenBytes)) return null
        val len = DnsPacketCodec.readU16(lenBytes, 0)
        if (len <= 0 || len > MAX_TCP_PAYLOAD) return null
        val payload = ByteArray(len)
        if (!readFully(input, payload)) return null
        return payload
    }

    private fun readFully(input: InputStream, dst: ByteArray): Boolean {
        var off = 0
        while (off < dst.size) {
            val n = input.read(dst, off, dst.size - off)
            if (n < 0) return false
            off += n
        }
        return true
    }

    private fun closeQuietly(c: AutoCloseable?) {
        try {
            c?.close()
        } catch (_: Throwable) {
        }
    }

    companion object {
        private const val MAX_UDP_PACKET = 4096
        private const val MAX_TCP_PAYLOAD = 8192
    }
}

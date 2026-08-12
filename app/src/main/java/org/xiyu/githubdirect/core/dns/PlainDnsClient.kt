package org.xiyu.githubdirect.core.dns

import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

/**
 * 明文 DNS 客户端（纯 JDK，无 android.* 依赖）：
 * - UDP/53：raw 查询发到上游服务器，读回一个包原样返回（轮换服务器）
 * - TCP/53（§30）：2 字节大端长度前缀 framing，字节透传
 *
 * 服务器仅接受 IP 字面量（IpAddresses 解析，免递归 DNS 调用）。
 * 网络调用在 JVM 测试环境不可依赖——测试只测 framing 纯函数，或注入 override。
 */
class PlainDnsClient @JvmOverloads constructor(
    private val servers: List<String> = DEFAULT_SERVERS,
    private val defaultTimeoutMs: Int = 3000,
    /** 测试注入：替代真实 UDP 网络 I/O。 */
    private val queryOverride: ((ByteArray, Int) -> ByteArray?)? = null,
    /** 测试注入：替代真实 TCP 网络 I/O。 */
    private val queryTcpOverride: ((ByteArray, Int) -> ByteArray?)? = null,
) {

    private val serverIndex = AtomicInteger(0)

    /** UDP/53 查询：发 raw 查询字节，收响应包原样返回；超时/失败 → null。 */
    fun query(raw: ByteArray, timeoutMs: Int = defaultTimeoutMs): ByteArray? {
        val override = queryOverride
        if (override != null) return override(raw, timeoutMs)
        return udpQuery(raw, timeoutMs)
    }

    /** TCP/53 查询（2 字节长度前缀 framing，§30）；超时/失败 → null。 */
    fun queryTcp(raw: ByteArray, timeoutMs: Int = defaultTimeoutMs): ByteArray? {
        val override = queryTcpOverride
        if (override != null) return override(raw, timeoutMs)
        return tcpQuery(raw, timeoutMs)
    }

    private fun udpQuery(raw: ByteArray, timeoutMs: Int): ByteArray? {
        if (raw.size < 12) return null
        val socket = DatagramSocket()
        try {
            socket.soTimeout = timeoutMs
            val address = nextAddress() ?: return null
            socket.send(DatagramPacket(raw, raw.size, address, 53))
            val buf = ByteArray(4096)
            val pkt = DatagramPacket(buf, buf.size)
            socket.receive(pkt)
            if (pkt.length < 12) return null
            val response = buf.copyOfRange(0, pkt.length)
            // ID 校验：防串包（明文 UDP 的基本防线）
            return if (DnsPacketCodec.readU16(response, 0) == DnsPacketCodec.readU16(raw, 0)) {
                response
            } else {
                null
            }
        } catch (_: Exception) {
            return null
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun tcpQuery(raw: ByteArray, timeoutMs: Int): ByteArray? {
        if (raw.size < 12) return null
        val socket = Socket()
        try {
            val address = nextAddress() ?: return null
            socket.connect(InetSocketAddress(address, 53), timeoutMs)
            socket.soTimeout = timeoutMs
            socket.tcpNoDelay = true

            val out = socket.getOutputStream()
            out.write(encodeTcpFrame(raw))
            out.flush()

            val input = socket.getInputStream()
            val header = ByteArray(2)
            if (!readFully(input, header, 2)) return null
            val bodyLen = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
            if (bodyLen < 12) return null
            val body = ByteArray(bodyLen)
            if (!readFully(input, body, bodyLen)) return null
            return if (DnsPacketCodec.readU16(body, 0) == DnsPacketCodec.readU16(raw, 0)) body else null
        } catch (_: Exception) {
            return null
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun readFully(input: InputStream, target: ByteArray, len: Int): Boolean {
        var off = 0
        while (off < len) {
            val n = input.read(target, off, len - off)
            if (n < 0) return false
            off += n
        }
        return true
    }

    /** 轮换取下一个服务器地址（仅 IP 字面量，不触发递归 DNS）。 */
    private fun nextAddress(): InetAddress? {
        val list = servers
        if (list.isEmpty()) return null
        val idx = Math.floorMod(serverIndex.getAndIncrement(), list.size)
        val server = list[idx] ?: return null
        return IpAddresses.parseIpAddress(server)?.let { InetAddress.getByAddress(it) }
    }

    companion object {

        /** 上游明文 DNS 服务器（国内优先）。 */
        val DEFAULT_SERVERS: List<String> = listOf("223.5.5.5", "119.29.29.29")

        /** 2 字节大端长度前缀 + 数据（§30 TCP/53 framing，纯函数可测）。 */
        fun encodeTcpFrame(data: ByteArray): ByteArray {
            if (data.size > 0xFFFF) {
                throw IllegalArgumentException("DNS TCP frame too large: ${data.size}")
            }
            val frame = ByteArray(2 + data.size)
            frame[0] = ((data.size shr 8) and 0xFF).toByte()
            frame[1] = (data.size and 0xFF).toByte()
            System.arraycopy(data, 0, frame, 2, data.size)
            return frame
        }

        /** 剥 2 字节长度前缀；帧不完整/长度越界返回 null。 */
        fun decodeTcpFrame(frame: ByteArray): ByteArray? {
            if (frame.size < 2) return null
            val len = ((frame[0].toInt() and 0xFF) shl 8) or (frame[1].toInt() and 0xFF)
            if (frame.size < 2 + len) return null
            return frame.copyOfRange(2, 2 + len)
        }
    }
}

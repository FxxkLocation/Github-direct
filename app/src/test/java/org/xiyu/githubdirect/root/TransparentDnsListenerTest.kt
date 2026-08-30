package org.xiyu.githubdirect.root

import org.xiyu.githubdirect.core.dns.DnsPacketCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * TransparentDnsListener 测试：UDP 查询→响应回写、TCP DNS 两字节 framing、
 * 绑定冲突返回 false、stop 后 alive()=false。
 */
class TransparentDnsListenerTest {

    private val handler: (ByteArray) -> ByteArray? = { raw ->
        when {
            raw.contentEquals("query".toByteArray()) -> "answer".toByteArray()
            raw.contentEquals("nodata".toByteArray()) -> null
            else -> null
        }
    }

    @Test
    fun `UDP 查询收到响应回写`() {
        val ports = freePorts()
        val listener = TransparentDnsListener(udpPort = ports.udp, tcpPort = ports.tcp)
        assertTrue(listener.start(handler))
        assertTrue(listener.alive())

        val client = DatagramSocket()
        try {
            client.soTimeout = 3000
            client.send(
                DatagramPacket(
                    "query".toByteArray(),
                    5,
                    InetAddress.getLoopbackAddress(),
                    ports.udp,
                ),
            )
            val buf = ByteArray(64)
            val pkt = DatagramPacket(buf, buf.size)
            client.receive(pkt)
            assertEquals("answer", String(buf, 0, pkt.length))
        } finally {
            client.close()
            listener.stop()
        }
        assertFalse(listener.alive())
    }

    @Test
    fun `UDP handler 返回 null 时回 SERVFAIL`() {
        val ports = freePorts()
        val listener = TransparentDnsListener(udpPort = ports.udp, tcpPort = ports.tcp)
        assertTrue(listener.start { null })
        val client = DatagramSocket()
        try {
            client.soTimeout = 3000
            val query = ByteArray(12).also { it[0] = 0x12; it[1] = 0x34 }
            client.send(
                DatagramPacket(query, query.size, InetAddress.getLoopbackAddress(), ports.udp),
            )
            val buf = ByteArray(64)
            val pkt = DatagramPacket(buf, buf.size)
            client.receive(pkt)
            assertTrue(pkt.length >= 4)
            assertEquals(2, buf[3].toInt() and 0x0F) // RCODE=SERVFAIL
        } finally {
            client.close()
            listener.stop()
        }
    }

    @Test
    fun `TCP DNS 两字节长度 framing 回写响应`() {
        val ports = freePorts()
        val listener = TransparentDnsListener(udpPort = ports.udp, tcpPort = ports.tcp)
        assertTrue(listener.start(handler))

        val client = Socket()
        try {
            client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), ports.tcp), 2000)
            client.soTimeout = 3000
            val out = BufferedOutputStream(client.getOutputStream())
            val payload = "query".toByteArray()
            val frame = ByteArray(2 + payload.size)
            DnsPacketCodec.writeU16(frame, 0, payload.size)
            System.arraycopy(payload, 0, frame, 2, payload.size)
            out.write(frame)
            out.flush()

            val input = BufferedInputStream(client.getInputStream())
            val lenBytes = ByteArray(2)
            readFully(input, lenBytes)
            val len = DnsPacketCodec.readU16(lenBytes, 0)
            assertEquals(6, len)
            val resp = ByteArray(len)
            readFully(input, resp)
            assertEquals("answer", String(resp))
        } finally {
            client.close()
            listener.stop()
        }
    }

    @Test
    fun `TCP DNS 连接数超限时拒接新连接`() {
        val firstRequestEntered = CountDownLatch(1)
        val releaseFirstRequest = CountDownLatch(1)
        val ports = freePorts()
        val listener = TransparentDnsListener(
            udpPort = ports.udp,
            tcpPort = ports.tcp,
            tcpMaxConnections = 1,
        )
        assertTrue(listener.start { raw ->
            firstRequestEntered.countDown()
            releaseFirstRequest.await(3, TimeUnit.SECONDS)
            handler(raw)
        })

        val conn1 = Socket()
        val conn2 = Socket()
        try {
            conn1.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), ports.tcp), 2000)
            val payload = "query".toByteArray()
            val frame = ByteArray(2 + payload.size)
            DnsPacketCodec.writeU16(frame, 0, payload.size)
            System.arraycopy(payload, 0, frame, 2, payload.size)
            conn1.getOutputStream().apply {
                write(frame)
                flush()
            }
            assertTrue(firstRequestEntered.await(2, TimeUnit.SECONDS))

            // 第一条连接已进入 handler 且仍占用额度，第二条必须由服务端直接关闭。
            conn2.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), ports.tcp), 2000)
            conn2.soTimeout = 3000
            val buf = ByteArray(16)
            assertEquals(-1, conn2.getInputStream().read(buf))
        } catch (e: java.net.SocketException) {
            // 预期：连接被重置
        } finally {
            releaseFirstRequest.countDown()
            conn2.close()
            conn1.close()
            listener.stop()
        }
    }

    @Test
    fun `端口占用时 start 返回 false`() {
        val ports = freePorts()
        val listener = TransparentDnsListener(udpPort = ports.udp, tcpPort = ports.tcp)
        assertTrue(listener.start(handler))
        // 第二个监听器撞同一端口 → false（UDP 或 TCP 任一失败都失败）
        val second = TransparentDnsListener(udpPort = ports.udp, tcpPort = ports.tcp)
        assertFalse(second.start(handler))
        listener.stop()
        // close 后的端口释放在不同 runner 内核上可能有极短延迟；保持有界重试，
        // 仍要求监听器在 1 秒内恢复可绑定，而不是把竞态当作功能失败。
        var rebound = false
        repeat(40) {
            if (!rebound) {
                rebound = second.start(handler)
                if (!rebound) Thread.sleep(25)
            }
        }
        assertTrue(rebound)
        second.stop()
    }

    private data class TestPorts(val udp: Int, val tcp: Int)

    private fun freePorts(): TestPorts {
        val udp = DatagramSocket(0).use { it.localPort }
        val tcp = ServerSocket(0).use { it.localPort }
        return TestPorts(udp, tcp)
    }

    private fun readFully(input: java.io.InputStream, dst: ByteArray) {
        var off = 0
        while (off < dst.size) {
            val n = input.read(dst, off, dst.size - off)
            if (n < 0) throw AssertionError("提前 EOF")
            off += n
        }
    }
}

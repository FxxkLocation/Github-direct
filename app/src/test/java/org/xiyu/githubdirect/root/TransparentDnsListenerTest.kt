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
        val listener = TransparentDnsListener(udpPort = 15354, tcpPort = 15355)
        assertTrue(listener.start(handler))
        assertTrue(listener.alive())

        val client = DatagramSocket()
        try {
            client.soTimeout = 3000
            client.send(DatagramPacket("query".toByteArray(), 5, InetAddress.getLoopbackAddress(), 15354))
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
        val listener = TransparentDnsListener(udpPort = 15354, tcpPort = 15355)
        assertTrue(listener.start { null })
        val client = DatagramSocket()
        try {
            client.soTimeout = 3000
            val query = ByteArray(12).also { it[0] = 0x12; it[1] = 0x34 }
            client.send(DatagramPacket(query, query.size, InetAddress.getLoopbackAddress(), 15354))
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
        val listener = TransparentDnsListener(udpPort = 15354, tcpPort = 15355)
        assertTrue(listener.start(handler))

        val client = Socket()
        try {
            client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 15355), 2000)
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
        val listener = TransparentDnsListener(udpPort = 15354, tcpPort = 15355, tcpMaxConnections = 1)
        assertTrue(listener.start { raw ->
            firstRequestEntered.countDown()
            releaseFirstRequest.await(3, TimeUnit.SECONDS)
            handler(raw)
        })

        val conn1 = Socket()
        val conn2 = Socket()
        try {
            conn1.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 15355), 2000)
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
            conn2.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 15355), 2000)
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
        val listener = TransparentDnsListener(udpPort = 15354, tcpPort = 15355)
        assertTrue(listener.start(handler))
        // 第二个监听器撞同一端口 → false（UDP 或 TCP 任一失败都失败）
        val second = TransparentDnsListener(udpPort = 15354, tcpPort = 15355)
        assertFalse(second.start(handler))
        listener.stop()
        // 释放后可重新绑定
        assertTrue(second.start(handler))
        second.stop()
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

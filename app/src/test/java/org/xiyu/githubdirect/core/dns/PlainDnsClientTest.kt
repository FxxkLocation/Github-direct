package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 只测 2 字节 framing 编解码纯函数；网络 I/O 不依赖真实网络（可注入 override）。
 */
class PlainDnsClientTest {

    @Test
    fun `encodeTcpFrame加2字节大端长度前缀`() {
        val data = byteArrayOf(0x12, 0x34, 0x56)
        val frame = PlainDnsClient.encodeTcpFrame(data)
        assertEquals(5, frame.size)
        assertEquals(0x00, frame[0].toInt() and 0xFF)
        assertEquals(0x03, frame[1].toInt() and 0xFF)
        assertArrayEquals(data, frame.copyOfRange(2, 5))
    }

    @Test
    fun `encodeTcpFrame大帧前缀正确`() {
        val data = ByteArray(300)
        data[299] = 0x7F.toByte()
        val frame = PlainDnsClient.encodeTcpFrame(data)
        assertEquals(0x01, frame[0].toInt() and 0xFF)
        assertEquals(0x2C, frame[1].toInt() and 0xFF) // 300 = 0x012C
        assertEquals(0x7F, frame[frame.size - 1].toInt() and 0xFF)
    }

    @Test
    fun `encodeTcpFrame超限抛异常`() {
        try {
            PlainDnsClient.encodeTcpFrame(ByteArray(0x10000))
            org.junit.Assert.fail("应抛 IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // 预期
        }
    }

    @Test
    fun `decodeTcpFrame roundtrip`() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val frame = PlainDnsClient.encodeTcpFrame(data)
        assertArrayEquals(data, PlainDnsClient.decodeTcpFrame(frame))
    }

    @Test
    fun `decodeTcpFrame非法帧返回null`() {
        assertNull(PlainDnsClient.decodeTcpFrame(byteArrayOf(0x00))) // 不足 2 字节
        assertNull(PlainDnsClient.decodeTcpFrame(byteArrayOf(0x00, 0x05, 1, 2))) // 声明长度越界
    }

    @Test
    fun `decodeTcpFrame空负载合法`() {
        assertArrayEquals(ByteArray(0), PlainDnsClient.decodeTcpFrame(byteArrayOf(0x00, 0x00)))
    }
}

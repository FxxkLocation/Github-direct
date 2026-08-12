package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsFragmenterTest {

    /** 构造 TLS ClientHello（record + handshake）。withSni=false 时仅带 ALPN 扩展。 */
    private fun buildClientHello(domain: String, withSni: Boolean = true): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        // Handshake: type(1) + len(3)
        out.write(0x01)
        out.write(0); out.write(0); out.write(0) // 长度占位，随后修复
        // Client version
        out.write(0x03); out.write(0x03)
        // Random (32)
        val random = ByteArray(32) { 0xAA.toByte() }
        out.write(random)
        // Session ID
        out.write(0)
        // Cipher suites
        out.write(0); out.write(2)
        out.write(0x13); out.write(0x01)
        // Compression
        out.write(0)

        // Extensions
        val ext = java.io.ByteArrayOutputStream()
        if (withSni) {
            // SNI: type 0x0000
            ext.write(0x00); ext.write(0x00)
            val nameBytes = domain.toByteArray(Charsets.US_ASCII)
            val extBody = 2 + 1 + 2 + nameBytes.size // list_len + name_type + name_len + name
            ext.write((extBody shr 8) and 0xFF); ext.write(extBody and 0xFF)
            val listLen = 1 + 2 + nameBytes.size
            ext.write((listLen shr 8) and 0xFF); ext.write(listLen and 0xFF)
            ext.write(0x00) // name_type: host_name
            ext.write((nameBytes.size shr 8) and 0xFF); ext.write(nameBytes.size and 0xFF)
            ext.write(nameBytes)
        } else {
            // ALPN: type 0x0016, empty
            ext.write(0x00); ext.write(0x16)
            ext.write(0x00); ext.write(0x00)
        }
        val extBytes = ext.toByteArray()
        out.write((extBytes.size shr 8) and 0xFF); out.write(extBytes.size and 0xFF)
        out.write(extBytes)

        val handshake = out.toByteArray()
        val handshakeLen = handshake.size - 4
        handshake[1] = ((handshakeLen shr 16) and 0xFF).toByte()
        handshake[2] = ((handshakeLen shr 8) and 0xFF).toByte()
        handshake[3] = (handshakeLen and 0xFF).toByte()

        // TLS Record: type 0x16, version 0x0301, len
        val record = ByteArray(5 + handshake.size)
        record[0] = 0x16.toByte()
        record[1] = 0x03.toByte()
        record[2] = 0x01.toByte()
        record[3] = ((handshake.size shr 8) and 0xFF).toByte()
        record[4] = (handshake.size and 0xFF).toByte()
        System.arraycopy(handshake, 0, record, 5, handshake.size)
        return record
    }

    /** 从分片结果中提取两个 record 的 payload 并拼接。 */
    private fun payloads(frag: ByteArray): Pair<ByteArray, ByteArray> {
        val firstLen = ((frag[3].toInt() and 0xFF) shl 8) or (frag[4].toInt() and 0xFF)
        val secondStart = 5 + firstLen
        val secondLen = ((frag[secondStart + 3].toInt() and 0xFF) shl 8) or
                (frag[secondStart + 4].toInt() and 0xFF)
        return Pair(
            frag.copyOfRange(5, 5 + firstLen),
            frag.copyOfRange(secondStart + 5, secondStart + 5 + secondLen),
        )
    }

    @Test
    fun `完整ClientHello分片后拼接还原`() {
        val hello = buildClientHello("github.com")
        assertTrue(TlsFragmenter.isTlsClientHello(hello))
        val frag = TlsFragmenter.fragmentTlsRecord(hello)
        assertNotNull(frag)
        val (p1, p2) = payloads(frag!!)
        assertEquals(hello.size - 5, p1.size + p2.size)
        // 拼接 == 原始 payload
        val joined = ByteArray(p1.size + p2.size)
        System.arraycopy(p1, 0, joined, 0, p1.size)
        System.arraycopy(p2, 0, joined, p1.size, p2.size)
        assertTrue(joined.contentEquals(hello.copyOfRange(5, hello.size)))
    }

    @Test
    fun `SNI在域名字符串前3字节处切割`() {
        val hello = buildClientHello("github.com")
        val sniOffset = TlsFragmenter.findSniOffset(hello, 5,
            ((hello[3].toInt() and 0xFF) shl 8) or (hello[4].toInt() and 0xFF))
        assertTrue("SNI 偏移: $sniOffset", sniOffset > 0)
        // SNI 位置的内容是 "github.com"
        assertEquals("github.com", String(hello, sniOffset, 10, Charsets.US_ASCII))

        val frag = TlsFragmenter.fragmentTlsRecord(hello)!!
        val firstLen = ((frag[3].toInt() and 0xFF) shl 8) or (frag[4].toInt() and 0xFF)
        // 切割点 = sniOffset + 3（域名前 3 个字节）
        assertEquals(sniOffset + 3 - 5, firstLen)
    }

    @Test
    fun `无SNI时在数据中间切割`() {
        val hello = buildClientHello("github.com", withSni = false)
        val frag = TlsFragmenter.fragmentTlsRecord(hello)
        assertNotNull(frag)
        val recordLen = ((hello[3].toInt() and 0xFF) shl 8) or (hello[4].toInt() and 0xFF)
        val (p1, _) = payloads(frag!!)
        assertEquals(minOf(recordLen / 2, 50), p1.size)
    }

    @Test
    fun `非TLS数据不判为ClientHello`() {
        assertFalse(TlsFragmenter.isTlsClientHello(ByteArray(20)))
        assertFalse(TlsFragmenter.isTlsClientHello("GET / HTTP/1.1".toByteArray()))
        // 超短
        assertFalse(TlsFragmenter.isTlsClientHello(byteArrayOf(0x16, 0x03, 0x01, 0, 0)))
    }

    @Test
    fun `过短数据无法分片`() {
        assertNull(TlsFragmenter.fragmentTlsRecord(ByteArray(9)))
        assertNull(TlsFragmenter.fragmentTlsRecord(ByteArray(0)))
    }

    @Test
    fun `record长度越界无法分片`() {
        val hello = buildClientHello("github.com")
        // 截断：声明的 record len > 实际数据
        val truncated = hello.copyOf(hello.size - 10)
        assertNull(TlsFragmenter.fragmentTlsRecord(truncated))
    }
}

package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ClientHelloAccumulatorTest {

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

    /** 提取开头连续 Handshake records 的 payload。 */
    private fun payloads(frag: ByteArray): List<ByteArray> {
        val result = ArrayList<ByteArray>()
        var pos = 0
        while (pos + 5 <= frag.size && frag[pos] == 0x16.toByte()) {
            val length = ((frag[pos + 3].toInt() and 0xFF) shl 8) or
                (frag[pos + 4].toInt() and 0xFF)
            val end = pos + 5 + length
            if (length <= 0 || end > frag.size) break
            result += frag.copyOfRange(pos + 5, end)
            pos = end
        }
        return result
    }

    private fun joined(parts: List<ByteArray>): ByteArray = parts.fold(ByteArray(0), ByteArray::plus)

    @Test
    fun `完整单段ClientHello分片输出且多record拼接还原`() {
        val hello = buildClientHello("github.com")
        val acc = ClientHelloAccumulator()
        val out = acc.feed(hello, 1000)
        assertNotNull(out)
        assertTrue("输出应为分片字节", acc.consumeFragmented())
        assertTrue(acc.isPassthrough())
        assertTrue("分片拼接 == 原始 payload", joined(payloads(out!!)).contentEquals(hello.copyOfRange(5, hello.size)))
    }

    @Test
    fun `2段到达累积后正确分片`() {
        val hello = buildClientHello("github.com")
        val acc = ClientHelloAccumulator()
        val mid = hello.size / 2
        assertNull("首段未齐应继续累积", acc.feed(hello.copyOfRange(0, mid), 1000))
        assertFalse(acc.isPassthrough())
        val out = acc.feed(hello.copyOfRange(mid, hello.size), 1100)
        assertNotNull(out)
        assertTrue(acc.consumeFragmented())
        assertEquals(hello.size - 5, joined(payloads(out!!)).size)
    }

    @Test
    fun `3段到达累积后正确分片`() {
        val hello = buildClientHello("github.com")
        val acc = ClientHelloAccumulator()
        val a = 4; val b = 9
        assertNull(acc.feed(hello.copyOfRange(0, a), 1000))
        assertNull(acc.feed(hello.copyOfRange(a, a + b), 1100))
        val out = acc.feed(hello.copyOfRange(a + b, hello.size), 1200)
        assertNotNull(out)
        assertTrue(acc.consumeFragmented())
        assertEquals(hello.size - 5, joined(payloads(out!!)).size)
    }

    @Test
    fun `record头在首段body在次段累积后正确分片`() {
        val hello = buildClientHello("github.com")
        val acc = ClientHelloAccumulator()
        assertNull("仅 record 头应累积", acc.feed(hello.copyOfRange(0, 5), 1000))
        val out = acc.feed(hello.copyOfRange(5, hello.size), 1100)
        assertNotNull(out)
        assertTrue(acc.consumeFragmented())
        assertEquals(hello.size - 5, joined(payloads(out!!)).size)
    }

    @Test
    fun `非TLS首字节原样输出且passthrough`() {
        val data = "GET / HTTP/1.1\r\nHost: a\r\n\r\n".toByteArray()
        val acc = ClientHelloAccumulator()
        val out = acc.feed(data, 1000)
        assertTrue(out!!.contentEquals(data))
        assertTrue(acc.isPassthrough())
        assertFalse(acc.consumeFragmented())
    }

    @Test
    fun `首字节16但超时未凑齐则原样输出已累积并passthrough`() {
        val acc = ClientHelloAccumulator()
        // 声称 record len = 0x0100(256) → 需要 261 字节，只有 7 字节
        val part = byteArrayOf(0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x00)
        assertNull(acc.feed(part, 1000))
        val extra = byteArrayOf(0x02) // 迟到片段（已超 deadline 1500ms）
        val out = acc.feed(extra, 3000)
        assertNotNull(out)
        assertTrue(acc.isPassthrough())
        assertEquals("原样输出已累积全部字节", 8, out!!.size)
        assertEquals(part[0], out[0])
        assertEquals(extra[0], out[7])
        assertFalse(acc.consumeFragmented())
    }

    @Test
    fun `超限则原样输出并passthrough`() {
        val hello = buildClientHello("github.com")
        val acc = ClientHelloAccumulator(maxBuffer = 16)
        val chunk = hello.copyOfRange(0, 20) // 已超 maxBuffer，且 record 未齐
        val out = acc.feed(chunk, 1000)
        assertNotNull(out)
        assertTrue(acc.isPassthrough())
        assertEquals(20, out!!.size)
        assertTrue(out.contentEquals(chunk))
    }

    @Test
    fun `无SNI时按固定上限均匀拆分`() {
        val hello = buildClientHello("github.com", withSni = false)
        val acc = ClientHelloAccumulator()
        val out = acc.feed(hello, 1000)
        assertNotNull(out)
        assertTrue(acc.consumeFragmented())
        val parts = payloads(out!!)
        assertEquals(9, parts.size)
        assertTrue(joined(parts).contentEquals(hello.copyOfRange(5, hello.size)))
    }

    @Test
    fun `疑似TLS但非ClientHello则原样`() {
        // 0x16 + 合法版本，但 handshake type = 0x02（非 ClientHello）
        val data = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0, 0, 0, 0)
        val acc = ClientHelloAccumulator()
        val out = acc.feed(data, 1000)
        assertNotNull(out)
        assertTrue(out!!.contentEquals(data))
        assertTrue(acc.isPassthrough())
        assertFalse(acc.consumeFragmented())
    }

    @Test
    fun `分片失败则原样输出不卡死`() {
        // record len=1（不足 10 字节，fragmentTlsRecord 返回 null）
        val data = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x01, 0x01)
        val acc = ClientHelloAccumulator()
        assertNull(acc.feed(data, 1000))
        val out = acc.feed(byteArrayOf(0), 2501)
        assertNotNull(out)
        assertTrue(out!!.copyOfRange(0, data.size).contentEquals(data))
        assertEquals(data.size + 1, out.size)
        assertTrue(acc.isPassthrough())
        assertFalse(acc.consumeFragmented())
    }

    @Test
    fun `跨两个TLS record的ClientHello可提取SNI并分片`() {
        val hello = buildClientHello("github.com")
        val payload = hello.copyOfRange(5, hello.size)
        val split = 24
        fun record(part: ByteArray): ByteArray = byteArrayOf(
            0x16, 0x03, 0x03,
            ((part.size shr 8) and 0xff).toByte(),
            (part.size and 0xff).toByte(),
        ) + part
        val multi = record(payload.copyOfRange(0, split)) + record(payload.copyOfRange(split, payload.size))
        val inspected = TlsClientHelloRecords.inspect(multi)
        assertTrue(inspected is TlsClientHelloRecords.Inspection.Complete)
        assertEquals("github.com", (inspected as TlsClientHelloRecords.Inspection.Complete).serverName)
        val fragmented = requireNotNull(TlsClientHelloRecords.fragment(multi))
        assertTrue(fragmented.firstRecordEnd in 6 until fragmented.bytes.size)
    }

    @Test
    fun `固定熵生成可复现布局且TCP边界覆盖完整字节流`() {
        val hello = buildClientHello("gateway.discord.gg")
        val first = requireNotNull(TlsClientHelloRecords.fragment(hello, entropy = 7L))
        val repeated = requireNotNull(TlsClientHelloRecords.fragment(hello, entropy = 7L))
        assertArrayEquals(first.bytes, repeated.bytes)

        val tcpPlan = TlsClientHelloRecords.tcpWritePlan(first.bytes, entropy = 11L)
        val repeatedPlan = TlsClientHelloRecords.tcpWritePlan(first.bytes, entropy = 11L)
        assertArrayEquals(tcpPlan.writeEnds, repeatedPlan.writeEnds)
        assertTrue("SNI records 应进一步拆成 TCP writes", tcpPlan.writeEnds.size > first.writeEnds.size)
        assertEquals(first.bytes.size, tcpPlan.writeEnds.last())
        assertTrue(tcpPlan.writeEnds.asSequence().zipWithNext().all { (left, right) -> left < right })
        assertTrue(tcpPlan.urgentAfterWriteIndex in 0 until tcpPlan.writeEnds.lastIndex)
    }

    @Test
    fun `多record首record完整即分片其余原样跟随`() {
        val hello = buildClientHello("github.com")
        val extra = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x04, 9, 9, 9, 9)
        val both = hello + extra
        val acc = ClientHelloAccumulator()
        val out = acc.feed(both, 1000)
        assertNotNull(out)
        assertTrue(acc.consumeFragmented())
        assertTrue(joined(payloads(out!!)).contentEquals(hello.copyOfRange(5, hello.size)))
        val tail = out.copyOfRange(out.size - extra.size, out.size)
        assertTrue(tail.contentEquals(extra))
    }

    @Test
    fun `passthrough后后续数据原样透传`() {
        val hello = buildClientHello("github.com")
        val acc = ClientHelloAccumulator()
        assertNotNull(acc.feed(hello, 1000)) // 分片完成 → passthrough
        assertTrue("分片输出标记应被 writer 消费", acc.consumeFragmented())
        assertTrue(acc.isPassthrough())
        val more = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5)
        val out = acc.feed(more, 1100)
        assertTrue(out!!.contentEquals(more))
        assertFalse("后续 feed 不再产生分片标记", acc.consumeFragmented())
    }
}

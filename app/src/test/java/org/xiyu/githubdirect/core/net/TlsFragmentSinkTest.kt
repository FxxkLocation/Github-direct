package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsFragmentSinkTest {

    private fun buildClientHello(domain: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(0x01)
        out.write(0); out.write(0); out.write(0)
        out.write(0x03); out.write(0x03)
        out.write(ByteArray(32) { 0xAA.toByte() })
        out.write(0)
        out.write(0); out.write(2)
        out.write(0x13); out.write(0x01)
        out.write(0)
        val ext = java.io.ByteArrayOutputStream()
        ext.write(0x00); ext.write(0x00)
        val nameBytes = domain.toByteArray(Charsets.US_ASCII)
        val extBody = 2 + 1 + 2 + nameBytes.size
        ext.write((extBody shr 8) and 0xFF); ext.write(extBody and 0xFF)
        val listLen = 1 + 2 + nameBytes.size
        ext.write((listLen shr 8) and 0xFF); ext.write(listLen and 0xFF)
        ext.write(0x00)
        ext.write((nameBytes.size shr 8) and 0xFF); ext.write(nameBytes.size and 0xFF)
        ext.write(nameBytes)
        val extBytes = ext.toByteArray()
        out.write((extBytes.size shr 8) and 0xFF); out.write(extBytes.size and 0xFF)
        out.write(extBytes)
        val handshake = out.toByteArray()
        val handshakeLen = handshake.size - 4
        handshake[1] = ((handshakeLen shr 16) and 0xFF).toByte()
        handshake[2] = ((handshakeLen shr 8) and 0xFF).toByte()
        handshake[3] = (handshakeLen and 0xFF).toByte()
        val record = ByteArray(5 + handshake.size)
        record[0] = 0x16.toByte()
        record[1] = 0x03.toByte()
        record[2] = 0x01.toByte()
        record[3] = ((handshake.size shr 8) and 0xFF).toByte()
        record[4] = (handshake.size and 0xFF).toByte()
        System.arraycopy(handshake, 0, record, 5, handshake.size)
        return record
    }

    @Test
    fun `非TLS一次写出且不分片`() {
        val writes = ArrayList<ByteArray>()
        val sleeps = ArrayList<Long>()
        val sink = TlsFragmentSink(
            write = { d, o, l -> writes.add(d.copyOfRange(o, o + l)) },
            sleep = { sleeps.add(it) },
        )
        sink.write("hello".toByteArray())
        assertEquals(1, writes.size)
        assertEquals("hello", String(writes[0]))
        assertTrue(sleeps.isEmpty())
    }

    @Test
    fun `ClientHello按多record写出并使用短间隔`() {
        val hello = buildClientHello("github.com")
        val writes = ArrayList<ByteArray>()
        val sleeps = ArrayList<Long>()
        val sink = TlsFragmentSink(
            write = { d, o, l -> writes.add(d.copyOfRange(o, o + l)) },
            sleep = { sleeps.add(it) },
        )
        sink.write(hello)
        assertTrue(writes.size > 2)
        assertEquals(List(writes.size - 1) { TlsClientHelloRecords.WRITE_INTERVAL_MS }, sleeps)
        val combined = writes.fold(ByteArray(0), ByteArray::plus)
        val inspected = TlsClientHelloRecords.inspect(combined)
        assertTrue(inspected is TlsClientHelloRecords.Inspection.Complete)
        assertEquals("github.com", (inspected as TlsClientHelloRecords.Inspection.Complete).serverName)
    }
}

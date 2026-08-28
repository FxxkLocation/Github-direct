package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsWireCodecTest {

    @Test
    fun `构造查询并解析压缩名A响应`() {
        val query = DnsWireCodec.buildQuery("github.com", 1, id = 0x1234)!!
        assertEquals(0x1234, DnsPacketCodec.readU16(query, 0))
        assertEquals("github.com", DnsPacketCodec.parseDnsDomain(query))
        assertEquals(1, DnsPacketCodec.getQueryType(query))

        val ip = byteArrayOf(20, 205.toByte(), 243.toByte(), 166.toByte())
        val response = DnsPacketCodec.buildDnsResponse(
            query,
            DnsPacketCodec.getQuestionEnd(query),
            listOf(ip),
            1,
        )!!
        val parsed = DnsWireCodec.parseAnswers(response, 0x1234, 1)!!
        assertEquals(0, parsed.rcode)
        assertEquals(1, parsed.addresses.size)
        assertArrayEquals(ip, parsed.addresses.single())
    }

    @Test
    fun `拒绝事务ID不匹配与非法域名`() {
        val query = DnsWireCodec.buildQuery("api.github.com", 28, id = 7)!!
        val response = DnsPacketCodec.buildNodataResponse(query)
        assertNull(DnsWireCodec.parseAnswers(response, 8, 28))
        assertNull(DnsWireCodec.buildQuery("bad domain", 1))
        assertNull(DnsWireCodec.buildQuery("github.com", 65))
    }
}

package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DnsPacketCodecTest {

    private fun buildQuery(domain: String, qtype: Int): ByteArray {
        val qname = java.io.ByteArrayOutputStream().apply {
            for (label in domain.split(".")) {
                write(label.length)
                write(label.toByteArray(Charsets.US_ASCII))
            }
            write(0)
        }.toByteArray()
        val dns = java.io.ByteArrayOutputStream().apply {
            write(0x12); write(0x34)
            write(0x01); write(0x00)
            write(0); write(1)
            write(0); write(0)
            write(0); write(0)
            write(0); write(0)
            write(qname)
            write((qtype shr 8) and 0xFF); write(qtype and 0xFF)
            write(0); write(1)
        }.toByteArray()
        return dns
    }

    @Test
    fun `roundtrip解析域名和类型`() {
        val dns = buildQuery("github.com", 1)
        val q = DnsPacketCodec.parseDnsQuery(dns)
        assertNotNull(q)
        assertEquals("github.com", q!!.domain)
        assertEquals(1, q.qtype)
        assertEquals(dns.size, q.questionEnd)
    }

    @Test
    fun `AAAA查询roundtrip`() {
        val dns = buildQuery("api.github.com", 28)
        val q = DnsPacketCodec.parseDnsQuery(dns)
        assertEquals("api.github.com", q!!.domain)
        assertEquals(28, q.qtype)
    }

    @Test
    fun `越界和非法输入返回null`() {
        assertNull(DnsPacketCodec.parseDnsQuery(ByteArray(11))) // < 12 字节
        val truncated = buildQuery("github.com", 1).copyOf(10)  // 截断
        assertNull(DnsPacketCodec.parseDnsQuery(truncated))
    }

    @Test
    fun `buildDnsResponse只返回匹配类型的地址`() {
        val dns = buildQuery("github.com", 1)
        val resp = DnsPacketCodec.buildDnsResponse(
            dns, DnsPacketCodec.getQuestionEnd(dns),
            listOf(
                IpAddresses.parseIpv4("140.82.112.3")!!,
                IpAddresses.parseIpv6("2606:50c0::1")!!,
            ),
            1, 300,
        )
        assertNotNull(resp)
        assertEquals(1, DnsPacketCodec.readU16(resp!!, 6)) // ANCOUNT=1
        // NOERROR
        assertEquals(0, resp[3].toInt() and 0x0F)
        // 第一条 A 记录 rdata
        val rdata = resp.copyOfRange(DnsPacketCodec.getQuestionEnd(dns) + 12, DnsPacketCodec.getQuestionEnd(dns) + 16)
        assertEquals(140, rdata[0].toInt() and 0xFF)
    }

    @Test
    fun `buildDnsResponse无匹配类型返回null`() {
        val dns = buildQuery("github.com", 28)
        val resp = DnsPacketCodec.buildDnsResponse(
            dns, DnsPacketCodec.getQuestionEnd(dns),
            listOf(IpAddresses.parseIpv4("140.82.112.3")!!),
            28, 300,
        )
        assertNull(resp) // 只有 v4，查询 AAAA
    }

    @Test
    fun `NXDOMAIN和SERVFAIL的RCODE`() {
        val dns = buildQuery("github.com", 1)
        assertEquals(3, DnsPacketCodec.buildNxdomainResponse(dns)[3].toInt() and 0x0F)
        assertEquals(2, DnsPacketCodec.buildServFailResponse(dns)[3].toInt() and 0x0F)
        assertEquals(0, DnsPacketCodec.buildNodataResponse(dns, DnsPacketCodec.getQuestionEnd(dns))[3].toInt() and 0x0F)
        assertEquals(0, DnsPacketCodec.readU16(
            DnsPacketCodec.buildNodataResponse(dns, DnsPacketCodec.getQuestionEnd(dns)), 6))
    }

    @Test
    fun `constructIpPacket交换地址和端口`() {
        val dns = buildQuery("github.com", 1)
        val queryPacket = ByteArray(28 + dns.size)
        queryPacket[0] = 0x45
        queryPacket[9] = 17
        queryPacket[12] = 10; queryPacket[13] = 0; queryPacket[14] = 0; queryPacket[15] = 2  // src
        queryPacket[16] = 10; queryPacket[17] = 0; queryPacket[18] = 0; queryPacket[19] = 53 // dst
        DnsPacketCodec.writeU16(queryPacket, 20, 12345) // src port
        DnsPacketCodec.writeU16(queryPacket, 22, 53)    // dst port
        DnsPacketCodec.writeU16(queryPacket, 24, 8 + dns.size)
        System.arraycopy(dns, 0, queryPacket, 28, dns.size)

        val resp = DnsPacketCodec.buildNodataResponse(dns, DnsPacketCodec.getQuestionEnd(dns))
        val ipPacket = DnsPacketCodec.constructIpPacket(queryPacket, 20, resp)

        assertEquals(10, ipPacket[12].toInt() and 0xFF) // src = 原 dst
        assertEquals(53, ipPacket[15].toInt() and 0xFF)
        assertEquals(10, ipPacket[16].toInt() and 0xFF) // dst = 原 src
        assertEquals(2, ipPacket[19].toInt() and 0xFF)
        assertEquals(53, DnsPacketCodec.readU16(ipPacket, 20))  // src port = 53
        assertEquals(12345, DnsPacketCodec.readU16(ipPacket, 22)) // dst port = 12345
        assertArrayEquals(resp, ipPacket.copyOfRange(28, 28 + resp.size))
    }
}

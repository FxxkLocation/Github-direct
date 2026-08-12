package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.net.RelayIpTable
import org.xiyu.githubdirect.core.net.VirtualIpPool
import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.ResolverPolicy
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.SuffixMatcher
import org.xiyu.githubdirect.core.rules.TransportPolicy.CLEAN_DNS
import org.xiyu.githubdirect.core.rules.TransportPolicy.NXDOMAIN
import org.xiyu.githubdirect.core.rules.TransportPolicy.TLS_FRAGMENT_RELAY
import org.xiyu.githubdirect.test.FakeBinder
import org.xiyu.githubdirect.test.InMemorySettingsStore
import org.xiyu.githubdirect.test.buildRegistry
import org.xiyu.githubdirect.test.dnsAncount
import org.xiyu.githubdirect.test.dnsRcode
import org.xiyu.githubdirect.test.dohResponder

/**
 * SelectiveDnsEngine 决策流测试（全部 mock，无真实网络）。
 *
 * 核心不变式（§28/§29）：
 * - 非目标/无法合成 → raw 字节原样转发，绝不 JSON 重建（qtype TXT/HTTPS/未知 全保留）
 * - 合成路径失败 → SERVFAIL；raw 转发失败 → null（非 NXDOMAIN）
 * - 上游 RCode 原样透传
 */
class SelectiveDnsEngineTest {

    /** 可控假上游：wire/plain 收到的原始字节 + 可编程应答。 */
    private class FakeUpstream {
        val wireReceived = ArrayList<ByteArray>()
        val plainReceived = ArrayList<ByteArray>()
        var wireBody: (ByteArray) -> ByteArray? = { null }
        var plainBody: (ByteArray) -> ByteArray? = { null }
    }

    /** 构造裸 DNS 查询字节（12 字节头 + question）。 */
    private fun buildRawQuery(domain: String, qtype: Int): ByteArray {
        val qname = java.io.ByteArrayOutputStream().apply {
            for (label in domain.split(".")) {
                write(label.length)
                write(label.toByteArray(Charsets.US_ASCII))
            }
            write(0)
        }.toByteArray()
        return java.io.ByteArrayOutputStream().apply {
            write(0x12); write(0x34)
            write(0x01); write(0x00)
            write(0); write(1)       // QDCOUNT=1
            write(0); write(0)       // ANCOUNT=0
            write(0); write(0)       // NSCOUNT=0
            write(0); write(0)       // ARCOUNT=0
            write(qname)
            write((qtype shr 8) and 0xFF); write(qtype and 0xFF)
            write(0); write(1)       // QCLASS=IN
        }.toByteArray()
    }

    private fun engine(
        upstream: FakeUpstream,
        vararg profiles: ServiceProfile,
        dohJson: (String) -> String? = { null },
    ): SelectiveDnsEngine {
        val registry = buildRegistry(InMemorySettingsStore(), *profiles)
        val resolver = EndpointResolver(FakeBinder(dohJson), servers = listOf("http://fake.doh/"))
        val wire = WireDohClient(transportOverride = { _, raw, _ ->
            upstream.wireReceived.add(raw); upstream.wireBody(raw)
        })
        val plain = PlainDnsClient(queryOverride = { raw, _ ->
            upstream.plainReceived.add(raw); upstream.plainBody(raw)
        })
        return SelectiveDnsEngine(
            registry, resolver, EndpointCache(), VirtualIpPool(), RelayIpTable(), wire, plain,
        )
    }

    private fun profile(id: String, priority: Int = 5, vararg rules: DomainRule) = ServiceProfile(
        id = id,
        displayName = id,
        category = "test",
        enabledByDefault = true,
        priority = priority,
        domains = rules.toList(),
    )

    // ---------- 非目标域：raw 原样转发，绝不 JSON 重建（§28） ----------

    @Test
    fun `未命中域TXT查询raw转发`() {
        val up = FakeUpstream()
        val canned = byteArrayOf(9)
        up.wireBody = { canned }
        val e = engine(
            up,
            profile("p", 5, DomainRule("x", ExactMatcher("x.example.com"), CLEAN_DNS)),
        )
        val raw = buildRawQuery("nomatch.example.com", 16) // TXT
        val resp = e.handleQuery(raw)
        assertNotNull(resp)
        assertTrue(resp === canned) // 上游响应原样返回
        assertArrayEquals(raw, up.wireReceived[0]) // 原始字节原样转发
        assertTrue(up.plainReceived.isEmpty())
    }

    @Test
    fun `未命中域HTTPS未知qtype与ANY均raw转发`() {
        val up = FakeUpstream()
        up.wireBody = { raw -> DnsPacketCodec.buildEmptyResponse(raw, DnsPacketCodec.getQuestionEnd(raw)) }
        val e = engine(
            up,
            profile("p", 5, DomainRule("x", ExactMatcher("x.example.com"), CLEAN_DNS)),
        )
        for (qtype in listOf(65, 99, 255)) { // HTTPS / 未知 / ANY
            up.wireReceived.clear()
            val raw = buildRawQuery("other.example.com", qtype)
            val resp = e.handleQuery(raw)
            assertNotNull("qtype=$qtype", resp)
            assertArrayEquals(raw, up.wireReceived[0])
        }
    }

    @Test
    fun `normalize失败raw转发不破坏`() {
        val up = FakeUpstream()
        up.wireBody = { raw -> byteArrayOf(7) }
        val e = engine(up)
        // 下划线域名：normalize 失败 → 原样转发（不能破坏）
        val raw = buildRawQuery("bad_domain.example.com", 1)
        val resp = e.handleQuery(raw)
        assertNotNull(resp)
        assertArrayEquals(raw, up.wireReceived[0])
    }

    // ---------- 目标域：relay 合成 ----------

    @Test
    fun `relay域A查询返回vIP`() {
        val up = FakeUpstream()
        val e = engine(
            up,
            profile(
                "github", 5,
                DomainRule("github.com", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY, fixedIp = "140.82.112.3"),
            ),
        )
        val raw = buildRawQuery("github.com", 1)
        val resp = e.handleQuery(raw)!!
        assertEquals(0, dnsRcode(resp))
        assertEquals(1, dnsAncount(resp))
        val qEnd = DnsPacketCodec.getQuestionEnd(raw)
        val rdata = resp.copyOfRange(qEnd + 12, qEnd + 16)
        assertEquals(10, rdata[0].toInt() and 0xFF) // 10.0.0.x 网段
        assertEquals(0, rdata[1].toInt() and 0xFF)
        assertEquals(0, rdata[2].toInt() and 0xFF)
        assertTrue((rdata[3].toInt() and 0xFF) in 10..254)
        assertTrue(up.wireReceived.isEmpty()) // 未走转发
    }

    @Test
    fun `relay域同域复用同一vIP`() {
        val up = FakeUpstream()
        val e = engine(
            up,
            profile(
                "github", 5,
                DomainRule("github.com", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY, fixedIp = "140.82.112.3"),
            ),
        )
        val qEnd = DnsPacketCodec.getQuestionEnd(buildRawQuery("github.com", 1))
        val r1 = e.handleQuery(buildRawQuery("github.com", 1))!!
        val r2 = e.handleQuery(buildRawQuery("github.com", 1))!!
        val a1 = r1.copyOfRange(qEnd + 12, qEnd + 16)
        val a2 = r2.copyOfRange(qEnd + 12, qEnd + 16)
        assertArrayEquals(a1, a2)
    }

    @Test
    fun `relay域AAAA带抑制返回NODATA`() {
        val up = FakeUpstream()
        val p = ServiceProfile(
            id = "github", displayName = "github", category = "test", enabledByDefault = true,
            priority = 5, aaaaSuppress = true,
            domains = listOf(
                DomainRule("g", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY, fixedIp = "140.82.112.3"),
            ),
        )
        val e = engine(up, p)
        val resp = e.handleQuery(buildRawQuery("github.com", 28))!!
        assertEquals(0, dnsRcode(resp)) // NOERROR，绝不 NXDOMAIN
        assertEquals(0, dnsAncount(resp)) // NODATA
        assertTrue(up.wireReceived.isEmpty())
    }

    @Test
    fun `relay域AAAA无抑制raw转发`() {
        val up = FakeUpstream()
        up.wireBody = { raw -> byteArrayOf(3) }
        val e = engine(
            up,
            profile(
                "github", 5,
                DomainRule("g", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY, fixedIp = "140.82.112.3"),
            ),
        )
        val raw = buildRawQuery("github.com", 28)
        val resp = e.handleQuery(raw)
        assertNotNull(resp)
        assertArrayEquals(raw, up.wireReceived[0]) // 不合成，交给上游
    }

    @Test
    fun `relay域TXT查询raw转发不合成`() {
        val up = FakeUpstream()
        up.wireBody = { raw -> byteArrayOf(4) }
        val e = engine(
            up,
            profile(
                "github", 5,
                DomainRule("g", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY, fixedIp = "140.82.112.3"),
            ),
        )
        val raw = buildRawQuery("github.com", 16)
        val resp = e.handleQuery(raw)
        assertNotNull(resp)
        assertArrayEquals(raw, up.wireReceived[0])
    }

    @Test
    fun `relay域取真实IP失败返回SERVFAIL`() {
        val up = FakeUpstream()
        val e = engine(
            up,
            profile(
                "github", 5,
                DomainRule(
                    "g", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY,
                    resolver = ResolverPolicy.PROVIDER_ONLY, // 无 hosts 表 + 无 DoH → 失败
                ),
            ),
        )
        val resp = e.handleQuery(buildRawQuery("github.com", 1))!!
        assertEquals(2, dnsRcode(resp)) // SERVFAIL，绝不 NXDOMAIN
        assertTrue(up.wireReceived.isEmpty())
    }

    // ---------- 目标域：NXDOMAIN / CLEAN_DNS ----------

    @Test
    fun `NXDOMAIN域返回NXDOMAIN且不触网`() {
        val up = FakeUpstream()
        val e = engine(
            up,
            profile("ads", 5, DomainRule("nx", ExactMatcher("tracking.example.com"), NXDOMAIN)),
        )
        val resp = e.handleQuery(buildRawQuery("tracking.example.com", 1))!!
        assertEquals(3, dnsRcode(resp))
        assertTrue(up.wireReceived.isEmpty())
        assertTrue(up.plainReceived.isEmpty())
    }

    @Test
    fun `CLEAN_DNS域A查询走JSON解析返回真实IP`() {
        val up = FakeUpstream()
        val e = engine(
            up,
            profile("p", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
            dohJson = dohResponder(v4 = "1.2.3.4"),
        )
        val raw = buildRawQuery("clean.example.com", 1)
        val resp = e.handleQuery(raw)!!
        assertEquals(0, dnsRcode(resp))
        assertEquals(1, dnsAncount(resp))
        val qEnd = DnsPacketCodec.getQuestionEnd(raw)
        val rdata = resp.copyOfRange(qEnd + 12, qEnd + 16)
        assertEquals("1.2.3.4", IpAddresses.ipv4ToString(rdata))
        assertTrue(up.wireReceived.isEmpty()) // 合成路径，未走 raw 转发
    }

    @Test
    fun `CLEAN_DNS域TXT查询raw转发`() {
        val up = FakeUpstream()
        up.wireBody = { raw -> byteArrayOf(5) }
        val e = engine(
            up,
            profile("p", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
            dohJson = dohResponder(v4 = "1.2.3.4"),
        )
        val raw = buildRawQuery("clean.example.com", 16)
        val resp = e.handleQuery(raw)
        assertNotNull(resp)
        assertArrayEquals(raw, up.wireReceived[0])
    }

    // ---------- raw 转发回退与错误语义（§29） ----------

    @Test
    fun `wire失败回退明文UDP`() {
        val up = FakeUpstream()
        up.wireBody = { null } // wire DoH 失败
        up.plainBody = { raw -> byteArrayOf(6) } // 明文回退成功
        val e = engine(up)
        val raw = buildRawQuery("nomatch.example.com", 1)
        val resp = e.handleQuery(raw)
        assertNotNull(resp)
        assertArrayEquals(raw, up.wireReceived[0])
        assertArrayEquals(raw, up.plainReceived[0]) // 回退收到同一原始字节
    }

    @Test
    fun `全部上游失败返回null而非NXDOMAIN`() {
        val up = FakeUpstream() // wire/plain 均无应答
        val e = engine(up)
        val resp = e.handleQuery(buildRawQuery("nomatch.example.com", 1))
        assertNull(resp) // 调用方回 SERVFAIL；绝不伪装 NXDOMAIN
        assertFalse(up.wireReceived.isEmpty())
        assertFalse(up.plainReceived.isEmpty())
    }

    @Test
    fun `上游NXDOMAIN应答RCode原样透传`() {
        val up = FakeUpstream()
        up.wireBody = { raw -> DnsPacketCodec.buildNxdomainResponse(raw) }
        val e = engine(up)
        val raw = buildRawQuery("nomatch.example.com", 1)
        val resp = e.handleQuery(raw)!!
        assertEquals(3, dnsRcode(resp)) // 上游 NXDOMAIN 透传（非本地合成）
        assertArrayEquals(DnsPacketCodec.buildNxdomainResponse(raw), resp)
    }

    @Test
    fun `解析失败返回null`() {
        val up = FakeUpstream()
        val e = engine(up)
        assertNull(e.handleQuery(ByteArray(4)))
        assertTrue(up.wireReceived.isEmpty())
    }
}

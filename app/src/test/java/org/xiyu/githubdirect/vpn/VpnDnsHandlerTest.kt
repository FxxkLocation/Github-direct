package org.xiyu.githubdirect.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.DnsPacketCodec
import org.xiyu.githubdirect.core.dns.EndpointCache
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.PlainDnsClient
import org.xiyu.githubdirect.core.dns.SelectiveDnsEngine
import org.xiyu.githubdirect.core.dns.WireDohClient
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
import org.xiyu.githubdirect.test.answerRdata
import org.xiyu.githubdirect.test.buildDnsQueryPacket
import org.xiyu.githubdirect.test.buildRegistry
import org.xiyu.githubdirect.test.dnsAncount
import org.xiyu.githubdirect.test.dnsRcode
import org.xiyu.githubdirect.test.extractDnsResponse

/**
 * VpnDnsHandler 薄壳测试（Phase 2）：UDP/IP 封装 + 引擎注入。
 * 策略语义本身在 SelectiveDnsEngineTest 全覆盖；这里验证：
 * - 引擎返回 null（上游全失败）→ 壳层回 SERVFAIL（§29，绝不 NXDOMAIN）
 * - 未命中/relay 非 A → raw 透传（原样返回上游响应）
 */
class VpnDnsHandlerTest {

    /** 可控假上游（wire/plain 收到字节 + 可编程应答）。 */
    private class FakeUpstream {
        val wireReceived = ArrayList<ByteArray>()
        val plainReceived = ArrayList<ByteArray>()
        var wireBody: (ByteArray) -> ByteArray? = { null }
        var plainBody: (ByteArray) -> ByteArray? = { null }
    }

    private fun handler(upstream: FakeUpstream, vararg profiles: ServiceProfile): VpnDnsHandler {
        val registry = buildRegistry(InMemorySettingsStore(), *profiles)
        val resolver = EndpointResolver(FakeBinder({ null }), servers = listOf("http://fake.doh/"))
        val wire = WireDohClient(transportOverride = { _, raw, _ ->
            upstream.wireReceived.add(raw); upstream.wireBody(raw)
        })
        val plain = PlainDnsClient(queryOverride = { raw, _ ->
            upstream.plainReceived.add(raw); upstream.plainBody(raw)
        })
        val engine = SelectiveDnsEngine(
            registry, resolver, EndpointCache(), VirtualIpPool(), RelayIpTable(), wire, plain,
        )
        return VpnDnsHandler(registry, resolver, EndpointCache(), VirtualIpPool(), RelayIpTable(), engine)
    }

    private fun profile(id: String, priority: Int = 5, vararg rules: DomainRule) = ServiceProfile(
        id = id,
        displayName = id,
        category = "test",
        enabledByDefault = true,
        priority = priority,
        domains = rules.toList(),
    )

    // ---------- NXDOMAIN 仲裁（block 支配 allow） ----------

    @Test
    fun `NX域返回NXDOMAIN应答`() {
        val h = handler(
            FakeUpstream(), // 若走到转发即测试失败（NX 应提前返回）
            profile("ads", 5, DomainRule("nx", ExactMatcher("tracking.example.com"), NXDOMAIN)),
            profile("corp", 5, DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
        )
        val resp = extractDnsResponse(h.handle(buildDnsQueryPacket("tracking.example.com", 1), 20)!!)
        assertEquals(3, dnsRcode(resp)) // NXDOMAIN
    }

    @Test
    fun `NX域对AAAA查询同样返回NXDOMAIN`() {
        val h = handler(
            FakeUpstream(),
            profile("ads", 5, DomainRule("nx", ExactMatcher("tracking.example.com"), NXDOMAIN)),
        )
        val resp = extractDnsResponse(h.handle(buildDnsQueryPacket("tracking.example.com", 28), 20)!!)
        assertEquals(3, dnsRcode(resp))
    }

    // ---------- AAAA 抑制 ----------

    @Test
    fun `aaaaSuppress下AAAA查询返回NODATA而非NXDOMAIN`() {
        val h = handler(
            FakeUpstream(),
            ServiceProfile(
                id = "corp", displayName = "corp", category = "test", enabledByDefault = true,
                priority = 5, aaaaSuppress = true,
                domains = listOf(DomainRule("s", SuffixMatcher(".example.com"), CLEAN_DNS)),
            ),
        )
        val resp = extractDnsResponse(h.handle(buildDnsQueryPacket("x.example.com", 28), 20)!!)
        assertEquals(0, dnsRcode(resp)) // NOERROR
        assertEquals(0, dnsAncount(resp)) // NODATA
    }

    // ---------- relay 路径 ----------

    @Test
    fun `relay域A查询返回vIP`() {
        val h = handler(
            FakeUpstream(),
            profile(
                "github", 5,
                DomainRule("github.com", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY, fixedIp = "140.82.112.3"),
            ),
        )
        val query = buildDnsQueryPacket("github.com", 1)
        val resp = extractDnsResponse(h.handle(query, 20)!!)
        assertEquals(0, dnsRcode(resp))
        assertEquals(1, dnsAncount(resp))
        val rdata = answerRdata(resp, DnsPacketCodec.getQuestionEnd(extractDnsResponse(query)))
        assertEquals(10, rdata[0].toInt() and 0xFF) // 10.0.0.x 网段
        assertEquals(0, rdata[1].toInt() and 0xFF)
        assertEquals(0, rdata[2].toInt() and 0xFF)
        assertTrue((rdata[3].toInt() and 0xFF) in 10..254)
    }

    @Test
    fun `relay域AAAA查询raw转发不合成`() {
        val up = FakeUpstream()
        val query = buildDnsQueryPacket("github.com", 28)
        val rawQuery = extractDnsResponse(query)
        val canned = DnsPacketCodec.buildEmptyResponse(rawQuery, DnsPacketCodec.getQuestionEnd(rawQuery))
        up.wireBody = { canned }
        val h = handler(
            up,
            profile(
                "github", 5,
                DomainRule("github.com", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY, fixedIp = "140.82.112.3"),
            ),
        )
        val resp = extractDnsResponse(h.handle(query, 20)!!)
        assertNotNull(resp)
        assertEquals(canned.toList(), resp.toList()) // 上游响应原样透传
        assertEquals(rawQuery.toList(), up.wireReceived[0].toList()) // 原始字节转发
    }

    @Test
    fun `relay域取真实IP失败返回SERVFAIL`() {
        val h = handler(
            FakeUpstream(),
            profile(
                "github", 5,
                DomainRule(
                    "github.com", ExactMatcher("github.com"), TLS_FRAGMENT_RELAY,
                    resolver = ResolverPolicy.PROVIDER_ONLY, // 无 hosts 表 + 无 DoH → 失败
                ),
            ),
        )
        val resp = extractDnsResponse(h.handle(buildDnsQueryPacket("github.com", 1), 20)!!)
        assertEquals(2, dnsRcode(resp)) // SERVFAIL
    }

    // ---------- 未命中：raw 转发（绝不 JSON 重建） ----------

    @Test
    fun `未命中域raw转发返回上游响应`() {
        val up = FakeUpstream()
        val query = buildDnsQueryPacket("notmatched.org", 1)
        val rawQuery = extractDnsResponse(query)
        val canned = DnsPacketCodec.buildEmptyResponse(rawQuery, DnsPacketCodec.getQuestionEnd(rawQuery))
        up.wireBody = { canned }
        val h = handler(
            up,
            profile("github", 5, DomainRule("github.com", ExactMatcher("github.com"), CLEAN_DNS)),
        )
        val resp = extractDnsResponse(h.handle(query, 20)!!)
        assertNotNull(resp)
        assertEquals(canned.toList(), resp.toList())
        assertEquals(rawQuery.toList(), up.wireReceived[0].toList())
        assertTrue(up.wireReceived.size == 1) // 只走 wire，未走 plain
    }

    // ---------- 错误语义（§29） ----------

    @Test
    fun `上游全部失败返回SERVFAIL而非NXDOMAIN`() {
        val h = handler(
            FakeUpstream(), // wire/plain 均无应答
            profile("github", 5, DomainRule("github.com", ExactMatcher("github.com"), CLEAN_DNS)),
        )
        val resp = extractDnsResponse(h.handle(buildDnsQueryPacket("notmatched.org", 1), 20)!!)
        assertEquals(2, dnsRcode(resp)) // SERVFAIL
    }

    @Test
    fun `非法输入返回null`() {
        val h = handler(
            FakeUpstream(),
            profile("github", 5, DomainRule("github.com", ExactMatcher("github.com"), CLEAN_DNS)),
        )
        assertNull(h.handle(byteArrayOf(1, 2, 3), 20))
    }
}

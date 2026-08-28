package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.WireDohClient.Health
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class WireDohClientTest {

    // ---------- HTTP 请求字节构造（纯函数） ----------

    @Test
    fun `buildHttpPost方法行和头格式正确`() {
        val body = "abc".toByteArray(Charsets.US_ASCII)
        val req = WireDohClient.buildHttpPost("dns.alidns.com", body)
        val text = String(req, Charsets.US_ASCII)
        assertTrue(text.startsWith("POST /dns-query HTTP/1.1\r\n"))
        assertTrue(text.contains("Host: dns.alidns.com\r\n"))
        assertTrue(text.contains("Accept: application/dns-message\r\n"))
        assertTrue(text.contains("Content-Type: application/dns-message\r\n"))
        assertTrue(text.contains("Content-Length: 3\r\n"))
        assertTrue(text.contains("Connection: close\r\n"))
        // 双 CRLF 结束头，随后是原始 body
        assertTrue(text.endsWith("\r\n\r\nabc"))
    }

    @Test
    fun `buildHttpPost二进制body原样追加`() {
        val body = byteArrayOf(0x00, 0x01, 0xFF.toByte(), 0xAB.toByte())
        val req = WireDohClient.buildHttpPost("dns.google", body)
        assertArrayEquals(body, req.copyOfRange(req.size - 4, req.size))
        val head = String(req.copyOfRange(0, req.size - 4), Charsets.US_ASCII)
        assertTrue(head.contains("Content-Length: 4\r\n"))
    }

    @Test
    fun `buildHttpPost支持提供方路径并拒绝请求注入`() {
        val req = WireDohClient.buildHttpPost(
            "doh.cleanbrowsing.org",
            "/doh/security-filter/",
            byteArrayOf(1, 2),
        )
        assertTrue(String(req, Charsets.US_ASCII).startsWith(
            "POST /doh/security-filter/ HTTP/1.1\r\n",
        ))
        runCatching {
            WireDohClient.buildHttpPost("safe.example", "/dns-query\r\nX-Bad: 1", ByteArray(0))
        }.onSuccess { throw AssertionError("CRLF path must be rejected") }
    }

    @Test
    fun `默认首选无过滤Mullvad且国内端点仅作污染观察器`() {
        val defaults = WireDohClient.DEFAULT_ENDPOINTS
        assertEquals("194.242.2.2", defaults.first().ip)
        assertEquals("dns.mullvad.net", defaults.first().hostname)
        assertEquals("/dns-query", defaults.first().path)
        assertTrue(defaults.first().trustedForAnswers)
        assertTrue(defaults.any {
            it.ip == "76.76.10.11" &&
                it.hostname == "freedns.controld.com" &&
                it.path == "/p0" &&
                it.resolverId == "controld-unfiltered" &&
                it.trustedForAnswers
        })
        assertTrue(defaults.filterNot(WireDohClient.WireEndpoint::trustedForAnswers).all {
            it.resolverId.endsWith("-observer")
        })
    }

    // ---------- HTTP 响应解析（纯函数） ----------

    @Test
    fun `parseHttpResponse返回200与body`() {
        val body = byteArrayOf(1, 2, 3, 4)
        val raw = ("HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/dns-message\r\n" +
            "Content-Length: ${body.size}\r\n" +
            "\r\n").toByteArray(Charsets.US_ASCII) + body
        val parsed = WireDohClient.parseHttpResponse(raw)
        assertNotNull(parsed)
        assertEquals(200, parsed!!.first)
        assertArrayEquals(body, parsed.second)
    }

    @Test
    fun `parseHttpResponse非200返回null body`() {
        val raw = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val parsed = WireDohClient.parseHttpResponse(raw)
        assertNotNull(parsed)
        assertEquals(400, parsed!!.first)
        assertNull(parsed.second)
    }

    @Test
    fun `parseHttpResponse无ContentLength取剩余字节`() {
        val raw = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nABCD".toByteArray(Charsets.US_ASCII)
        val parsed = WireDohClient.parseHttpResponse(raw)
        assertArrayEquals("ABCD".toByteArray(Charsets.US_ASCII), parsed!!.second)
    }

    @Test
    fun `parseHttpResponse声明超长拒绝截断body`() {
        val raw = ("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
            .toByteArray(Charsets.US_ASCII)
        assertNull(WireDohClient.parseHttpResponse(raw))
    }

    @Test
    fun `parseHttpResponse chunked不支持返回null`() {
        val raw = ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd")
            .toByteArray(Charsets.US_ASCII)
        assertNull(WireDohClient.parseHttpResponse(raw))
    }

    @Test
    fun `parseHttpResponse非法输入返回null`() {
        assertNull(WireDohClient.parseHttpResponse(ByteArray(0)))
        assertNull(WireDohClient.parseHttpResponse("HTTP/1.1 200 OK no header separator".toByteArray()))
        assertNull(WireDohClient.parseHttpResponse(
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n".toByteArray(),
        ))
        assertNull(WireDohClient.parseHttpResponse("ICY 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray()))
    }

    @Test
    fun `wire响应只接受application dns message媒体类型`() {
        assertTrue(WireDohClient.hasDnsMessageContentType(
            "HTTP/1.1 200 OK\r\nContent-Type: Application/DNS-Message; charset=binary\r\n\r\n".toByteArray(),
        ))
        assertFalse(WireDohClient.hasDnsMessageContentType(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".toByteArray(),
        ))
        assertFalse(WireDohClient.hasDnsMessageContentType(
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n".toByteArray(),
        ))
    }

    @Test
    fun `DoH响应必须匹配事务ID opcode且设置QR`() {
        val query = ByteArray(12).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = 0x01
        }
        val valid = query.copyOf().apply { this[2] = 0x81.toByte() }
        assertTrue(WireDohClient.isResponseForQuery(query, valid))
        assertFalse(WireDohClient.isResponseForQuery(query, valid.copyOf().apply { this[1] = 0x35 }))
        assertFalse(WireDohClient.isResponseForQuery(query, valid.copyOf().apply { this[2] = 0x01 }))
        assertFalse(WireDohClient.isResponseForQuery(query, valid.copyOf().apply { this[2] = 0x89.toByte() }))
    }

    // ---------- Hedging（§33，注入假 transport） ----------

    private val ep1 = WireDohClient.WireEndpoint("1.1.1.1", "a.test")
    private val ep2 = WireDohClient.WireEndpoint("2.2.2.2", "b.test")

    @Test
    fun `普通回答不会调用仅观察端点`() {
        val observer = WireDohClient.WireEndpoint(
            "9.9.9.9",
            "observer.test",
            trustedForAnswers = false,
        )
        val calls = Collections.synchronizedList(ArrayList<String>())
        val client = WireDohClient(
            endpoints = listOf(observer, ep1),
            transport = { ep, _, _ -> calls += ep.hostname; byteArrayOf(1) },
        )
        assertArrayEquals(byteArrayOf(1), client.post(ByteArray(12), 500))
        assertEquals(listOf("a.test"), calls)
    }

    @Test
    fun `候选发现每个解析器只查询一个IP并包含观察器`() {
        val aSecondary = ep1.copy(ip = "1.1.1.2")
        val observer = WireDohClient.WireEndpoint(
            "9.9.9.9",
            "observer.test",
            resolverId = "observer",
            trustedForAnswers = false,
        )
        val calls = Collections.synchronizedList(ArrayList<String>())
        val client = WireDohClient(
            endpoints = listOf(ep1, aSecondary, ep2, observer),
            transport = { ep, _, _ ->
                calls += ep.ip
                byteArrayOf(ep.ip.last().digitToInt().toByte())
            },
        )
        val responses = client.postAllDistinctResolvers(
            ByteArray(12),
            timeoutMs = 500,
            maxTrustedResponses = 2,
            maxObserverResponses = 1,
            maxResolvers = 3,
        )
        assertEquals(3, responses.size)
        assertEquals(2, responses.count { it.endpoint.trustedForAnswers })
        assertEquals(1, responses.count { !it.endpoint.trustedForAnswers })
        assertTrue("同 resolver 的备用 IP 不应重复查询: $calls", "1.1.1.2" !in calls)
        assertTrue("观察器必须参与候选发现: $calls", "9.9.9.9" in calls)
    }

    @Test
    fun `候选发现固定主解析器并轮换第二可信提供方`() {
        val third = WireDohClient.WireEndpoint("3.3.3.3", "c.test")
        val observer = WireDohClient.WireEndpoint(
            "9.9.9.9",
            "observer.test",
            resolverId = "observer",
            trustedForAnswers = false,
        )
        val calls = Collections.synchronizedList(ArrayList<String>())
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2, third, observer),
            transport = { ep, _, _ -> calls += ep.hostname; byteArrayOf(1) },
        )

        client.postAllDistinctResolvers(ByteArray(12), timeoutMs = 500)
        val firstRound = calls.toSet()
        calls.clear()
        client.postAllDistinctResolvers(ByteArray(12), timeoutMs = 500)
        val secondRound = calls.toSet()

        assertEquals(setOf("a.test", "b.test", "observer.test"), firstRound)
        assertEquals(setOf("a.test", "c.test", "observer.test"), secondRound)
    }

    @Test
    fun `主端点快速成功不触发次级`() {
        val calls = ArrayList<String>()
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2),
            hedgeDelayMs = 50,
            transport = { ep, raw, _ -> calls.add(ep.hostname); byteArrayOf(0x12) },
        )
        val r = client.post(ByteArray(12), 1000)
        assertArrayEquals(byteArrayOf(0x12), r)
        assertEquals(listOf("a.test"), calls) // 次级从未被调用
    }

    @Test
    fun `主端点超时则次级完成`() {
        val primaryGate = CountDownLatch(1)
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2),
            hedgeDelayMs = 60,
            transport = { ep, raw, _ ->
                if (ep.hostname == "a.test") {
                    primaryGate.await(5, TimeUnit.SECONDS) // 阻塞主端点
                    null
                } else {
                    byteArrayOf(0x12, 0x34)
                }
            },
        )
        val r = client.post(ByteArray(12), 2000)
        assertArrayEquals(byteArrayOf(0x12, 0x34), r)
        primaryGate.countDown() // 释放主端点线程
    }

    @Test
    fun `只有一个端点时不会在hedge窗口后提前取消`() {
        val client = WireDohClient(
            endpoints = listOf(ep1),
            hedgeDelayMs = 20,
            transport = { _, _, _ ->
                Thread.sleep(80)
                byteArrayOf(0x12, 0x34)
            },
        )
        assertArrayEquals(byteArrayOf(0x12, 0x34), client.post(ByteArray(12), 500))
        assertEquals(Health.HEALTHY, client.healthSnapshot()["a.test"])
    }

    @Test
    fun `全部失败返回null`() {
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2),
            hedgeDelayMs = 30,
            transport = { _, _, _ -> null },
        )
        assertNull(client.post(ByteArray(12), 300))
    }

    @Test
    fun `全部端点快速失败时不空等到总deadline`() {
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2),
            hedgeDelayMs = 100,
            transport = { _, _, _ -> null },
        )
        val started = System.nanoTime()
        assertNull(client.post(ByteArray(12), 2_000))
        val elapsedMs = (System.nanoTime() - started) / 1_000_000L
        assertTrue("fast failures took ${elapsedMs}ms", elapsedMs < 500)
    }

    @Test
    fun `截止前未返回的端点计入退避`() {
        val gate = CountDownLatch(1)
        val client = WireDohClient(
            endpoints = listOf(ep1),
            maxFailuresBeforeBackoff = 1,
            transport = { _, _, _ ->
                gate.await(5, TimeUnit.SECONDS)
                null
            },
        )
        try {
            assertNull(client.post(ByteArray(12), 80))
            assertEquals(Health.BACKOFF, client.healthSnapshot()["a.test"])
        } finally {
            gate.countDown()
        }
    }

    // ---------- 健康状态（§32） ----------

    @Test
    fun `连续失败进入BACKOFF并被跳过`() {
        var calls = 0
        var now = 0L
        val client = WireDohClient(
            endpoints = listOf(ep1),
            clock = { now },
            backoffMs = 60_000,
            maxFailuresBeforeBackoff = 2,
            transport = { _, _, _ -> calls++; null },
        )
        assertNull(client.post(ByteArray(12), 100))
        assertNull(client.post(ByteArray(12), 100))
        assertEquals(Health.BACKOFF, client.healthSnapshot()["a.test"])
        // 冷却期内直接跳过，不再请求
        assertNull(client.post(ByteArray(12), 100))
        assertEquals(2, calls)
        // 冷却过期后恢复尝试（状态回到 UNKNOWN）
        now = 61_000
        assertNull(client.post(ByteArray(12), 100))
        assertEquals(3, calls)
    }

    @Test
    fun `成功恢复HEALTHY并清零失败计数`() {
        var succeed = false
        var now = 0L
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2),
            clock = { now },
            backoffMs = 60_000,
            maxFailuresBeforeBackoff = 2,
            transport = { _, _, _ -> if (succeed) byteArrayOf(0x7F) else null },
        )
        // 连续两次查询：主端点各失败 2 次 → BACKOFF（次级同样失败）
        assertNull(client.post(ByteArray(12), 100))
        assertNull(client.post(ByteArray(12), 100))
        assertEquals(Health.BACKOFF, client.healthSnapshot()["a.test"])
        assertEquals(Health.BACKOFF, client.healthSnapshot()["b.test"])
        // 冷却期内直接跳过 → 不再请求（transport 不会被调用，直接 null）
        assertNull(client.post(ByteArray(12), 100))
        // 冷却过期后恢复尝试并成功 → HEALTHY
        now = 61_000
        succeed = true
        assertNotNull(client.post(ByteArray(12), 100))
        assertEquals(Health.HEALTHY, client.healthSnapshot()["a.test"])
        // 失败计数已清零：下一次失败只降到 DEGRADED，不直接 BACKOFF
        succeed = false
        assertNull(client.post(ByteArray(12), 100))
        assertEquals(Health.DEGRADED, client.healthSnapshot()["a.test"])
    }
}

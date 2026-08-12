package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.WireDohClient.Health
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
    fun `parseHttpResponse声明超长截取可用部分`() {
        val raw = ("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
            .toByteArray(Charsets.US_ASCII)
        val parsed = WireDohClient.parseHttpResponse(raw)
        assertArrayEquals("0123456789".toByteArray(Charsets.US_ASCII), parsed!!.second)
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
    }

    // ---------- Hedging（§33，注入假 transport） ----------

    private val ep1 = WireDohClient.WireEndpoint("1.1.1.1", "a.test")
    private val ep2 = WireDohClient.WireEndpoint("2.2.2.2", "b.test")

    @Test
    fun `主端点快速成功不触发次级`() {
        val calls = ArrayList<String>()
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2),
            hedgeDelayMs = 50,
            transportOverride = { ep, raw, _ -> calls.add(ep.hostname); byteArrayOf(0x12) },
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
            transportOverride = { ep, raw, _ ->
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
    fun `全部失败返回null`() {
        val client = WireDohClient(
            endpoints = listOf(ep1, ep2),
            hedgeDelayMs = 30,
            transportOverride = { _, _, _ -> null },
        )
        assertNull(client.post(ByteArray(12), 300))
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
            transportOverride = { _, _, _ -> calls++; null },
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
            transportOverride = { _, _, _ -> if (succeed) byteArrayOf(0x7F) else null },
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

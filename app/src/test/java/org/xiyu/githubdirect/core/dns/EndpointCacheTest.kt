package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.xiyu.githubdirect.core.data.ResolvedIps
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class EndpointCacheTest {

    private fun ips(vararg v4: String): ResolvedIps {
        val list = v4.map { IpAddresses.parseIpv4(it)!! }
        return ResolvedIps(v4 = list, v6 = emptyList())
    }

    @Test
    fun `TTL内命中缓存`() {
        val cache = EndpointCache(ttlMs = 60_000)
        val calls = AtomicInteger()
        val r = cache.resolve("github.com") {
            calls.incrementAndGet()
            ips("1.1.1.1")
        }
        assertEquals(ips("1.1.1.1").v4[0].size, r!!.v4[0].size)
        val r2 = cache.resolve("github.com") {
            calls.incrementAndGet()
            ips("2.2.2.2")
        }
        assertEquals(1, calls.get()) // 第二次走缓存
        assertEquals(1, r2!!.v4.size)
    }

    @Test
    fun `TTL过期后重新解析`() {
        val cache = EndpointCache(ttlMs = 50)
        val calls = AtomicInteger()
        cache.resolve("github.com") {
            calls.incrementAndGet()
            ips("1.1.1.1")
        }
        Thread.sleep(100)
        cache.resolve("github.com") {
            calls.incrementAndGet()
            ips("1.1.1.1")
        }
        assertEquals(2, calls.get())
    }

    @Test
    fun `single-flight并发只触发一次上游`() {
        val cache = EndpointCache()
        val calls = AtomicInteger()
        val threads = 20
        val executor = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(threads)
        val results = AtomicInteger()

        for (i in 0 until threads) {
            executor.submit {
                val r = cache.resolve("github.com") {
                    calls.incrementAndGet()
                    Thread.sleep(200) // 放大竞态窗口
                    ips("1.1.1.1")
                }
                if (r != null) results.incrementAndGet()
                latch.countDown()
            }
        }
        latch.await(30, TimeUnit.SECONDS)
        executor.shutdown()

        assertEquals("上游应只调用一次", 1, calls.get())
        assertEquals(threads, results.get()) // 全部拿到结果
    }

    @Test
    fun `stale窗口内上游失败返回旧值`() {
        val cache = EndpointCache(ttlMs = 50, staleMs = 1000)
        cache.resolve("github.com") { ips("1.1.1.1") }
        Thread.sleep(100) // TTL 过期，仍在 stale 窗口

        val stale = cache.resolve("github.com") { null }
        assertNotNull("stale 兜底应返回旧值", stale)
        assertEquals(1, stale!!.v4.size)
    }

    @Test
    fun `stale窗口外上游失败返回null`() {
        val cache = EndpointCache(ttlMs = 50, staleMs = 50)
        cache.resolve("github.com") { ips("1.1.1.1") }
        Thread.sleep(150) // TTL + stale 全部过期

        assertNull(cache.resolve("github.com") { null })
    }

    @Test
    fun `get只读不触发上游`() {
        val cache = EndpointCache()
        val calls = AtomicInteger()
        cache.resolve("github.com") {
            calls.incrementAndGet()
            ips("1.1.1.1")
        }
        assertEquals(1, calls.get())
        assertNotNull(cache.get("github.com"))
        assertNull(cache.get("unknown.com"))
        assertEquals(1, calls.get())
    }

    @Test
    fun `invalidate清掉缓存`() {
        val cache = EndpointCache()
        cache.resolve("github.com") { ips("1.1.1.1") }
        cache.invalidate("github.com")
        assertNull(cache.get("github.com"))
    }
}

package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class VirtualIpPoolTest {

    private fun ipv4(a: Int, b: Int, c: Int, d: Int): ByteArray =
        byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())

    @Test
    fun `并发分配唯一性且同域复用同vIP`() {
        val pool = VirtualIpPool()
        val threads = 10
        val perThread = 20 // 200 个不同域 < 245，不会触发驱逐
        val executor = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(threads)
        val vips = ConcurrentHashMap.newKeySet<Int>()
        val byDomain = ConcurrentHashMap<String, Int>()
        val errors = AtomicInteger()

        for (t in 0 until threads) {
            executor.submit {
                try {
                    for (i in 0 until perThread) {
                        val domain = "d$t-$i.example.com"
                        val vip = pool.allocate(domain, ipv4(1, 1, 1, 1), null)
                        assertTrue("vip 必须有效: $vip", vip > 0)
                        vips.add(vip)
                        byDomain[domain] = vip
                    }
                } catch (e: Throwable) {
                    errors.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }
        latch.await(30, TimeUnit.SECONDS)
        executor.shutdown()

        assertEquals(0, errors.get())
        assertEquals(200, vips.size) // 全唯一
        assertEquals(200, byDomain.size)

        // 同域再分配 → 同一 vIP
        assertEquals(byDomain["d0-0.example.com"],
            pool.allocate("d0-0.example.com", ipv4(2, 2, 2, 2), null))
    }

    @Test
    fun `容量245且全租约时新分配返回负一`() {
        val pool = VirtualIpPool()
        val vips = HashSet<Int>()
        for (i in 0 until 245) {
            val vip = pool.allocate("d$i.example.com", ipv4(1, 1, 1, 1), null)
            assertTrue(vip > 0)
            vips.add(vip)
        }
        assertEquals(245, vips.size) // 全部分配成功且唯一

        // 全部租约钉住 → 无可用 vIP
        for (vip in vips) pool.lease(vip)
        assertEquals(-1, pool.allocate("overflow.example.com", ipv4(1, 1, 1, 1), null))
        assertEquals(245, pool.snapshot().leased)
    }

    @Test
    fun `refs大于0的映射不可被驱逐且未过TTL不可驱逐`() {
        var t = 1_000_000L
        val pool = VirtualIpPool(clock = { t })
        // 租约钉住第一个域
        val pinned = pool.allocate("pinned.example.com", ipv4(1, 1, 1, 1), null)
        pool.lease(pinned)
        // 填满其余 244 个
        for (i in 0 until 244) {
            assertTrue(pool.allocate("d$i.example.com", ipv4(1, 1, 1, 1), null) > 0)
        }
        // 未过 DNS TTL：所有映射都太新，不可驱逐 → 池满返回 -1（TTL 安全驱逐语义）
        assertEquals(-1, pool.allocate("extra.example.com", ipv4(1, 1, 1, 1), null))
        // 越过 TTL：LRU 驱逐最旧的未租约映射（被钉住的不可驱逐）
        t += 301_000
        val extra = pool.allocate("extra.example.com", ipv4(1, 1, 1, 1), null)
        assertTrue(extra > 0)
        // pinned 映射仍然存活
        assertEquals("pinned.example.com", pool.lookupReal(pinned)!!.domain)
        pool.release(pinned)
    }

    @Test
    fun `满池逐出后同域重查获得新vIP且映射正确`() {
        var t = 1_000_000L
        val pool = VirtualIpPool(clock = { t })
        val first = pool.allocate("a.example.com", ipv4(1, 1, 1, 1), null)
        assertTrue(first > 0)

        // 填满其余 244 个 → 池满
        for (i in 0 until 244) {
            assertTrue(pool.allocate("f$i.example.com", ipv4(2, 2, 2, 2), null) > 0)
        }
        // 未过 TTL：a 太新不可驱逐 → -1，且 a 的映射仍在（客户端 DNS 缓存期内的稳定性）
        assertEquals(-1, pool.allocate("f244.example.com", ipv4(2, 2, 2, 2), null))
        assertEquals("a.example.com", pool.lookupReal(first)!!.domain)

        // 越过 TTL：最旧的 a 被驱逐，其 vIP 被 f244 接管
        t += 301_000
        assertTrue(pool.allocate("f244.example.com", ipv4(2, 2, 2, 2), null) > 0)
        assertEquals("f244.example.com", pool.lookupReal(first)!!.domain)

        // TTL 内同域重新分配：墓地 vIP 已被 f244 占用 → 驱逐另一旧映射后分配新 vIP，映射正确
        val again = pool.allocate("a.example.com", ipv4(3, 3, 3, 3), null)
        assertTrue("重新分配成功", again > 0)
        assertNotEquals("旧 vIP 已被 f244 占用", first, again)
        assertEquals("a.example.com", pool.lookupReal(again)!!.domain)
        assertEquals(245, pool.snapshot().active)
    }

    @Test
    fun `过期墓地中已被接管的vIP不得误分配且池保持一致`() {
        var t = 1_000_000L
        val pool = VirtualIpPool(dnsTtlSec = 1, clock = { t })
        val first = pool.allocate("a.example.com", ipv4(1, 1, 1, 1), null)
        for (i in 0 until 244) {
            pool.allocate("f$i.example.com", ipv4(2, 2, 2, 2), null)
        }
        // 越过 1s TTL：f244 驱逐 a（a 进墓地，其 vIP 已移交 f244）
        t += 1_100
        assertTrue(pool.allocate("f244.example.com", ipv4(2, 2, 2, 2), null) > 0)
        // 墓地过期且 a 的 vIP 仍被 f244 活跃占用：不得把活跃 vIP 误发给新域
        t += 1_100
        val g = pool.allocate("g.example.com", ipv4(4, 4, 4, 4), null)
        assertTrue("过期后仍可分配（经 LRU 驱逐路径）", g > 0)
        assertNotEquals("活跃 vIP 不得因过期墓地被误分配", first, g)
        assertEquals("g.example.com", pool.lookupReal(g)!!.domain)
        assertEquals("f244.example.com", pool.lookupReal(first)!!.domain) // first 仍归 f244
        assertEquals(245, pool.snapshot().active)
        assertEquals(1, pool.snapshot().graveyard) // a 的过期墓地被清除，仅剩新驱逐项
    }

    @Test
    fun `lease和release配对refs归零`() {
        val pool = VirtualIpPool()
        val vip = pool.allocate("a.example.com", ipv4(1, 1, 1, 1), null)
        assertEquals(1, pool.lease(vip))
        assertEquals(2, pool.lease(vip))
        assertEquals(1, pool.release(vip))
        assertEquals(0, pool.release(vip))
        assertEquals(0, pool.release(vip)) // 负归零
        assertEquals(0, pool.snapshot().leased)
    }

    @Test
    fun `isVirtualIp只认池内网段`() {
        val pool = VirtualIpPool()
        assertTrue(pool.isVirtualIp(ipv4(10, 0, 0, 10)))
        assertTrue(pool.isVirtualIp(ipv4(10, 0, 0, 254)))
        assertTrue(!pool.isVirtualIp(ipv4(10, 0, 0, 2)))  // 2 = fake DNS
        assertTrue(!pool.isVirtualIp(ipv4(10, 0, 0, 1)))  // 1 = VPN 自身
        assertTrue(!pool.isVirtualIp(ipv4(10, 0, 0, 255))) // 广播
        assertTrue(!pool.isVirtualIp(ipv4(10, 0, 1, 10))) // 网段外
        assertTrue(!pool.isVirtualIp(ipv4(8, 8, 8, 8)))
    }

    @Test
    fun `vIP分配范围为10到254`() {
        val pool = VirtualIpPool()
        val vips = HashSet<Int>()
        for (i in 0 until 245) {
            vips.add(pool.allocate("d$i.example.com", ipv4(1, 1, 1, 1), null))
        }
        for (vip in vips) {
            val host = vip and 0xFF
            assertTrue("host 范围: $host", host in 10..254)
        }
    }
}

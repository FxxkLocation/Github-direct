package org.xiyu.githubdirect.core.net

import org.xiyu.githubdirect.core.dns.IpAddresses
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * 虚拟 IP 池（10.0.0.0/24，10..254 = 245 个）。
 *
 * 语义（设计 §3.2-3.4）：
 * - free 队列 + active（vIP→映射）+ byDomain（域→vIP）+ graveyard（域→(vIP, 过期时间)）
 * - 同域复用同 vIP（客户端 DNS 缓存期内永远有效）
 * - LRU 驱逐仅限 refs==0（无活跃会话）；驱逐入墓地 TTL 后回收
 * - 分配前必须已取得真实 IP（vIP 绝不裸发——由调用方保证）
 *
 * 与设计文档差异（实现细节）：graveyard 值从 Long（过期时间）改为
 * GraveEntry(vip, expireAt)——同域复用需要知道原 vIP，仅存过期时间无法实现
 * "TTL 内同域复用同 vIP" 的不变式。
 *
 * 并发：active/byDomain/graveyard 为 ConcurrentHashMap；free 为并发队列；
 * allocate 全程在 allocLock 短临界区（无网络 I/O，调用方为 DNS 工作线程，最多 4 并发）；
 * lookup/lease/release 无锁。
 */
class VirtualIpPool(
    private val base: Int = ipInt(10, 0, 0, 0),
    private val startHost: Int = 10,
    private val endHost: Int = 254,
    private val dnsTtlSec: Int = 300,
    /** 时钟注入（测试用假时钟；生产用系统时钟）。 */
    private val clock: () -> Long = System::currentTimeMillis,
) {

    class Mapping(
        val domain: String,
        @Volatile var v4: ByteArray,
        @Volatile var v6: ByteArray?,
        val refs: AtomicInteger = AtomicInteger(0),
        @Volatile var lastUsed: Long,
        /** 分配序号：lastUsed 相同时按此稳定排序（LRU 确定性驱逐，避免 ms 级时间戳并发平局）。 */
        val allocSeq: Long = 0,
        /** 分配时间戳：映射存活超过 DNS TTL 后客户端的 DNS 缓存已过期，此时才允许换域复用该 vIP。 */
        val createdAt: Long = 0,
    )

    class GraveEntry internal constructor(val vip: Int, val expireAt: Long)

    data class PoolStats(
        val active: Int,
        val free: Int,
        val graveyard: Int,
        val leased: Int,
    )

    private val free = ConcurrentLinkedQueue<Int>()
    private val active = ConcurrentHashMap<Int, Mapping>()
    private val byDomain = ConcurrentHashMap<String, Int>()
    private val graveyard = ConcurrentHashMap<String, GraveEntry>()
    private val allocLock = Any()

    init {
        for (host in startHost..endHost) {
            free.add(base + host)
        }
    }

    /**
     * 分配（域 → vIP）。-1 = 池满（全被会话租约钉住）。
     * domain 必须已 normalize；v4 为真实 IPv4（必填），v6 可选。
     */
    fun allocate(domain: String, v4: ByteArray, v6: ByteArray?): Int {
        val now = clock()

        synchronized(allocLock) {
            // 同域已映射 → 原地刷新 IP，vIP 不变（客户端缓存仍有效）
            byDomain[domain]?.let { vip ->
                active[vip]?.let { m ->
                    m.v4 = v4
                    m.v6 = v6
                    m.lastUsed = now
                    return vip
                }
            }

            // 墓地复用：同域专属（TTL 内客户端旧 vIP 仍有效）
            val grave = graveyard[domain]
            if (grave != null) {
                if (grave.expireAt > now) {
                    val mapping = Mapping(domain, v4, v6, AtomicInteger(0), now, nextAllocSeq(), now)
                    if (active.putIfAbsent(grave.vip, mapping) == null) {
                        byDomain[domain] = grave.vip
                        graveyard.remove(domain)
                        return grave.vip
                    }
                    // 竞态：vIP 已被占用，落入下方 free 分配
                } else {
                    graveyard.remove(domain)
                    // vIP 可能已被他域接管（驱逐时直接移交）→ 活跃则不回收
                    if (!active.containsKey(grave.vip)) free.offer(grave.vip)
                }
            }

            // free 队列
            free.poll()?.let { vip ->
                val mapping = Mapping(domain, v4, v6, AtomicInteger(0), now, nextAllocSeq(), now)
                if (active.putIfAbsent(vip, mapping) == null) {
                    byDomain[domain] = vip
                    return vip
                }
                free.offer(vip) // 竞态：被其它线程占用，放回
            }

            // 清扫过期墓地（仅回收未被接管的 vIP；驱逐时 vIP 已直接移交新域）
            val it = graveyard.entries.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (e.value.expireAt <= now) {
                    it.remove()
                    if (!active.containsKey(e.value.vip)) free.offer(e.value.vip)
                }
            }
            free.poll()?.let { vip ->
                val mapping = Mapping(domain, v4, v6, AtomicInteger(0), now, nextAllocSeq(), now)
                if (active.putIfAbsent(vip, mapping) == null) {
                    byDomain[domain] = vip
                    return vip
                }
                free.offer(vip)
            }

            // LRU 驱逐（仅限 refs==0 且映射存活已超过 DNS TTL——客户端 DNS 缓存已过期，
            // 换域复用不会让旧域客户端把流量发错目标；驱逐入墓地，TTL 内同域可复用）
            // lastUsed 相同时按 allocSeq 稳定排序（确定性驱逐）
            val minAgeMs = dnsTtlSec * 1000L
            var victimVip = -1
            var victim: Mapping? = null
            for ((vip, m) in active) {
                if (m.refs.get() == 0 && now - m.createdAt >= minAgeMs &&
                    (victim == null ||
                        m.lastUsed < victim!!.lastUsed ||
                        (m.lastUsed == victim!!.lastUsed && m.allocSeq < victim!!.allocSeq))
                ) {
                    victim = m
                    victimVip = vip
                }
            }
            if (victim != null) {
                active.remove(victimVip)
                byDomain.remove(victim.domain)
                graveyard[victim.domain] = GraveEntry(victimVip, now + minAgeMs)
                val mapping = Mapping(domain, v4, v6, AtomicInteger(0), now, nextAllocSeq(), now)
                active[victimVip] = mapping
                byDomain[domain] = victimVip
                return victimVip
            }
        }
        return -1 // 池满且无 TTL 过期的可回收映射（正确性优先于容量）
    }

    /** 域名 → vIP（无锁）。 */
    fun lookupVip(domain: String): Int? = byDomain[domain]

    /** vIP → 映射（无锁）。 */
    fun lookupReal(vip: Int): Mapping? = active[vip]

    /** 判断字节数组是否为池内 vIP（网段 + 主机范围）。 */
    fun isVirtualIp(addr: ByteArray): Boolean {
        if (addr.size != 4) return false
        val ip = IpAddresses.ipToInt(addr)
        val host = ip and 0xFF
        val mask = 0xFFFFFF00.toInt()
        return (ip and mask) == (base and mask) && host in startHost..endHost
    }

    /** 会话建立时 refs++（TcpRelay 租约钩子）。 */
    fun lease(vip: Int): Int = active[vip]?.refs?.incrementAndGet() ?: 0

    /** 会话结束时 refs--。 */
    fun release(vip: Int): Int {
        val m = active[vip] ?: return 0
        val v = m.refs.decrementAndGet()
        if (v < 0) {
            m.refs.set(0)
            return 0 // 钳制后返回 0（双 release 幂等）
        }
        return v
    }

    fun snapshot(): PoolStats {
        var leased = 0
        for (m in active.values) {
            if (m.refs.get() > 0) leased++
        }
        return PoolStats(active = active.size, free = free.size, graveyard = graveyard.size, leased = leased)
    }

    companion object {
        private val allocSeqCounter = AtomicLong(0)

        fun ipInt(a: Int, b: Int, c: Int, d: Int): Int =
            (a shl 24) or (b shl 16) or (c shl 8) or d

        fun nextAllocSeq(): Long = allocSeqCounter.incrementAndGet()
    }
}

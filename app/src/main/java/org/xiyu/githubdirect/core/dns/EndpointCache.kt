package org.xiyu.githubdirect.core.dns

import org.xiyu.githubdirect.core.data.ResolvedIps
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * 解析结果缓存（从原 DnsCache 迁移 + TTL 参数化 + per-domain single-flight 去重）。
 *
 * - single-flight：N 并发同域查询 → 1 次上游请求，其余 join 同一 CompletableFuture
 * - stale 窗口：TTL 过期后、staleMs 内返回旧值兜底（上游失败时）
 * - 完成即从 inflight 移除
 */
class EndpointCache(
    private val ttlMs: Long = 10 * 60 * 1000L, // 10 分钟
    private val staleMs: Long = 0,
    private val maxSize: Int = 128,
) {

    private class Entry(val ips: ResolvedIps, val expireAt: Long, val staleUntil: Long)

    private val cache = ConcurrentHashMap<String, Entry>()
    private val inflight = ConcurrentHashMap<String, CompletableFuture<ResolvedIps>>()

    /** 命中且未过期 → 返回；否则 null（不触发上游）。 */
    fun get(domain: String): ResolvedIps? {
        val now = System.currentTimeMillis()
        val entry = cache[domain] ?: return null
        if (now < entry.expireAt) return entry.ips
        return null
    }

    /**
     * single-flight resolve：缓存命中（含 stale 兜底）→ 返回；否则恰一次调用 fetch。
     * fetch 失败且存在 stale 值 → 返回 stale；否则 null。
     */
    fun resolve(domain: String, fetch: (String) -> ResolvedIps?): ResolvedIps? {
        val now = System.currentTimeMillis()
        var staleResult: ResolvedIps? = null

        cache[domain]?.let { entry ->
            if (now < entry.expireAt) return entry.ips
            if (staleMs > 0 && now < entry.staleUntil) staleResult = entry.ips
        }

        // single-flight：重复请求 join 同一 future
        val future = CompletableFuture<ResolvedIps>()
        val existing = inflight.putIfAbsent(domain, future)
        if (existing != null) {
            return try {
                existing.get(15, TimeUnit.SECONDS)
            } catch (_: Exception) {
                staleResult
            }
        }

        var result: ResolvedIps? = null
        try {
            result = fetch(domain)
            if (result != null) {
                val expireAt = now + ttlMs
                if (cache.size >= maxSize && !evictExpired()) {
                    // 无过期条目 → 驱逐最近将过期者（近似 LRU，防止无界增长）
                    cache.entries.minByOrNull { it.value.expireAt }?.let { cache.remove(it.key) }
                }
                cache[domain] = Entry(result, expireAt, expireAt + staleMs)
                future.complete(result)
            } else {
                future.completeExceptionally(java.util.NoSuchElementException("resolve failed: $domain"))
            }
        } catch (t: Throwable) {
            future.completeExceptionally(t)
        } finally {
            inflight.remove(domain)
        }
        return result ?: staleResult
    }

    fun invalidate(domain: String) {
        cache.remove(domain)
    }

    fun clear() {
        cache.clear()
        inflight.clear()
    }

    fun size(): Int = cache.size

    /** 移除全部过期条目；返回是否有条目被移除。 */
    private fun evictExpired(): Boolean {
        val now = System.currentTimeMillis()
        var removed = false
        val it = cache.entries.iterator()
        while (it.hasNext()) {
            if (now >= it.next().value.expireAt) {
                it.remove()
                removed = true
            }
        }
        return removed
    }
}

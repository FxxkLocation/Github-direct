package org.xiyu.githubdirect.core.net

import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.rules.DnsNames
import java.util.concurrent.ConcurrentHashMap

/**
 * relay 域真实 IP 表（provider 同步数据，copy-on-write）。
 * @Volatile Map 整体替换，读无锁；修复原 HashMap 并发写读竞争。
 */
class RelayIpTable {

    private data class EphemeralEntry(
        val addresses: List<String>,
        val expiresAt: Long,
    )

    @Volatile
    private var table: Map<String, List<String>> = emptyMap()

    /** 严格 DoH 的短 TTL 精确域结果；不持久化、不生成通配键，也不等同于已探测候选。 */
    private val ephemeral = ConcurrentHashMap<String, EphemeralEntry>()

    /** 原子整体替换（调用方传入不可变 map）。 */
    fun update(hosts: Map<String, List<String>>) {
        table = hosts
    }

    /** 精确键优先；`*.example.com` 按最长标签后缀匹配，且不匹配裸 apex。 */
    fun lookup(domain: String, now: Long = System.currentTimeMillis()): List<String>? {
        val normalized = DnsNames.normalize(domain) ?: return null
        val fresh = ephemeral[normalized]?.let { entry ->
            if (now < entry.expiresAt) {
                entry.addresses
            } else {
                ephemeral.remove(normalized, entry)
                null
            }
        }.orEmpty()
        val stable = lookupStable(normalized).orEmpty()
        if (fresh.isEmpty()) return stable.takeIf { it.isNotEmpty() }
        if (stable.isEmpty()) return fresh
        return (fresh + stable).distinct().take(MAX_ADDRESSES_PER_ENTRY)
    }

    private fun lookupStable(domain: String): List<String>? {
        table[domain]?.let { return it }
        var dot = domain.indexOf('.')
        while (dot >= 0 && dot < domain.lastIndex) {
            table["*.${domain.substring(dot + 1)}"]?.let { return it }
            dot = domain.indexOf('.', dot + 1)
        }
        return null
    }

    /** 查询第一个 IPv4 候选；无返回 null。 */
    fun firstIpv4(domain: String): String? {
        lookup(domain)?.forEach { ip ->
            if (ip.contains(".")) return ip
        }
        return null
    }

    fun snapshot(): Map<String, List<String>> = table

    fun size(): Int = table.size

    /**
     * 记录一次严格解析的精确域结果。这里只提供同一连接的地址竞速线索；系统链和原始主机名
     * 校验仍由目标客户端执行，provider 的持久候选仍必须经过主动 TLS 探测。
     */
    @Synchronized
    fun observeResolution(
        rawDomain: String,
        addresses: Collection<String>,
        ttlMs: Long = DEFAULT_EPHEMERAL_TTL_MS,
        now: Long = System.currentTimeMillis(),
    ) {
        val domain = DnsNames.normalize(rawDomain) ?: return
        val sanitized = addresses.asSequence()
            .mapNotNull { address ->
                val raw = IpAddresses.parseIpAddress(address) ?: return@mapNotNull null
                if (IpAddresses.isBogonOrPoisoned(raw)) return@mapNotNull null
                if (raw.size == 4) IpAddresses.ipv4ToString(raw) else IpAddresses.ipv6ToString(raw)
            }
            .distinct()
            .take(MAX_ADDRESSES_PER_ENTRY)
            .toList()
        if (sanitized.isEmpty()) return
        val boundedTtl = ttlMs.coerceIn(MIN_EPHEMERAL_TTL_MS, MAX_EPHEMERAL_TTL_MS)
        ephemeral[domain] = EphemeralEntry(sanitized, now + boundedTtl)
        pruneEphemeral(now)
    }

    @Synchronized
    private fun pruneEphemeral(now: Long) {
        ephemeral.entries.removeIf { now >= it.value.expiresAt }
        if (ephemeral.size <= MAX_EPHEMERAL_DOMAINS) return
        ephemeral.entries.sortedBy { it.value.expiresAt }
            .take(ephemeral.size - MAX_EPHEMERAL_DOMAINS)
            .forEach { ephemeral.remove(it.key, it.value) }
    }

    internal fun ephemeralSize(): Int = ephemeral.size

    companion object {
        private const val MAX_EPHEMERAL_DOMAINS = 128
        private const val MAX_ADDRESSES_PER_ENTRY = 8
        private const val MIN_EPHEMERAL_TTL_MS = 30_000L
        private const val DEFAULT_EPHEMERAL_TTL_MS = 5 * 60_000L
        private const val MAX_EPHEMERAL_TTL_MS = 10 * 60_000L
    }
}

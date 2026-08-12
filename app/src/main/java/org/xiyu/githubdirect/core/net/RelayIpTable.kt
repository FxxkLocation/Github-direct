package org.xiyu.githubdirect.core.net

/**
 * relay 域真实 IP 表（provider 同步数据，copy-on-write）。
 * @Volatile Map 整体替换，读无锁；修复原 HashMap 并发写读竞争。
 */
class RelayIpTable {

    @Volatile
    private var table: Map<String, List<String>> = emptyMap()

    /** 原子整体替换（调用方传入不可变 map）。 */
    fun update(hosts: Map<String, List<String>>) {
        table = hosts
    }

    /** 精确查询（domain 已 normalize）；未命中返回 null。 */
    fun lookup(domain: String): List<String>? = table[domain]

    /** 查询第一个 IPv4 候选；无返回 null。 */
    fun firstIpv4(domain: String): String? {
        table[domain]?.forEach { ip ->
            if (ip.contains(".")) return ip
        }
        return null
    }

    fun snapshot(): Map<String, List<String>> = table

    fun size(): Int = table.size
}

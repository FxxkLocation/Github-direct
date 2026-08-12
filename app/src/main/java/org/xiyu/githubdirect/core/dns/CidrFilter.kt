package org.xiyu.githubdirect.core.dns

/**
 * CIDR 白名单过滤器（从原 DohResolver 的 GitHub 网段过滤逻辑参数化而来）。
 *
 * - v4Ranges: (网络地址 long, 掩码位数) 列表
 * - v6Prefixes: IPv6 前缀 CIDR 字符串（如 "2606:50c0::/32"），parse 时编译为字节前缀
 */
class CidrFilter(
    private val v4Ranges: List<Pair<Long, Int>>,
    private val v6Prefixes: List<Pair<ByteArray, Int>>,
) {

    fun allowsIpv4(addr: ByteArray): Boolean {
        if (addr.size != 4) return false
        val ip = ((addr[0].toLong() and 0xFF) shl 24) or
                ((addr[1].toLong() and 0xFF) shl 16) or
                ((addr[2].toLong() and 0xFF) shl 8) or
                (addr[3].toLong() and 0xFF)
        for ((network, bits) in v4Ranges) {
            val mask = if (bits == 0) 0L else (0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL
            if ((ip and mask) == (network and mask)) return true
        }
        return false
    }

    fun allowsIpv6(addr: ByteArray): Boolean {
        if (addr.size != 16) return false
        for ((prefix, bits) in v6Prefixes) {
            if (matchesV6Prefix(addr, prefix, bits)) return true
        }
        return false
    }

    private fun matchesV6Prefix(addr: ByteArray, prefix: ByteArray, bits: Int): Boolean {
        val fullBytes = bits / 8
        for (i in 0 until fullBytes) {
            if (addr[i] != prefix[i]) return false
        }
        val rest = bits % 8
        if (rest > 0) {
            val mask = (0xFF shl (8 - rest)) and 0xFF
            if ((addr[fullBytes].toInt() and mask) != (prefix[fullBytes].toInt() and mask)) return false
        }
        return true
    }

    val isEmpty: Boolean get() = v4Ranges.isEmpty() && v6Prefixes.isEmpty()

    companion object {
        /**
         * 从 CIDR 字符串列表编译（规则数据加载时调用一次）。
         * v4: "140.82.112.0/20"；v6: "2606:50c0::/32"。非法条目跳过。
         */
        fun parse(v4Cidrs: List<String>, v6Cidrs: List<String>): CidrFilter {
            val v4 = ArrayList<Pair<Long, Int>>(v4Cidrs.size)
            for (cidr in v4Cidrs) {
                val (network, bits) = parseV4Cidr(cidr) ?: continue
                v4.add(network to bits)
            }
            val v6 = ArrayList<Pair<ByteArray, Int>>(v6Cidrs.size)
            for (cidr in v6Cidrs) {
                val (prefix, bits) = parseV6Cidr(cidr) ?: continue
                v6.add(prefix to bits)
            }
            return CidrFilter(v4, v6)
        }

        fun parseV4Cidr(cidr: String): Pair<Long, Int>? {
            val parts = cidr.trim().split("/", limit = 2)
            val addr = IpAddresses.parseIpv4(parts[0]) ?: return null
            val bits = if (parts.size == 2) parts[1].toIntOrNull() ?: return null else 32
            if (bits < 0 || bits > 32) return null
            val ip = ((addr[0].toLong() and 0xFF) shl 24) or
                    ((addr[1].toLong() and 0xFF) shl 16) or
                    ((addr[2].toLong() and 0xFF) shl 8) or
                    (addr[3].toLong() and 0xFF)
            val mask = if (bits == 0) 0L else (0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL
            return (ip and mask) to bits
        }

        fun parseV6Cidr(cidr: String): Pair<ByteArray, Int>? {
            val parts = cidr.trim().split("/", limit = 2)
            val addr = IpAddresses.parseIpv6(parts[0]) ?: return null
            val bits = if (parts.size == 2) parts[1].toIntOrNull() ?: return null else 128
            if (bits < 0 || bits > 128) return null
            // 归一化前缀：不足 bits 的字节补零，多出的字节截断
            val fullBytes = (bits + 7) / 8
            val prefix = ByteArray(fullBytes)
            System.arraycopy(addr, 0, prefix, 0, fullBytes)
            if (bits % 8 != 0) {
                val mask = (0xFF shl (8 - bits % 8)) and 0xFF
                prefix[fullBytes - 1] = (prefix[fullBytes - 1].toInt() and mask).toByte()
            }
            return prefix to bits
        }
    }
}

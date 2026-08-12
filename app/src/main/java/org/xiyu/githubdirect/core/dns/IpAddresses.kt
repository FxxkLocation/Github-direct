package org.xiyu.githubdirect.core.dns

/**
 * IP 字符串 → 字节数组的纯函数（从原 DohResolver 迁移）。
 * 不使用 InetAddress.getByName() 以避免递归 DNS 调用。
 */
object IpAddresses {

    /** 解析 "1.2.3.4" → 4 字节；非法返回 null。 */
    @JvmStatic
    fun parseIpv4(ip: String?): ByteArray? {
        if (ip == null || ip.isEmpty()) return null
        val parts = ip.split(".")
        if (parts.size != 4) return null
        val addr = ByteArray(4)
        for (i in 0 until 4) {
            val part = parts[i]
            if (part.isEmpty() || part.length > 3) return null
            val v = part.toIntOrNull() ?: return null
            if (v < 0 || v > 255) return null
            addr[i] = v.toByte()
        }
        return addr
    }

    /** 解析 IPv6（支持 :: 缩写与内嵌 IPv4 尾段）→ 16 字节；非法返回 null。 */
    @JvmStatic
    fun parseIpv6(ip: String?): ByteArray? {
        if (ip == null || ip.isEmpty()) return null

        var s = ip
        // 内嵌 IPv4：把尾段转为两个 16 位组
        if (s.contains(".")) {
            val idx = s.lastIndexOf(':')
            if (idx < 0) return null
            val v4 = parseIpv4(s.substring(idx + 1)) ?: return null
            s = s.substring(0, idx) + ":" +
                    String.format("%02x%02x", v4[0].toInt() and 0xFF, v4[1].toInt() and 0xFF) + ":" +
                    String.format("%02x%02x", v4[2].toInt() and 0xFF, v4[3].toInt() and 0xFF)
        }

        val halves = s.split("::", limit = 2)
        if (halves.size > 2) return null

        val left = if (halves[0].isEmpty()) emptyList() else halves[0].split(":")
        val right = if (halves.size == 2 && halves[1].isNotEmpty()) halves[1].split(":") else emptyList()

        val totalGroups = left.size + right.size
        if (halves.size == 1 && totalGroups != 8) return null
        if (halves.size == 2 && totalGroups > 7) return null

        val missingGroups = 8 - totalGroups
        val addr = ByteArray(16)
        var idx = 0

        for (part in left) {
            val v = parseHexGroup(part) ?: return null
            addr[idx++] = (v shr 8).toByte()
            addr[idx++] = v.toByte()
        }
        for (i in 0 until missingGroups) {
            addr[idx++] = 0
            addr[idx++] = 0
        }
        for (part in right) {
            val v = parseHexGroup(part) ?: return null
            addr[idx++] = (v shr 8).toByte()
            addr[idx++] = v.toByte()
        }
        return addr
    }

    private fun parseHexGroup(part: String): Int? {
        if (part.isEmpty() || part.length > 4) return null
        return part.toIntOrNull(16)
    }

    /** 解析 "1.2.3.4" 或 IPv6 → 字节数组；非法返回 null。 */
    @JvmStatic
    fun parseIpAddress(ip: String?): ByteArray? {
        if (ip == null || ip.isEmpty()) return null
        return if (ip.contains(":")) parseIpv6(ip) else parseIpv4(ip)
    }

    /** 4 字节数组 → 十进制点分字符串。 */
    @JvmStatic
    fun ipv4ToString(addr: ByteArray): String =
        (addr[0].toInt() and 0xFF).toString() + "." +
                (addr[1].toInt() and 0xFF) + "." +
                (addr[2].toInt() and 0xFF) + "." +
                (addr[3].toInt() and 0xFF)

    /** 16 字节数组 → 标准 IPv6 字符串（冒号分隔，不缩写）。 */
    @JvmStatic
    fun ipv6ToString(addr: ByteArray): String {
        if (addr.size != 16) return ipv4ToString(addr)
        val sb = StringBuilder()
        for (i in 0 until 8) {
            if (i > 0) sb.append(':')
            val hi = addr[i * 2].toInt() and 0xFF
            val lo = addr[i * 2 + 1].toInt() and 0xFF
            sb.append(String.format("%x", (hi shl 8) or lo))
        }
        return sb.toString()
    }

    /** 字节数组 → 整数（v4 用）。 */
    @JvmStatic
    fun ipToInt(addr: ByteArray): Int {
        return ((addr[0].toInt() and 0xFF) shl 24) or
                ((addr[1].toInt() and 0xFF) shl 16) or
                ((addr[2].toInt() and 0xFF) shl 8) or
                (addr[3].toInt() and 0xFF)
    }

    /** 整数 → 4 字节数组（大端）。 */
    @JvmStatic
    fun intToIpv4(value: Int): ByteArray {
        return byteArrayOf(
            ((value shr 24) and 0xFF).toByte(),
            ((value shr 16) and 0xFF).toByte(),
            ((value shr 8) and 0xFF).toByte(),
            (value and 0xFF).toByte(),
        )
    }
}

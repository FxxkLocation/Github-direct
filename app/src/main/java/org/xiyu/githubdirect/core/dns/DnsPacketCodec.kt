package org.xiyu.githubdirect.core.dns

/**
 * DNS/IP 协议层纯函数（从原 DnsVpnService.java:474-655 迁移，无 Android 依赖）。
 * 全部为纯 byte[] 操作。
 */
object DnsPacketCodec {

    /**
     * 解析 DNS 查询（UDP payload，含 12 字节头）。
     * 结构非法（<12 字节 / 域名越界 / 截断）返回 null。
     */
    fun parseDnsQuery(dns: ByteArray): DnsQuestion? {
        if (dns.size < 12) return null
        val domain = parseDnsDomain(dns)
        val qtype = getQueryType(dns)
        val questionEnd = getQuestionEnd(dns)
        if (questionEnd > dns.size) return null
        if (questionEnd < 13) return null
        return DnsQuestion(domain = domain, qtype = qtype, questionEnd = questionEnd, query = dns)
    }

    /**
     * 从 DNS 查询中解析域名。
     * DNS 域名格式: [长度][标签][长度][标签]...[0]
     * 例如: \x06github\x03com\x00 = github.com
     * 仅支持无压缩指针的问题名（查询包正常无指针）。
     */
    fun parseDnsDomain(dns: ByteArray): String? {
        if (dns.size < 13) return null

        val sb = StringBuilder()
        var pos = 12 // 跳过 DNS 头 (12 bytes)

        while (pos < dns.size) {
            val labelLen = dns[pos].toInt() and 0xFF
            if (labelLen == 0) break

            // 指针 (0xC0xx) — 查询包中不应出现；遇到即终止解析
            if ((labelLen and 0xC0) == 0xC0) break

            if (pos + 1 + labelLen > dns.size) return null
            if (sb.isNotEmpty()) sb.append('.')

            for (i in 0 until labelLen) {
                sb.append((dns[pos + 1 + i].toInt() and 0xFF).toChar())
            }
            pos += 1 + labelLen
        }

        return if (sb.isNotEmpty()) sb.toString().lowercase() else null
    }

    /**
     * 获取 DNS 查询类型 (QTYPE)。位于 Question Section 的域名之后。
     */
    fun getQueryType(dns: ByteArray): Int {
        val pos = skipQuestionName(dns) ?: return 0
        if (pos + 2 <= dns.size) {
            return readU16(dns, pos)
        }
        return 0
    }

    /**
     * 获取 Question Section 的结束位置（含 QTYPE+QCLASS）。
     */
    fun getQuestionEnd(dns: ByteArray): Int {
        val pos = skipQuestionName(dns) ?: return 12
        return pos + 4
    }

    private fun skipQuestionName(dns: ByteArray): Int? {
        var pos = 12
        while (pos < dns.size) {
            val labelLen = dns[pos].toInt() and 0xFF
            if (labelLen == 0) {
                return pos + 1
            }
            if ((labelLen and 0xC0) == 0xC0) {
                return pos + 2
            }
            pos += 1 + labelLen
        }
        return null
    }

    /**
     * 构造 DNS 响应包（仅包含 A/AAAA 记录），NOERROR。
     * addrs 中与 queryType 类型不符的地址被跳过；无匹配地址返回 null（调用方自行决定）。
     */
    fun buildDnsResponse(
        query: ByteArray,
        questionEnd: Int,
        addrs: List<ByteArray>,
        queryType: Int,
        ttlSec: Int = 300,
    ): ByteArray? {
        if (questionEnd > query.size) return null

        // 筛选匹配查询类型的地址
        val matched = addrs.filter { addr ->
            (queryType == 1 && addr.size == 4) || (queryType == 28 && addr.size == 16)
        }
        if (matched.isEmpty()) return null

        val answerSize = matched.sumOf { if (it.size == 4) 16 else 28 } // 2+2+2+4+2+len
        val response = ByteArray(questionEnd + answerSize)

        // 复制 DNS 头和 Question Section
        System.arraycopy(query, 0, response, 0, questionEnd)

        // 设置响应标志: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()

        // ANCOUNT
        response[6] = ((matched.size shr 8) and 0xFF).toByte()
        response[7] = (matched.size and 0xFF).toByte()

        // NSCOUNT = 0, ARCOUNT = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0

        // 写入 Answer Records
        var pos = questionEnd
        for (addr in matched) {
            // Name: 指针到 offset 12（域名在 Question Section）
            response[pos++] = 0xC0.toByte()
            response[pos++] = 0x0C

            // Type
            writeU16(response, pos, if (addr.size == 4) 1 else 28)
            pos += 2

            // Class: IN (1)
            writeU16(response, pos, 1)
            pos += 2

            // TTL
            writeU32(response, pos, ttlSec)
            pos += 4

            // RDLENGTH
            writeU16(response, pos, addr.size)
            pos += 2

            // RDATA: IP
            System.arraycopy(addr, 0, response, pos, addr.size)
            pos += addr.size
        }

        return response
    }

    /** NOERROR 空应答（名字存在但无此类型记录；NODATA，绝不用 NXDOMAIN）。 */
    fun buildEmptyResponse(query: ByteArray, questionEnd: Int): ByteArray {
        val response = ByteArray(questionEnd)
        System.arraycopy(query, 0, response, 0, questionEnd)
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[6] = 0
        response[7] = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        return response
    }

    /** NODATA = NOERROR + 空 Answer（AAAA 抑制语义）。 */
    fun buildNodataResponse(query: ByteArray, questionEnd: Int = getQuestionEnd(query)): ByteArray {
        val end = if (questionEnd <= query.size) questionEnd else query.size.coerceAtLeast(12)
        return buildEmptyResponse(query, end)
    }

    /** SERVFAIL 应答。 */
    fun buildServFailResponse(query: ByteArray): ByteArray {
        var questionEnd = getQuestionEnd(query)
        if (questionEnd > query.size) questionEnd = minOf(query.size, 12)
        val response = ByteArray(questionEnd)
        System.arraycopy(query, 0, response, 0, minOf(query.size, questionEnd))
        if (response.size >= 4) {
            response[2] = 0x81.toByte()
            response[3] = 0x82.toByte() // RCODE=2 (SERVFAIL)
        }
        return response
    }

    /** NXDOMAIN 应答（RCODE=3）。 */
    fun buildNxdomainResponse(query: ByteArray): ByteArray {
        var questionEnd = getQuestionEnd(query)
        if (questionEnd > query.size) questionEnd = minOf(query.size, 12)
        val response = ByteArray(questionEnd)
        System.arraycopy(query, 0, response, 0, minOf(query.size, questionEnd))
        if (response.size >= 4) {
            response[2] = 0x81.toByte()
            response[3] = 0x83.toByte() // RCODE=3 (NXDOMAIN)
        }
        return response
    }

    /**
     * 将 DNS 响应封装为 IPv4 + UDP 数据包，交换原始查询包的源/目标地址和端口。
     */
    fun constructIpPacket(queryPacket: ByteArray, ipHeaderLen: Int, dnsResponse: ByteArray): ByteArray {
        val udpLen = 8 + dnsResponse.size
        val totalLen = 20 + udpLen // 标准 20 字节 IPv4 头

        val response = ByteArray(totalLen)

        // ---- IPv4 Header ----
        response[0] = 0x45 // Version=4, IHL=5
        response[1] = 0 // DSCP/ECN
        writeU16(response, 2, totalLen)
        writeU16(response, 4, 0) // Identification
        writeU16(response, 6, 0x4000) // Flags: Don't Fragment
        response[8] = 64 // TTL
        response[9] = 17 // Protocol: UDP

        // 源 IP = 原始查询的目标 IP (fake DNS)
        System.arraycopy(queryPacket, 16, response, 12, 4)
        // 目标 IP = 原始查询的源 IP (client)
        System.arraycopy(queryPacket, 12, response, 16, 4)

        // IP Checksum
        writeU16(response, 10, 0)
        writeU16(response, 10, ipChecksum(response, 0, 20))

        // ---- UDP Header ----
        val udpOffset = 20
        // 源端口 = 原始查询的目标端口 (53)
        System.arraycopy(queryPacket, ipHeaderLen + 2, response, udpOffset, 2)
        // 目标端口 = 原始查询的源端口
        System.arraycopy(queryPacket, ipHeaderLen, response, udpOffset + 2, 2)
        writeU16(response, udpOffset + 4, udpLen)
        writeU16(response, udpOffset + 6, 0) // UDP checksum = 0 (可选)

        // ---- DNS Response ----
        System.arraycopy(dnsResponse, 0, response, udpOffset + 8, dnsResponse.size)

        return response
    }

    fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    fun writeU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value shr 8) and 0xFF).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }

    fun writeU32(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value shr 24) and 0xFF).toByte()
        data[offset + 1] = ((value shr 16) and 0xFF).toByte()
        data[offset + 2] = ((value shr 8) and 0xFF).toByte()
        data[offset + 3] = (value and 0xFF).toByte()
    }

    fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i < length) {
            val word = if (i + 1 < length) {
                ((data[offset + i].toInt() and 0xFF) shl 8) or (data[offset + i + 1].toInt() and 0xFF)
            } else {
                (data[offset + i].toInt() and 0xFF) shl 8
            }
            sum += word
            i += 2
        }
        while ((sum shr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return ((sum.inv()) and 0xFFFF).toInt()
    }
}

package org.xiyu.githubdirect.core.net

/**
 * TLS ClientHello 分片纯函数（从原 TcpRelay.java:356-491 迁移，无 Android 依赖）。
 *
 * 行为与原实现完全一致：
 * - isTlsClientHello 判定：TLS Record type=0x16, version 0x0301..0x0304, Handshake type=0x01
 * - fragmentTlsRecord：在 SNI 域名前 3 字节处把一个 TLS record 拆成两个独立 record；
 *   找不到 SNI 时在 handshake data 中间切（≤50 字节处）；无法分片返回 null
 */
object TlsFragmenter {

    // 分片点：在 TLS Record Header (5字节) 后切割
    const val SPLIT_POSITION = 5
    const val SPLIT_DELAY_MS = 200

    /**
     * 检查数据是否为 TLS ClientHello。
     * TLS Record: type=0x16 (Handshake), version=0x0301/0x0303, then Handshake type=0x01
     */
    @JvmStatic
    fun isTlsClientHello(data: ByteArray): Boolean {
        return data.size > 5
                && data[0] == 0x16.toByte() // TLS Handshake
                && data[1] == 0x03.toByte() // Version major = 3
                && (data[2] >= 0x01 && data[2] <= 0x04) // Version minor 1-4
                && data[5] == 0x01.toByte() // ClientHello
    }

    /**
     * TLS 记录层分片：将一个 TLS 记录拆成两个独立的 TLS 记录。
     * 在 SNI 域名中间分割，使 DPI 无法从单个 TLS 记录中提取完整 SNI。
     *
     * @return 两个相邻的 TLS 记录的字节数组，或 null（无法分片）
     */
    @JvmStatic
    fun fragmentTlsRecord(data: ByteArray): ByteArray? {
        if (data.size < 10) return null

        // 原始 TLS Record: [type(1)][version(2)][length(2)] + [handshake_data]
        val recordDataLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        if (5 + recordDataLen > data.size) return null

        val tlsType = data[0]
        val verMaj = data[1]
        val verMin = data[2]

        // 找到 SNI 在 handshake data 中的偏移量（相对于 record 数据起始 offset=5）
        val sniOffset = findSniOffset(data, 5, recordDataLen)
        val splitPoint: Int

        if (sniOffset > 0) {
            // 在 SNI 域名中间切割（切到 SNI hostname 的前 3 个字节）
            splitPoint = sniOffset + 3
        } else {
            // 找不到 SNI，在 handshake data 中间切
            splitPoint = 5 + minOf(recordDataLen / 2, 50)
        }

        if (splitPoint <= 5 || splitPoint >= 5 + recordDataLen) return null

        val firstLen = splitPoint - 5 // 第一个 TLS 记录的数据长度
        val secondLen = recordDataLen - firstLen // 第二个 TLS 记录的数据长度

        // 构建两个 TLS 记录
        val result = ByteArray(5 + firstLen + 5 + secondLen)

        // Record 1
        result[0] = tlsType
        result[1] = verMaj
        result[2] = verMin
        result[3] = ((firstLen shr 8) and 0xFF).toByte()
        result[4] = (firstLen and 0xFF).toByte()
        System.arraycopy(data, 5, result, 5, firstLen)

        // Record 2
        val off2 = 5 + firstLen
        result[off2] = tlsType
        result[off2 + 1] = verMaj
        result[off2 + 2] = verMin
        result[off2 + 3] = ((secondLen shr 8) and 0xFF).toByte()
        result[off2 + 4] = (secondLen and 0xFF).toByte()
        System.arraycopy(data, splitPoint, result, off2 + 5, secondLen)

        return result
    }

    /**
     * 在 TLS ClientHello 中查找 SNI 域名字符串的起始绝对偏移；未找到返回 -1。
     *
     * ClientHello 结构:
     *   handshake_type(1) + length(3) + version(2) + random(32) + session_id(1+var)
     *   + cipher_suites(2+var) + compression(1+var) + extensions_len(2) + extensions
     * SNI extension: ext_type(2)=0x0000 + ext_len(2) + server_name_list_len(2)
     *   + name_type(1) + name_len(2) + name(var)
     */
    @JvmStatic
    fun findSniOffset(data: ByteArray, recordStart: Int, recordLen: Int): Int {
        var pos = recordStart
        val end = recordStart + recordLen

        // Handshake header: type(1) + length(3)
        if (pos + 4 > end) return -1
        pos += 4

        // ClientHello: version(2) + random(32) = 34 bytes
        if (pos + 34 > end) return -1
        pos += 34

        // Session ID: length(1) + data
        if (pos + 1 > end) return -1
        val sidLen = data[pos].toInt() and 0xFF
        pos += 1 + sidLen

        // Cipher Suites: length(2) + data
        if (pos + 2 > end) return -1
        val csLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2 + csLen

        // Compression Methods: length(1) + data
        if (pos + 1 > end) return -1
        val cmLen = data[pos].toInt() and 0xFF
        pos += 1 + cmLen

        // Extensions: length(2)
        if (pos + 2 > end) return -1
        val extTotalLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        var extEnd = pos + extTotalLen
        if (extEnd > end) extEnd = end

        // 遍历 extensions 寻找 SNI (type = 0x0000)
        while (pos + 4 <= extEnd) {
            val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            val extLen = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)

            if (extType == 0x0000 && extLen > 5) {
                // SNI extension: list_len(2) + name_type(1) + name_len(2) + name
                val sniDataStart = pos + 4
                if (sniDataStart + 5 <= extEnd) {
                    // name_type(1 byte at +2) name_len(2 bytes at +3) name(at +5)
                    val nameStart = sniDataStart + 5
                    if (nameStart < extEnd) {
                        return nameStart // SNI 域名字符串的起始位置
                    }
                }
            }

            pos += 4 + extLen
        }

        return -1
    }
}

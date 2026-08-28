package org.xiyu.githubdirect.core.net

import org.xiyu.githubdirect.core.rules.DnsNames
import java.io.ByteArrayOutputStream
import java.util.Random
import java.util.concurrent.ThreadLocalRandom

/** 解析可能跨多个 TLS record 的明文 ClientHello，并可只重写 record 边界进行分片。 */
object TlsClientHelloRecords {

    sealed class Inspection {
        data object NeedMore : Inspection()
        data object NotClientHello : Inspection()
        class Complete internal constructor(
            val serverName: String?,
            internal val versionMajor: Byte,
            internal val versionMinor: Byte,
            internal val handshake: ByteArray,
            internal val trailingHandshakePayload: ByteArray,
            internal val rawRemainder: ByteArray,
            internal val sniOffset: Int,
            internal val sniLength: Int,
        ) : Inspection()
    }

    data class Fragmented(
        val bytes: ByteArray,
        /** 每次 TCP write 结束位置（累计字节数，最后一项恒等于 [bytes].size）。 */
        val writeEnds: IntArray,
        val serverName: String?,
    ) {
        val firstRecordEnd: Int get() = writeEnds.firstOrNull() ?: bytes.size
    }

    data class TcpWritePlan(
        val writeEnds: IntArray,
        /** 在该 write 后发送一个 TCP urgent byte；-1 表示不发送。 */
        val urgentAfterWriteIndex: Int,
    )

    fun inspect(data: ByteArray, maxBytes: Int = MAX_CLIENT_HELLO): Inspection {
        if (data.isEmpty()) return Inspection.NeedMore
        if (data[0] != 0x16.toByte()) return Inspection.NotClientHello
        if (data.size > maxBytes) return Inspection.NotClientHello

        val payload = ByteArrayOutputStream()
        var pos = 0
        var versionMajor: Byte = 0
        var versionMinor: Byte = 0
        var expectedHandshake = -1
        while (pos < data.size) {
            if (pos + 5 > data.size) return Inspection.NeedMore
            val type = data[pos]
            if (type != 0x16.toByte()) return Inspection.NotClientHello
            val major = data[pos + 1]
            val minor = data[pos + 2]
            if (major != 0x03.toByte() || minor !in 0x01.toByte()..0x04.toByte()) {
                return Inspection.NotClientHello
            }
            if (payload.size() == 0) {
                versionMajor = major
                versionMinor = minor
            }
            val length = ((data[pos + 3].toInt() and 0xff) shl 8) or (data[pos + 4].toInt() and 0xff)
            if (length <= 0 || length > MAX_RECORD_PAYLOAD) return Inspection.NotClientHello
            val recordEnd = pos + 5 + length
            if (recordEnd > data.size) return Inspection.NeedMore
            payload.write(data, pos + 5, length)
            val handshakeBytes = payload.toByteArray()
            if (handshakeBytes.isNotEmpty() && handshakeBytes[0] != 0x01.toByte()) {
                return Inspection.NotClientHello
            }
            if (expectedHandshake < 0 && handshakeBytes.size >= 4) {
                expectedHandshake = 4 + ((handshakeBytes[1].toInt() and 0xff) shl 16) +
                    ((handshakeBytes[2].toInt() and 0xff) shl 8) +
                    (handshakeBytes[3].toInt() and 0xff)
                if (expectedHandshake !in 4..maxBytes) return Inspection.NotClientHello
            }
            pos = recordEnd
            if (expectedHandshake > 0 && handshakeBytes.size >= expectedHandshake) {
                val hello = handshakeBytes.copyOfRange(0, expectedHandshake)
                val sni = parseSni(hello)
                return Inspection.Complete(
                    serverName = sni?.name,
                    versionMajor = versionMajor,
                    versionMinor = versionMinor,
                    handshake = hello,
                    trailingHandshakePayload = handshakeBytes.copyOfRange(expectedHandshake, handshakeBytes.size),
                    rawRemainder = data.copyOfRange(pos, data.size),
                    sniOffset = sni?.offset ?: -1,
                    sniLength = sni?.length ?: 0,
                )
            }
        }
        return Inspection.NeedMore
    }

    fun fragment(
        data: ByteArray,
        maxBytes: Int = MAX_CLIENT_HELLO,
        entropy: Long = ThreadLocalRandom.current().nextLong(),
    ): Fragmented? {
        val complete = inspect(data, maxBytes) as? Inspection.Complete ?: return null
        val payload = complete.handshake + complete.trailingHandshakePayload
        if (payload.size < 2) return null
        val random = Random(entropy)

        // 兼容 TLS 规范地只改变 record 边界：SNI 每 3 字节一个 record，前后各随机取
        // 最多 8 个切点。配合 TCP_NODELAY 和短间隔 write，避免完整 SNI 落在单个 TLS
        // record/TCP write 中；不改 ClientHello 内容，也不影响证书校验。
        val ranges = ArrayList<Pair<Int, Int>>()
        val sniStart = complete.sniOffset
        val sniEnd = sniStart + complete.sniLength
        if (sniStart >= 0 && complete.sniLength > 0 && sniEnd <= complete.handshake.size) {
            ranges += splitSide(0, sniStart, SIDE_FRAGMENT_CUTS, random)
            var cursor = sniStart
            while (cursor < sniEnd) {
                val end = minOf(cursor + SNI_FRAGMENT_BYTES, sniEnd)
                ranges += cursor to end
                cursor = end
            }
            ranges += splitSide(sniEnd, payload.size, SIDE_FRAGMENT_CUTS, random)
        } else {
            ranges += splitSide(0, payload.size, SIDE_FRAGMENT_CUTS, random)
        }
        if (ranges.size < 2) return null

        val output = ByteArrayOutputStream(data.size + ranges.size * 5)
        val writeEnds = IntArray(ranges.size + if (complete.rawRemainder.isNotEmpty()) 1 else 0)
        ranges.forEachIndexed { index, (start, end) ->
            writeRecord(
                output,
                complete.versionMajor,
                complete.versionMinor,
                payload,
                start,
                end - start,
            )
            writeEnds[index] = output.size()
        }
        if (complete.rawRemainder.isNotEmpty()) {
            output.write(complete.rawRemainder)
            writeEnds[writeEnds.lastIndex] = output.size()
        }
        return Fragmented(output.toByteArray(), writeEnds, complete.serverName)
    }

    /**
     * 从 [fragment] 的输出恢复 write 边界；供先经 [ClientHelloAccumulator] 的 Java/VPN 路径使用。
     * 遇到后续非 Handshake record 时作为一个最终 write 原样发送。
     */
    @JvmStatic
    fun fragmentWriteEnds(data: ByteArray): IntArray {
        if (data.isEmpty()) return IntArray(0)
        val ends = ArrayList<Int>()
        var pos = 0
        while (pos + 5 <= data.size && data[pos] == 0x16.toByte()) {
            val length = u16(data, pos + 3)
            val end = pos + 5 + length
            if (length <= 0 || end > data.size) break
            ends += end
            pos = end
        }
        if (ends.isEmpty()) return intArrayOf(data.size)
        if (pos < data.size) ends += data.size
        return ends.toIntArray()
    }

    /**
     * TLS record 分片之后再做一层 TCP write 布局：SNI 区按 4 字节切，前后区域各随机取
     * 最多 8 个切点。只改变 write 边界，不改变字节流；服务端重组后的 TLS 内容与原
     * ClientHello 完全一致。urgent byte 的位置相对 SNI 起点计算，而不是相对整包中点。
     */
    @JvmStatic
    @JvmOverloads
    fun tcpWritePlan(
        data: ByteArray,
        entropy: Long = ThreadLocalRandom.current().nextLong(),
    ): TcpWritePlan {
        val fallback = fragmentWriteEnds(data)
        val complete = inspect(data) as? Inspection.Complete ?: return TcpWritePlan(fallback, -1)
        if (complete.sniOffset < 0 || complete.sniLength <= 0) return TcpWritePlan(fallback, -1)
        val sniStart = complete.sniOffset
        val sniEnd = sniStart + complete.sniLength
        var rawSniStart = -1
        var rawSniEnd = -1
        var rawStart = 0
        var payloadStart = 0
        while (rawStart + 5 <= data.size && data[rawStart] == 0x16.toByte()) {
            val length = u16(data, rawStart + 3)
            val rawEnd = rawStart + 5 + length
            if (length <= 0 || rawEnd > data.size) break
            val payloadEnd = payloadStart + length
            val carriesSni = payloadStart < sniEnd && payloadEnd > sniStart
            if (carriesSni) {
                if (rawSniStart < 0) rawSniStart = rawStart
                rawSniEnd = rawEnd
            }
            rawStart = rawEnd
            payloadStart = payloadEnd
        }
        if (rawSniStart < 0 || rawSniEnd <= rawSniStart) return TcpWritePlan(fallback, -1)

        val random = Random(entropy)
        val ranges = ArrayList<Pair<Int, Int>>()
        ranges += splitSide(0, rawSniStart, TCP_SIDE_FRAGMENT_CUTS, random)
        val firstSniWrite = ranges.size
        var cursor = rawSniStart
        while (cursor < rawSniEnd) {
            val end = minOf(cursor + TCP_SNI_FRAGMENT_BYTES, rawSniEnd)
            ranges += cursor to end
            cursor = end
        }
        val lastSniWrite = ranges.lastIndex
        ranges += splitSide(rawSniEnd, data.size, TCP_SIDE_FRAGMENT_CUTS, random)
        if (ranges.isEmpty()) return TcpWritePlan(fallback, -1)

        val ends = IntArray(ranges.size) { ranges[it].second }
        val urgentIndex = minOf(firstSniWrite + TCP_OOB_OFFSET, lastSniWrite, ends.lastIndex - 1)
            .takeIf { it >= firstSniWrite && it in ends.indices }
            ?: -1
        return TcpWritePlan(ends, urgentIndex)
    }

    @JvmStatic
    fun tcpWriteEnds(data: ByteArray): IntArray = tcpWritePlan(data).writeEnds

    private data class Sni(val name: String, val offset: Int, val length: Int)

    private fun parseSni(handshake: ByteArray): Sni? {
        var pos = 4 // handshake type + uint24 length
        if (pos + 34 > handshake.size) return null
        pos += 34 // legacy_version + random
        if (pos >= handshake.size) return null
        val sessionLength = handshake[pos].toInt() and 0xff
        pos += 1 + sessionLength
        if (pos + 2 > handshake.size) return null
        val cipherLength = u16(handshake, pos)
        pos += 2 + cipherLength
        if (pos >= handshake.size) return null
        val compressionLength = handshake[pos].toInt() and 0xff
        pos += 1 + compressionLength
        if (pos + 2 > handshake.size) return null
        val extensionsEnd = (pos + 2 + u16(handshake, pos)).coerceAtMost(handshake.size)
        pos += 2
        while (pos + 4 <= extensionsEnd) {
            val type = u16(handshake, pos)
            val length = u16(handshake, pos + 2)
            val extensionStart = pos + 4
            val extensionEnd = extensionStart + length
            if (extensionEnd > extensionsEnd) return null
            if (type == 0 && length >= 5) {
                var namePos = extensionStart + 2
                while (namePos + 3 <= extensionEnd) {
                    val nameType = handshake[namePos].toInt() and 0xff
                    val nameLength = u16(handshake, namePos + 1)
                    val valueStart = namePos + 3
                    val valueEnd = valueStart + nameLength
                    if (valueEnd > extensionEnd) return null
                    if (nameType == 0) {
                        val raw = String(handshake, valueStart, nameLength, Charsets.US_ASCII)
                        val normalized = DnsNames.normalize(raw) ?: return null
                        return Sni(normalized, valueStart, nameLength)
                    }
                    namePos = valueEnd
                }
            }
            pos = extensionEnd
        }
        return null
    }

    private fun writeRecord(
        output: ByteArrayOutputStream,
        major: Byte,
        minor: Byte,
        data: ByteArray,
        offset: Int,
        length: Int,
    ) {
        require(length in 1..0xffff)
        output.write(0x16)
        output.write(major.toInt() and 0xff)
        output.write(minor.toInt() and 0xff)
        output.write((length shr 8) and 0xff)
        output.write(length and 0xff)
        output.write(data, offset, length)
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private fun splitSide(start: Int, end: Int, maxCuts: Int, random: Random): List<Pair<Int, Int>> {
        val length = end - start
        if (length <= 0) return emptyList()
        val cutCount = minOf(maxCuts, length - 1)
        if (cutCount <= 0) return listOf(start to end)
        val cuts = HashSet<Int>(cutCount + 2).apply {
            add(start)
            add(end)
        }
        while (cuts.size < cutCount + 2) cuts += start + 1 + random.nextInt(length - 1)
        val ordered = cuts.sorted()
        return List(ordered.size - 1) { index -> ordered[index] to ordered[index + 1] }
    }

    const val MAX_CLIENT_HELLO = 64 * 1024
    const val WRITE_INTERVAL_MS = 10L
    internal const val SNI_FRAGMENT_BYTES = 3
    private const val TCP_SNI_FRAGMENT_BYTES = 4
    private const val SIDE_FRAGMENT_CUTS = 8
    private const val TCP_SIDE_FRAGMENT_CUTS = 8
    private const val TCP_OOB_OFFSET = 3
    private const val MAX_RECORD_PAYLOAD = 0xffff
}

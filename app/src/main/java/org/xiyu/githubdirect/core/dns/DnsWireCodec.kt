package org.xiyu.githubdirect.core.dns

import java.util.concurrent.atomic.AtomicInteger

/** RFC 1035 查询构造与 A/AAAA 响应解析；仅解析候选地址，不改写上游响应。 */
object DnsWireCodec {

    data class Answer(val rcode: Int, val addresses: List<ByteArray>)

    private val nextId = AtomicInteger((System.nanoTime() and 0xffff).toInt())

    fun buildQuery(domain: String, qtype: Int, id: Int = nextId.incrementAndGet() and 0xffff): ByteArray? {
        if (qtype != 1 && qtype != 28) return null
        val normalized = DnsNamesCompat.normalize(domain) ?: return null
        val labels = normalized.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 }) return null
        val nameSize = labels.sumOf { 1 + it.toByteArray(Charsets.US_ASCII).size } + 1
        if (nameSize > 255) return null
        val out = ByteArray(12 + nameSize + 4)
        DnsPacketCodec.writeU16(out, 0, id)
        DnsPacketCodec.writeU16(out, 2, 0x0100) // RD=1
        DnsPacketCodec.writeU16(out, 4, 1)
        var pos = 12
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out[pos++] = bytes.size.toByte()
            System.arraycopy(bytes, 0, out, pos, bytes.size)
            pos += bytes.size
        }
        out[pos++] = 0
        DnsPacketCodec.writeU16(out, pos, qtype)
        DnsPacketCodec.writeU16(out, pos + 2, 1)
        return out
    }

    fun parseAnswers(response: ByteArray, expectedId: Int, qtype: Int): Answer? {
        if (response.size < 12 || qtype != 1 && qtype != 28) return null
        if (DnsPacketCodec.readU16(response, 0) != (expectedId and 0xffff)) return null
        val flags = DnsPacketCodec.readU16(response, 2)
        if (flags and 0x8000 == 0) return null
        val rcode = flags and 0x000f
        val qdCount = DnsPacketCodec.readU16(response, 4)
        val anCount = DnsPacketCodec.readU16(response, 6)
        if (qdCount !in 0..4 || anCount !in 0..64) return null
        var pos = 12
        repeat(qdCount) {
            pos = skipName(response, pos) ?: return null
            if (pos + 4 > response.size) return null
            pos += 4
        }
        val addresses = ArrayList<ByteArray>(4)
        repeat(anCount) {
            pos = skipName(response, pos) ?: return null
            if (pos + 10 > response.size) return null
            val type = DnsPacketCodec.readU16(response, pos)
            val klass = DnsPacketCodec.readU16(response, pos + 2)
            val rdLength = DnsPacketCodec.readU16(response, pos + 8)
            pos += 10
            if (rdLength < 0 || pos + rdLength > response.size) return null
            if (klass == 1 && type == qtype
                && ((type == 1 && rdLength == 4) || (type == 28 && rdLength == 16))
            ) {
                addresses += response.copyOfRange(pos, pos + rdLength)
            }
            pos += rdLength
        }
        return Answer(rcode, addresses)
    }

    private fun skipName(packet: ByteArray, start: Int): Int? {
        var pos = start
        var labels = 0
        while (pos < packet.size && labels++ < 128) {
            val length = packet[pos].toInt() and 0xff
            when {
                length == 0 -> return pos + 1
                length and 0xc0 == 0xc0 -> {
                    if (pos + 1 >= packet.size) return null
                    val pointer = ((length and 0x3f) shl 8) or (packet[pos + 1].toInt() and 0xff)
                    if (pointer >= packet.size) return null
                    return pos + 2
                }
                length > 63 || pos + 1 + length > packet.size -> return null
                else -> pos += 1 + length
            }
        }
        return null
    }

    /** 避免 core/dns 对 rules 包产生循环初始化；语义与 DnsNames.normalize 一致的必要子集。 */
    private object DnsNamesCompat {
        fun normalize(raw: String): String? {
            val value = raw.trim().trimEnd('.').lowercase()
            if (value.isEmpty() || value.length > 253 || value.any { it <= ' ' }) return null
            return value
        }
    }
}

package org.xiyu.githubdirect.core.net

import java.io.ByteArrayOutputStream

/**
 * 累积首个、可能跨多个 TLS record 的 ClientHello；完整后仅重写 record 边界。
 * 超时、超限、非 TLS 或解析失败均原样放行。
 */
class ClientHelloAccumulator(
    private val maxBuffer: Int = TlsClientHelloRecords.MAX_CLIENT_HELLO,
    private val deadlineMs: Long = 1000,
) {
    private val buffer = ByteArrayOutputStream()
    private var startedAt = 0L
    private var decided = false
    private var fragmented = false

    fun feed(data: ByteArray, nowMs: Long): ByteArray? {
        if (decided) return data
        if (data.isEmpty()) return data
        if (buffer.size() == 0) startedAt = nowMs
        if (data.size > maxBuffer - buffer.size()) {
            val pending = buffer.toByteArray()
            decided = true
            return pending + data
        }
        buffer.write(data)
        if (nowMs - startedAt > deadlineMs) return flushRaw()

        return when (TlsClientHelloRecords.inspect(buffer.toByteArray(), maxBuffer)) {
            TlsClientHelloRecords.Inspection.NeedMore -> null
            TlsClientHelloRecords.Inspection.NotClientHello -> flushRaw()
            is TlsClientHelloRecords.Inspection.Complete -> {
                val raw = buffer.toByteArray()
                val result = TlsClientHelloRecords.fragment(raw, maxBuffer)
                decided = true
                if (result == null) raw else {
                    fragmented = true
                    result.bytes
                }
            }
        }
    }

    fun isPassthrough(): Boolean = decided

    fun consumeFragmented(): Boolean {
        val value = fragmented
        fragmented = false
        return value
    }

    private fun flushRaw(): ByteArray {
        decided = true
        return buffer.toByteArray()
    }
}

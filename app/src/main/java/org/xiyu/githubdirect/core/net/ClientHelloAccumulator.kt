package org.xiyu.githubdirect.core.net

import java.io.ByteArrayOutputStream

/**
 * TLS ClientHello 首段累积器（纯 JVM，无 android.* 依赖）。
 *
 * 用途：TcpRelay.writerLoop 分批收到客户端上行数据时，TCP 段可能在任意位置
 * 截断 TLS record（只有 record 头、body 在下一段、甚至头都不完整）。
 * 本类把首段累积到完整 record 后再交给 [TlsFragmenter] 判定 + 分片，
 * 避免「首批发出的数据恰好不完整 → 永久错过分片」的问题。
 *
 * 状态机（单线程使用，writerLoop 调用）：
 *  - WAITING：首个疑似 TLS 字节（0x16）之后累积；feed 返回 null = 继续等下一批
 *  - PASSTHROUGH：最终判定已做出（分片完成 或 放弃），feed 对后续数据原样透传
 *
 * 判定规则：
 *  - 首字节不是 0x16 → 立即原样输出并进入 PASSTHROUGH
 *  - 首字节 0x16 但不足 5 字节 record 头 → 累积
 *  - record 头完整 → 按 record length 计算所需字节；不够 → 累积等待
 *  - 凑齐 → TlsFragmenter.isTlsClientHello + fragmentTlsRecord：
 *      - 是 ClientHello 且分片成功 → 输出分片字节（consumeFragmented() 为 true）
 *      - 不是 / 分片失败 → 输出累积字节原样（forward untouched，不卡死）
 *  - 超时（deadlineMs）或超限（maxBuffer）→ 原样输出已累积部分并进入 PASSTHROUGH
 *  - 累积期间跨过 record 边界的多余字节（客户端后续 TLS 段已到达）：整段累积到
 *    判定完成，判定后剩余字节原样附加在输出末尾
 */
class ClientHelloAccumulator(
    /** 累积缓冲上限：超过 → 放弃累积，原样输出并透传。 */
    private val maxBuffer: Int = 8192,
    /** 首个疑似 TLS 字节后的补齐等待：超时仍未凑齐 → 原样输出并透传。 */
    private val deadlineMs: Long = 1500,
) {
    private val buf = ByteArrayOutputStream()
    private var startMs = 0L
    private var firstByteSeen = false
    private var recordLen = -1
    private var passthrough = false
    private var fragmentedFlag = false

    /**
     * 喂入一段字节。
     * @return null = 本次不输出、继续累积；非 null = 把这段字节发给服务器
     *         （可能是原样字节，也可能是分片后的字节，用 [consumeFragmented] 区分）
     */
    fun feed(data: ByteArray, nowMs: Long): ByteArray? {
        if (passthrough) return data

        if (!firstByteSeen) {
            if (data.isEmpty()) return data
            firstByteSeen = true
            if (data[0] != 0x16.toByte()) { // 非 TLS → 立即原样透传
                passthrough = true
                return data
            }
            startMs = nowMs
        }

        buf.write(data, 0, data.size)

        // record 头凑齐 5 字节后锁定 record length
        if (recordLen < 0 && buf.size() >= 5) {
            val b = buf.toByteArray()
            recordLen = ((b[3].toInt() and 0xFF) shl 8) or (b[4].toInt() and 0xFF)
        }

        if (recordLen >= 0 && buf.size() >= 5 + recordLen) {
            return decide() // 首 record 完整 → 判定
        }
        if (buf.size() > maxBuffer) return flushRaw() // 超限 → 放弃累积
        if (nowMs - startMs > deadlineMs) return flushRaw() // 超时 → 放弃累积
        return null
    }

    /** 是否已完成/放弃分片：后续数据直接透传（feed 对后续数据原样返回）。 */
    fun isPassthrough(): Boolean = passthrough

    /**
     * 上次 feed 返回的输出是否为本累积器产生的 TLS 分片字节（一次性标记，读取后复位）。
     * true → writer 应分两段发送（首段 + SPLIT_DELAY_MS + 尾段）；false → 一次写入。
     */
    fun consumeFragmented(): Boolean {
        val f = fragmentedFlag
        fragmentedFlag = false
        return f
    }

    /** 判定首 record：ClientHello 且分片成功 → 分片 + 剩余原样；否则整体原样。 */
    private fun decide(): ByteArray {
        val all = buf.toByteArray()
        val needed = 5 + recordLen
        val first = all.copyOfRange(0, needed)
        val remaining = if (all.size > needed) all.copyOfRange(needed, all.size) else ByteArray(0)

        if (TlsFragmenter.isTlsClientHello(first)) {
            val fragmented = TlsFragmenter.fragmentTlsRecord(first)
            if (fragmented != null) {
                fragmentedFlag = true
                passthrough = true
                if (remaining.isNotEmpty()) {
                    val out = ByteArray(fragmented.size + remaining.size)
                    System.arraycopy(fragmented, 0, out, 0, fragmented.size)
                    System.arraycopy(remaining, 0, out, fragmented.size, remaining.size)
                    return out
                }
                return fragmented
            }
        }
        passthrough = true
        return all // 原样转发，不卡死
    }

    private fun flushRaw(): ByteArray {
        passthrough = true
        return buf.toByteArray()
    }
}

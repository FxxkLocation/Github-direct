package org.xiyu.githubdirect.core.net

/**
 * 把上行字节喂给 [ClientHelloAccumulator]，必要时按多 TLS record/TCP write 分片写出。
 * Root 透明中继与（将来）其它字节泵共用，避免再复制一份 writerLoop 逻辑。
 */
class TlsFragmentSink(
    private val write: (data: ByteArray, off: Int, len: Int) -> Unit,
    private val sleep: (ms: Long) -> Unit = { Thread.sleep(it) },
    private val accum: ClientHelloAccumulator = ClientHelloAccumulator(),
) {
    fun write(data: ByteArray, off: Int = 0, len: Int = data.size) {
        if (len <= 0) return
        val chunk = if (off == 0 && len == data.size) data else data.copyOfRange(off, off + len)
        if (accum.isPassthrough()) {
            write.invoke(chunk, 0, chunk.size)
            return
        }
        val out = accum.feed(chunk, System.currentTimeMillis()) ?: return
        if (accum.consumeFragmented()) {
            val ends = TlsClientHelloRecords.tcpWriteEnds(out)
            var start = 0
            for (end in ends) {
                if (end <= start || end > out.size) continue
                write.invoke(out, start, end - start)
                start = end
                if (start < out.size) sleep(TlsClientHelloRecords.WRITE_INTERVAL_MS)
            }
            if (start == out.size) return
        }
        write.invoke(out, 0, out.size)
    }
}

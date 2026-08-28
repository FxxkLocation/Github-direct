package org.xiyu.githubdirect.root

import android.os.ParcelFileDescriptor
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/** SO_ORIGINAL_DST 的小型 JNI 桥；不可用时返回 null，调用方必须 fail-open。 */
object OriginalDestination {
    private val loaded: Boolean = runCatching {
        System.loadLibrary("ghdnet")
        // fd=-1 必然返回 null，但会完成 JNI 符号解析；Release 混淆或 ABI 异常时立即 fail-open。
        nativeLookup(-1)
        true
    }.getOrDefault(false)

    fun available(): Boolean = loaded

    fun lookup(socket: Socket): InetSocketAddress? {
        if (!loaded) return null
        val descriptor = try {
            // Android 12+ 返回 dup fd，关闭 PFD 不影响原 Socket。
            ParcelFileDescriptor.fromSocket(socket)
        } catch (_: Throwable) {
            return null
        }
        return descriptor.use { pfd -> decode(nativeLookup(pfd.fd)) }
    }

    internal fun decode(raw: ByteArray?): InetSocketAddress? {
        if (raw == null || raw.size < 7) return null
        val family = raw[0].toInt() and 0xff
        val addressSize = when (family) {
            4 -> 4
            6 -> 16
            else -> return null
        }
        if (raw.size != 3 + addressSize) return null
        val port = ((raw[1].toInt() and 0xff) shl 8) or (raw[2].toInt() and 0xff)
        if (port !in 1..65535) return null
        val address = runCatching { InetAddress.getByAddress(raw.copyOfRange(3, raw.size)) }.getOrNull()
            ?: return null
        return InetSocketAddress(address, port)
    }

    private external fun nativeLookup(fd: Int): ByteArray?
}

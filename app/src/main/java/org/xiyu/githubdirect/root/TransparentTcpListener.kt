package org.xiyu.githubdirect.root

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.StandardSocketOptions
import java.nio.channels.ClosedSelectorException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * TCP 监听器抽象（测试注入点）。
 */
interface TcpListener {
    /** 绑定 127.0.0.1:BASE+N（N=vipStart..vipEnd）并启动 selector 线程；任一端口绑定失败 → false（已绑定的全部关闭）。 */
    fun start(resolveRealIp: (Int) -> ByteArray?): Boolean

    /** 关闭全部监听与活动会话；幂等。 */
    fun stop()

    /** 监听是否存活。 */
    fun alive(): Boolean

    fun stats(): ListenerStats
}

/** 会话统计。 */
data class ListenerStats(
    val acceptedTotal: Long,
    val rejectedTotal: Long,
    val completedSessions: Long,
    val activeSessions: Int,
)

/**
 * 透明 TCP 中继（端口编码 REDIRECT，设计 §1/§38）。
 *
 * - 一个 selector 线程管理 245 个 `ServerSocketChannel`（绑定 127.0.0.1:BASE+N，SO_REUSEADDR 防快速重启）。
 * - accept → 按监听端口算 vIP：`vip = port - BASE` → 注入的 resolveRealIp(vip) 查 VirtualIpPool 映射 → 拿不到 → 关闭。
 * - 远端 connect 到 realIp:remotePort（REDIRECT 重写了目标端口，原端口不可恢复；HTTPS 场景固定 443），10s 超时。
 * - relay：每会话 2 个泵线程（in→out / out→in，8KB buffer）；会话上限 128 → 线程上限 256，超出拒接。
 * - 空闲无数据超时：两侧 SO_TIMEOUT 60s，SocketTimeoutException → 关两侧。
 * - **kernel 管理 TCP 语义**：本地 accepted socket ↔ 远端 socket 双向字节泵，用户态不构造任何 TCP 包。
 *
 * 纯 JVM NIO + Socket。可单测部分：portToVip/vipToPort 伴生纯函数、pump（Socket 对）。
 */
class TransparentTcpListener(
    private val tcpBasePort: Int = DEFAULT_BASE_PORT,
    private val vipStart: Int = 10,
    private val vipEnd: Int = 254,
    private val remotePort: Int = DEFAULT_REMOTE_PORT,
    private val connectTimeoutMs: Int = 10_000,
    private val idleTimeoutMs: Int = 60_000,
    private val maxSessions: Int = 128,
    private val pumpBufferSize: Int = 8192,
) : TcpListener {

    private class Session(
        val client: Socket,
        val remote: Socket,
        /** 2 个泵线程共享；都退出后（值为 0）会话才算结束。 */
        val finishCount: AtomicInteger = AtomicInteger(2),
    )

    @Volatile
    private var running = false
    private var selector: Selector? = null
    private var resolveRealIp: ((Int) -> ByteArray?)? = null
    private val channels = CopyOnWriteArrayList<ServerSocketChannel>()
    private val sessions = ConcurrentHashMap<Session, Boolean>()
    private val sessionCount = AtomicInteger(0)
    private val statsAccepted = AtomicLong(0)
    private val statsRejected = AtomicLong(0)
    private val statsCompleted = AtomicLong(0)

    @Synchronized
    override fun start(resolveRealIp: (Int) -> ByteArray?): Boolean {
        if (running) return true
        requireNotNull(resolveRealIp) { "resolveRealIp 不能为 null" }
        require(vipStart in 1..255 && vipEnd in vipStart..255) { "vIP 范围非法: $vipStart..$vipEnd" }

        val sel = try {
            Selector.open()
        } catch (t: Throwable) {
            return false
        }
        val bound = mutableListOf<ServerSocketChannel>()
        for (vip in vipStart..vipEnd) {
            val port = vipToPort(vip, tcpBasePort)
            val ch = try {
                ServerSocketChannel.open()
            } catch (t: Throwable) {
                bound.forEach { closeQuietly(it) }
                closeQuietly(sel)
                return false
            }
            try {
                ch.setOption(StandardSocketOptions.SO_REUSEADDR, true)
                ch.configureBlocking(false)
                ch.socket().bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port))
                ch.register(sel, SelectionKey.OP_ACCEPT)
                bound.add(ch)
            } catch (t: Throwable) {
                closeQuietly(ch) // 未入列的失败 channel 也要关闭，不残留
                bound.forEach { closeQuietly(it) }
                closeQuietly(sel)
                return false // 绑定失败 → 事务 ROLLBACK 依据
            }
        }

        this.resolveRealIp = resolveRealIp
        this.selector = sel
        channels.addAll(bound)
        running = true
        Thread({ selectorLoop(sel) }, "GHD-TcpSelector").apply {
            isDaemon = true
            start()
        }
        return true
    }

    @Synchronized
    override fun stop() {
        running = false
        selector?.let { closeQuietly(it) } // 解除 select 阻塞
        selector = null
        channels.forEach { closeQuietly(it) }
        channels.clear()
        sessions.keys.forEach { session ->
            closeQuietly(session.client)
            closeQuietly(session.remote)
        }
        sessions.clear()
        sessionCount.set(0)
    }

    override fun alive(): Boolean = running && (selector?.isOpen == true)

    override fun stats(): ListenerStats = ListenerStats(
        acceptedTotal = statsAccepted.get(),
        rejectedTotal = statsRejected.get(),
        completedSessions = statsCompleted.get(),
        activeSessions = sessionCount.get(),
    )

    private fun selectorLoop(sel: Selector) {
        while (running) {
            try {
                if (sel.select(500) == 0) continue
                val keys = sel.selectedKeys().iterator()
                while (keys.hasNext()) {
                    val key = keys.next()
                    keys.remove()
                    if (!key.isValid) continue
                    if (key.isAcceptable) {
                        accept(key.channel() as ServerSocketChannel)
                    }
                }
            } catch (e: ClosedSelectorException) {
                break
            } catch (t: Throwable) {
                // 单次事件处理异常不终止循环
            }
        }
    }

    private fun accept(channel: ServerSocketChannel) {
        val client = try {
            // accept() 返回 SocketChannel，取底层 java.net.Socket（阻塞 pump 语义用）
            channel.accept()?.socket()
        } catch (t: Throwable) {
            null
        } ?: return

        if (sessionCount.get() >= maxSessions) {
            statsRejected.incrementAndGet()
            closeQuietly(client)
            return
        }
        val port = try {
            client.localPort
        } catch (t: Throwable) {
            -1
        }
        val vip = if (port in tcpBasePort + vipStart..tcpBasePort + vipEnd) port - tcpBasePort else -1
        val realIp = if (vip > 0) resolveRealIp?.invoke(vip) else null
        if (realIp == null || realIp.size != 4) {
            statsRejected.incrementAndGet()
            closeQuietly(client)
            return
        }

        val remote = Socket()
        try {
            remote.connect(InetSocketAddress(InetAddress.getByAddress(realIp), remotePort), connectTimeoutMs)
        } catch (t: Throwable) {
            statsRejected.incrementAndGet()
            closeQuietly(client)
            closeQuietly(remote)
            return
        }

        sessionCount.incrementAndGet()
        statsAccepted.incrementAndGet()
        try {
            client.soTimeout = idleTimeoutMs
            remote.soTimeout = idleTimeoutMs
        } catch (t: Throwable) {
            // 超时设置失败不影响 pump（无超时纯泵）
        }

        val session = Session(client, remote)
        sessions[session] = true
        Thread({ pumpOneDirection(session, forward = true) }, "GHD-TcpPumpA").apply { isDaemon = true; start() }
        Thread({ pumpOneDirection(session, forward = false) }, "GHD-TcpPumpB").apply { isDaemon = true; start() }
    }

    /** 会话一个方向的字节泵；结束（EOF/异常/RST/SO_TIMEOUT）→ 关两侧，双双退出后回收会话。 */
    private fun pumpOneDirection(session: Session, forward: Boolean) {
        try {
            if (forward) {
                copy(session.client.getInputStream(), session.remote.getOutputStream())
            } else {
                copy(session.remote.getInputStream(), session.client.getOutputStream())
            }
        } catch (t: Throwable) {
            // EOF/timeout/reset → 结束
        } finally {
            closeQuietly(session.client)
            closeQuietly(session.remote)
            if (session.finishCount.decrementAndGet() == 0) {
                sessions.remove(session)
                sessionCount.decrementAndGet()
                statsCompleted.incrementAndGet()
            }
        }
    }

    private fun copy(input: InputStream, output: OutputStream) {
        val buf = ByteArray(pumpBufferSize)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            output.write(buf, 0, n)
            output.flush()
        }
    }

    private fun closeQuietly(c: AutoCloseable?) {
        try {
            c?.close()
        } catch (_: Throwable) {
        }
    }

    companion object {
        const val DEFAULT_BASE_PORT = 7000
        const val DEFAULT_REMOTE_PORT = 443

        /** vIP 主机号 → 本地监听端口（BASE+N）。 */
        fun vipToPort(vip: Int, base: Int = DEFAULT_BASE_PORT): Int = base + vip

        /** 本地监听端口 → vIP 主机号；非 10..254 范围返回 -1。 */
        fun portToVip(port: Int, base: Int = DEFAULT_BASE_PORT): Int =
            if (port in base + 10..base + 254) port - base else -1

        /**
         * 双向字节泵：内部两个线程（A→B / B→A），任一侧 EOF/异常/超时 → 关两侧，等待另一线程退出。
         * 可用于测试（本地 SocketPair 透传字节）。
         */
        fun pump(socketA: Socket, socketB: Socket, idleTimeoutMs: Long, bufferSize: Int = 8192) {
            setTimeouts(socketA, socketB, idleTimeoutMs)
            val t1 = Thread({ copyOneWay(socketA, socketB, bufferSize) }, "GHD-PumpA")
            val t2 = Thread({ copyOneWay(socketB, socketA, bufferSize) }, "GHD-PumpB")
            t1.isDaemon = true
            t2.isDaemon = true
            t1.start()
            t2.start()
            joinQuietly(t1)
            closeQuietly(socketA)
            closeQuietly(socketB)
            joinQuietly(t2)
        }

        private fun copyOneWay(from: Socket, to: Socket, bufferSize: Int) {
            try {
                val buf = ByteArray(bufferSize)
                val input = from.getInputStream()
                val output = to.getOutputStream()
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    output.write(buf, 0, n)
                    output.flush()
                }
            } catch (t: Throwable) {
                // 结束
            }
        }

        private fun setTimeouts(a: Socket, b: Socket, idleTimeoutMs: Long) {
            try {
                a.soTimeout = idleTimeoutMs.toInt()
                b.soTimeout = idleTimeoutMs.toInt()
            } catch (_: Throwable) {
            }
        }

        private fun joinQuietly(t: Thread) {
            try {
                t.join()
            } catch (_: InterruptedException) {
            }
        }

        private fun closeQuietly(c: AutoCloseable?) {
            try {
                c?.close()
            } catch (_: Throwable) {
            }
        }
    }
}

package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException

/**
 * TransparentTcpListener 测试：vip↔port 换算纯函数、pump 双向透传、
 * 端到端透明中继（本地 SocketPair，不依赖 root）。
 */
class TransparentTcpListenerTest {

    // ---------- vip ↔ 端口换算 ----------

    @Test
    fun `vip 与端口换算`() {
        assertEquals(7010, TransparentTcpListener.vipToPort(10))
        assertEquals(7254, TransparentTcpListener.vipToPort(254))
        assertEquals(7000 + 123, TransparentTcpListener.vipToPort(123))

        assertEquals(10, TransparentTcpListener.portToVip(7010))
        assertEquals(254, TransparentTcpListener.portToVip(7254))
        assertEquals(-1, TransparentTcpListener.portToVip(7009))
        assertEquals(-1, TransparentTcpListener.portToVip(7255))
        assertEquals(-1, TransparentTcpListener.portToVip(53))
        assertEquals(-1, TransparentTcpListener.portToVip(7000))
    }

    // ---------- pump 双向透传 ----------

    @Test
    fun `pump 双向透传且关闭一侧后返回`() {
        val server = ServerSocket().apply { bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)) }
        val a = Socket()
        a.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort), 2000)
        val b = server.accept()
        server.close()

        val pumpThread = Thread { TransparentTcpListener.pump(a, b, 2000) }
        pumpThread.start()

        // a → b
        a.getOutputStream().write("hello-a".toByteArray())
        a.getOutputStream().flush()
        val buf = ByteArray(32)
        val n1 = b.getInputStream().read(buf)
        assertEquals("hello-a", String(buf, 0, n1))

        // b → a
        b.getOutputStream().write("hello-b".toByteArray())
        b.getOutputStream().flush()
        val n2 = a.getInputStream().read(buf)
        assertEquals("hello-b", String(buf, 0, n2))

        // 关一侧 → 另一侧泵退出 → pump 返回
        b.close()
        pumpThread.join(3000)
        assertFalse("pump 应在一侧关闭后返回", pumpThread.isAlive)
        a.close()
    }

    // ---------- 端到端透明中继 ----------

    private class EchoServer {
        private val server = ServerSocket().apply { bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)) }
        val port: Int get() = server.localPort

        init {
            Thread({
                while (!server.isClosed) {
                    val s = try {
                        server.accept()
                    } catch (t: Throwable) {
                        break
                    }
                    Thread({
                        try {
                            val buf = ByteArray(1024)
                            val input = s.getInputStream()
                            val output = s.getOutputStream()
                            while (true) {
                                val n = input.read(buf)
                                if (n < 0) break
                                output.write(buf, 0, n)
                                output.flush()
                            }
                        } catch (t: Throwable) {
                        } finally {
                            try {
                                s.close()
                            } catch (_: Throwable) {
                            }
                        }
                    }, "GHD-TestEcho").apply { isDaemon = true; start() }
                }
            }, "GHD-TestEchoAccept").apply { isDaemon = true; start() }
        }

        fun close() {
            try {
                server.close()
            } catch (_: Throwable) {
            }
        }
    }

    private fun listener(echoPort: Int): TransparentTcpListener = TransparentTcpListener(
        tcpBasePort = 7000,
        vipStart = 10,
        vipEnd = 11,
        remotePort = echoPort,
        connectTimeoutMs = 3000,
        idleTimeoutMs = 3000,
    )

    @Test
    fun `端到端 透明中继透传字节并统计`() {
        val echo = EchoServer()
        try {
            val listener = listener(echo.port)
            // vip 10 → 本机（echo 服务）；vip 11 → 无映射
            assertTrue(listener.start { vip -> if (vip == 10) byteArrayOf(127, 0, 0, 1) else null })

            val client = Socket()
            client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 7010), 3000)
            client.soTimeout = 3000
            client.getOutputStream().write("ping-1".toByteArray())
            client.getOutputStream().flush()

            val buf = ByteArray(16)
            val n = client.getInputStream().read(buf)
            assertEquals("ping-1", String(buf, 0, n))

            assertTrue(listener.stats().acceptedTotal >= 1)
            assertTrue(listener.stats().activeSessions in 0..1)

            listener.stop()
            client.close()

            // 停止后新连接应被拒绝
            try {
                val c2 = Socket()
                c2.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 7010), 1000)
                c2.close()
                throw AssertionError("stop 后监听应已关闭")
            } catch (e: SocketException) {
                // 预期：连接被拒绝
            }
        } finally {
            echo.close()
        }
    }

    @Test
    fun `resolve 无映射时拒绝连接`() {
        val echo = EchoServer()
        try {
            val listener = listener(echo.port)
            assertTrue(listener.start { null }) // 所有 vIP 无映射

            val client = Socket()
            client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 7010), 3000)
            client.soTimeout = 3000
            // 服务端直接关闭：读返回 EOF（-1）或异常
            try {
                assertEquals(-1, client.getInputStream().read())
            } catch (e: SocketException) {
                // 预期：连接被重置
            }
            assertTrue("拒接应计入 stats", listener.stats().rejectedTotal >= 1)
            client.close()
            listener.stop()
        } finally {
            echo.close()
        }
    }

    @Test
    fun `端口占用导致绑定失败返回 false 且已绑定的端口全部关闭`() {
        // 占用 7011（普通 ServerSocket，无 REUSEADDR；跨平台都阻止 REUSEADDR 绑定）
        val blocker = ServerSocket().apply { bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 7011)) }
        try {
            val listener = TransparentTcpListener(tcpBasePort = 7000, vipStart = 10, vipEnd = 11)
            assertFalse(listener.start { byteArrayOf(127, 0, 0, 1) })
            // ROLLBACK：已绑定的 7010 也应已关闭，不留残留
            try {
                val c = Socket()
                c.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 7010), 1000)
                c.close()
                throw AssertionError("绑定失败后 7010 不应残留")
            } catch (e: SocketException) {
                // 预期：连接被拒绝
            }
        } finally {
            blocker.close()
        }
    }
}

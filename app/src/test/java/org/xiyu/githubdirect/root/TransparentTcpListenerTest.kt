package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.routing.CandidateSource
import org.xiyu.githubdirect.core.routing.EndpointCandidate
import org.xiyu.githubdirect.core.routing.EndpointPlan
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * TransparentTcpListener 测试：vip↔port 换算纯函数、pump 双向透传、
 * 端到端透明中继（本地 SocketPair，不依赖 root）。
 */
class TransparentTcpListenerTest {

    private fun clientHello(domain: String): ByteArray {
        val body = ByteArrayOutputStream().apply {
            write(0x01); write(0); write(0); write(0)
            write(0x03); write(0x03)
            write(ByteArray(32) { 0x42 })
            write(0)
            write(0); write(2); write(0x13); write(0x01)
            write(0)
            val name = domain.toByteArray(Charsets.US_ASCII)
            val extensions = ByteArrayOutputStream().apply {
                write(0); write(0)
                val extensionLength = 2 + 1 + 2 + name.size
                write(extensionLength shr 8); write(extensionLength)
                val listLength = 1 + 2 + name.size
                write(listLength shr 8); write(listLength)
                write(0); write(name.size shr 8); write(name.size); write(name)
            }.toByteArray()
            write(extensions.size shr 8); write(extensions.size); write(extensions)
        }.toByteArray()
        val handshakeLength = body.size - 4
        body[1] = (handshakeLength shr 16).toByte()
        body[2] = (handshakeLength shr 8).toByte()
        body[3] = handshakeLength.toByte()
        return byteArrayOf(
            0x16, 0x03, 0x03,
            (body.size shr 8).toByte(), body.size.toByte(),
        ) + body
    }

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

    @Test
    fun `无SNI精确IP回退只接受可信且唯一的端点组`() {
        val now = System.currentTimeMillis()
        fun candidate(domain: String, address: String, interceptOnly: Boolean = false) = EndpointCandidate(
            domain, address, CandidateSource.BUNDLED, now, 0, 10,
            RouteCapability.FRAGMENTED_TLS, interceptOnly = interceptOnly,
        )
        fun snapshot(vararg plans: EndpointPlan) = RouteSnapshot(
            generation = 1,
            createdAt = now,
            expiresAt = 0,
            plans = plans.associateBy(EndpointPlan::domain),
            metaCidrs = emptySet(),
        )

        val pollutedOnly = snapshot(
            EndpointPlan("github.com", "web", candidates = listOf(candidate("github.com", "1.2.3.4", true))),
        )
        assertNull(TransparentTcpListener.uniqueExactEndpointGroup(pollutedOnly, "1.2.3.4"))

        val unique = snapshot(
            EndpointPlan("github.com", "web", candidates = listOf(candidate("github.com", "1.2.3.4"))),
            EndpointPlan("gist.github.com", "web", candidates = listOf(candidate("gist.github.com", "1.2.3.4"))),
        )
        assertEquals("web", TransparentTcpListener.uniqueExactEndpointGroup(unique, "1.2.3.4"))

        val ambiguous = snapshot(
            EndpointPlan("github.com", "web", candidates = listOf(candidate("github.com", "1.2.3.4"))),
            EndpointPlan("api.github.com", "api", candidates = listOf(candidate("api.github.com", "1.2.3.4"))),
        )
        assertNull(TransparentTcpListener.uniqueExactEndpointGroup(ambiguous, "1.2.3.4"))

        val unusable = snapshot(
            EndpointPlan(
                "github.com",
                "web",
                candidates = listOf(
                    candidate("github.com", "1.2.3.4").copy(capability = RouteCapability.UNUSABLE),
                ),
            ),
        )
        assertNull(TransparentTcpListener.uniqueExactEndpointGroup(unusable, "1.2.3.4", now))

        val expired = snapshot(
            EndpointPlan(
                "github.com",
                "web",
                candidates = listOf(candidate("github.com", "1.2.3.4").copy(expiresAt = now)),
            ),
        )
        assertNull(TransparentTcpListener.uniqueExactEndpointGroup(expired, "1.2.3.4", now))
    }

    @Test
    fun `只有TLS Handshake首包记为候选成功`() {
        assertTrue(TransparentTcpListener.isTlsServerHandshakeRecord(byteArrayOf(0x16)))
        assertFalse(TransparentTcpListener.isTlsServerHandshakeRecord(byteArrayOf(0x15, 0x03, 0x03)))
        assertFalse(TransparentTcpListener.isTlsServerHandshakeRecord("HTTP/1.1".toByteArray()))
        assertFalse(TransparentTcpListener.isTlsServerHandshakeRecord(byteArrayOf()))
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

    @Test
    fun `真实IP入口无法确认GitHub时原样连接原目的地`() {
        val echo = EchoServer()
        val directPort = ServerSocket(0).use { it.localPort }
        try {
            val original = InetSocketAddress(InetAddress.getLoopbackAddress(), echo.port)
            val listener = TransparentTcpListener(
                tcpBasePort = 7300,
                vipStart = 10,
                vipEnd = 11,
                remotePort = echo.port,
                directPort = directPort,
                connectTimeoutMs = 3000,
                idleTimeoutMs = 3000,
                directAvailable = { true },
                originalLookup = { original },
            )
            assertTrue(listener.start { null })
            assertTrue(listener.realDestinationInterceptionActive())
            assertTrue("测试主机应同时监听IPv6回环", listener.ipv6DirectActive())

            Socket().use { client ->
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), directPort), 3000)
                client.soTimeout = 3000
                client.getOutputStream().apply { write("passthrough".toByteArray()); flush() }
                val buf = ByteArray(32)
                val count = client.getInputStream().read(buf)
                assertEquals("passthrough", String(buf, 0, count))
            }
            assertTrue(listener.stats().unclassifiedTlsTotal >= 1)
            listener.stop()
        } finally {
            echo.close()
        }
    }

    @Test
    fun `首候选阻塞时225毫秒竞速第二候选且总切换低于2点5秒`() {
        val upstream = ServerSocket().apply {
            bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        }
        val upstreamThread = Thread {
            try {
                upstream.accept().use { socket ->
                    socket.soTimeout = 2000
                    val first = ByteArray(4096)
                    if (socket.getInputStream().read(first) > 0) {
                        socket.getOutputStream().apply { write(0x16); flush() }
                        Thread.sleep(500)
                    }
                }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true; start() }
        val directPort = ServerSocket(0).use { it.localPort }
        val now = System.currentTimeMillis()
        fun candidate(address: String, latency: Long) = EndpointCandidate(
            "github.com", address, CandidateSource.BUNDLED, now, 0, latency,
            RouteCapability.FRAGMENTED_TLS,
        )
        val snapshot = RouteSnapshot(
            7, now, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web",
                    candidates = listOf(candidate("192.0.2.1", 1), candidate("127.0.0.1", 20)),
                ),
            ),
            emptySet(),
        )
        val original = InetSocketAddress(InetAddress.getLoopbackAddress(), upstream.localPort)
        val listener = TransparentTcpListener(
            tcpBasePort = 7600,
            vipStart = 10,
            vipEnd = 11,
            remotePort = upstream.localPort,
            directPort = directPort,
            connectTimeoutMs = 2500,
            serverHelloTimeoutMs = 1200,
            directAvailable = { true },
            originalLookup = { original },
            routeProvider = { snapshot },
            bindRemote = {},
            routeOutcome = { _, _, _, _ -> },
        )
        try {
            assertTrue(listener.start { null })
            val started = System.nanoTime()
            Socket().use { client ->
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), directPort), 1000)
                client.soTimeout = 3000
                client.getOutputStream().apply { write(clientHello("github.com")); flush() }
                assertEquals(0x16, client.getInputStream().read())
            }
            val elapsedMs = (System.nanoTime() - started) / 1_000_000
            assertTrue("候选切换耗时 ${elapsedMs}ms", elapsedMs < 2500)
        } finally {
            listener.stop()
            upstream.close()
            upstreamThread.join(1000)
        }
    }

    @Test
    fun `单个分片候选不得占用两个竞速槽原目的地址作为第二槽`() {
        val now = System.currentTimeMillis()
        val candidate = EndpointCandidate(
            "chatgpt.com", "104.18.32.47", CandidateSource.WIRE_DOH,
            now, 0, 1, RouteCapability.FRAGMENTED_TLS,
        )
        val attempts = TransparentTcpListener.planAttempts(
            candidates = listOf(candidate),
            runtimeAddresses = emptyList(),
            originalAddress = "172.64.155.209",
            allowFragment = true,
        )

        assertEquals(
            listOf("104.18.32.47", "172.64.155.209", "104.18.32.47"),
            attempts.map { it.address },
        )
        assertEquals(
            listOf(0, 0, 1),
            attempts.map { it.variant },
        )
        assertEquals(
            "前两个竞速槽必须使用不同 IP",
            2,
            attempts.take(2).map { it.address }.distinct().size,
        )
    }

    @Test
    fun `关闭adaptive_candidates后只连接原目的地址`() {
        val acceptedAddress = AtomicReference<String>()
        val upstream = ServerSocket().apply { bind(InetSocketAddress("0.0.0.0", 0)) }
        val upstreamThread = Thread {
            try {
                upstream.accept().use { socket ->
                    acceptedAddress.set(socket.localAddress.hostAddress)
                    socket.getInputStream().read(ByteArray(4096))
                    socket.getOutputStream().apply { write(0x16); flush() }
                }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true; start() }
        val directPort = ServerSocket(0).use { it.localPort }
        val now = System.currentTimeMillis()
        val snapshot = RouteSnapshot(
            10, now, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web",
                    candidates = listOf(
                        EndpointCandidate(
                            "github.com", "127.0.0.2", CandidateSource.BUNDLED,
                            now, 0, 1, RouteCapability.FRAGMENTED_TLS,
                        ),
                    ),
                ),
            ),
            emptySet(),
        )
        val listener = TransparentTcpListener(
            tcpBasePort = 8200,
            vipStart = 10,
            vipEnd = 11,
            remotePort = upstream.localPort,
            directPort = directPort,
            directAvailable = { true },
            adaptiveCandidatesEnabled = { false },
            tlsFragmentV2Enabled = { false },
            originalLookup = { InetSocketAddress("127.0.0.3", upstream.localPort) },
            routeProvider = { snapshot },
            bindRemote = {},
            routeOutcome = { _, _, _, _ -> },
        )
        try {
            assertTrue(listener.start { null })
            Socket().use { client ->
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), directPort), 1000)
                client.soTimeout = 3000
                client.getOutputStream().apply { write(clientHello("github.com")); flush() }
                assertEquals(0x16, client.getInputStream().read())
            }
            assertEquals("127.0.0.3", acceptedAddress.get())
        } finally {
            listener.stop()
            upstream.close()
            upstreamThread.join(1000)
        }
    }

    @Test
    fun `关闭tls_fragment_v2后保持单一原始ClientHello record`() {
        val firstRecordLength = AtomicInteger(-1)
        val upstream = ServerSocket().apply { bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)) }
        val upstreamThread = Thread {
            try {
                upstream.accept().use { socket ->
                    val header = ByteArray(5)
                    var offset = 0
                    while (offset < header.size) {
                        val count = socket.getInputStream().read(header, offset, header.size - offset)
                        if (count < 0) break
                        offset += count
                    }
                    if (offset == header.size) {
                        firstRecordLength.set(
                            ((header[3].toInt() and 0xff) shl 8) or (header[4].toInt() and 0xff),
                        )
                    }
                    socket.getOutputStream().apply { write(0x16); flush() }
                }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true; start() }
        val directPort = ServerSocket(0).use { it.localPort }
        val hello = clientHello("github.com")
        val listener = TransparentTcpListener(
            tcpBasePort = 8300,
            vipStart = 10,
            vipEnd = 11,
            remotePort = upstream.localPort,
            directPort = directPort,
            directAvailable = { true },
            adaptiveCandidatesEnabled = { false },
            tlsFragmentV2Enabled = { false },
            originalLookup = { InetSocketAddress(InetAddress.getLoopbackAddress(), upstream.localPort) },
            bindRemote = {},
            routeOutcome = { _, _, _, _ -> },
        )
        try {
            assertTrue(listener.start { null })
            Socket().use { client ->
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), directPort), 1000)
                client.soTimeout = 3000
                client.getOutputStream().apply { write(hello); flush() }
                assertEquals(0x16, client.getInputStream().read())
            }
            assertEquals(hello.size - 5, firstRecordLength.get())
        } finally {
            listener.stop()
            upstream.close()
            upstreamThread.join(1000)
        }
    }

    @Test
    fun `vIP入口也按SNI竞速候选而非固守单一映射`() {
        val upstream = ServerSocket().apply {
            bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        }
        val upstreamThread = Thread {
            try {
                upstream.accept().use { socket ->
                    socket.soTimeout = 2000
                    if (socket.getInputStream().read(ByteArray(4096)) > 0) {
                        // 覆盖分片 record 的 200ms 间隔，等待第二段后再返回服务器字节。
                        Thread.sleep(300)
                        socket.getOutputStream().apply { write(0x16); flush() }
                    }
                }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true; start() }
        val now = System.currentTimeMillis()
        fun candidate(address: String, latency: Long) = EndpointCandidate(
            "github.com", address, CandidateSource.BUNDLED, now, 0, latency,
            RouteCapability.FRAGMENTED_TLS,
        )
        val snapshot = RouteSnapshot(
            9, now, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web",
                    candidates = listOf(candidate("192.0.2.1", 1), candidate("127.0.0.1", 20)),
                ),
            ),
            emptySet(),
        )
        val listener = TransparentTcpListener(
            tcpBasePort = 8100,
            vipStart = 10,
            vipEnd = 11,
            remotePort = upstream.localPort,
            connectTimeoutMs = 2500,
            serverHelloTimeoutMs = 1200,
            routeProvider = { snapshot },
            bindRemote = {},
            routeOutcome = { _, _, _, _ -> },
        )
        try {
            assertTrue(listener.start { vip -> if (vip == 10) byteArrayOf(127, 0, 0, 3) else null })
            Socket().use { client ->
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 8110), 1000)
                client.soTimeout = 3000
                client.getOutputStream().apply { write(clientHello("github.com")); flush() }
                assertEquals(0x16, client.getInputStream().read())
            }
        } finally {
            listener.stop()
            upstream.close()
            upstreamThread.join(1000)
        }
    }

    @Test
    fun `新后缀子域无需精确计划即可使用实时解析地址`() {
        val acceptedAddress = AtomicReference<String>()
        val upstream = ServerSocket().apply { bind(InetSocketAddress("0.0.0.0", 0)) }
        val upstreamThread = Thread {
            try {
                upstream.accept().use { socket ->
                    acceptedAddress.set(socket.localAddress.hostAddress)
                    socket.soTimeout = 2000
                    if (socket.getInputStream().read(ByteArray(4096)) > 0) {
                        Thread.sleep(300)
                        socket.getOutputStream().apply { write(0x16); flush() }
                    }
                }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true; start() }
        val listener = TransparentTcpListener(
            tcpBasePort = 8400,
            vipStart = 10,
            vipEnd = 11,
            remotePort = upstream.localPort,
            connectTimeoutMs = 1800,
            serverHelloTimeoutMs = 1000,
            tlsFragmentV2Enabled = { false },
            routeProvider = { RouteSnapshot.EMPTY },
            trustedRelayDomain = { it == "r9---sn-new.googlevideo.com" },
            runtimeAddresses = { listOf("127.0.0.2") },
            bindRemote = {},
            routeOutcome = { _, _, _, _ -> },
        )
        try {
            assertTrue(listener.start { vip -> if (vip == 10) byteArrayOf(127, 0, 0, 3) else null })
            Socket().use { client ->
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 8410), 1000)
                client.soTimeout = 3000
                client.getOutputStream().apply {
                    write(clientHello("r9---sn-new.googlevideo.com"))
                    flush()
                }
                val first = client.getInputStream().read()
                assertEquals("accepted=${acceptedAddress.get()} stats=${listener.stats()}", 0x16, first)
            }
            assertEquals("127.0.0.2", acceptedAddress.get())
        } finally {
            listener.stop()
            upstream.close()
            upstreamThread.join(1000)
        }
    }

    @Test
    fun `双能力候选仍优先使用已验证本机TLS终止器`() {
        val terminator = ServerSocket().apply {
            bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        }
        val terminatorAccepted = AtomicInteger()
        val terminatorThread = Thread {
            try {
                terminator.accept().use { socket ->
                    terminatorAccepted.incrementAndGet()
                    socket.soTimeout = 1500
                    if (socket.getInputStream().read(ByteArray(4096)) > 0) {
                        socket.getOutputStream().apply { write(0x16); flush() }
                    }
                }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true; start() }
        val directPort = ServerSocket(0).use { it.localPort }
        val directAttempts = AtomicInteger()
        val directUpstream = ServerSocket().apply {
            bind(InetSocketAddress("0.0.0.0", 0))
        }
        val directThread = Thread {
            try {
                directUpstream.accept().use { directAttempts.incrementAndGet() }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true; start() }
        val now = System.currentTimeMillis()
        val dualCapability = EndpointCandidate(
            "github.com", "127.0.0.2", CandidateSource.BUNDLED, now, 0, 10,
            RouteCapability.DIRECT_TLS,
            noSniCapable = true,
        )
        val snapshot = RouteSnapshot(
            10, now, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com",
                    "web",
                    candidates = listOf(dualCapability),
                ),
            ),
            emptySet(),
        )
        val listener = TransparentTcpListener(
            tcpBasePort = 8200,
            vipStart = 10,
            vipEnd = 11,
            remotePort = directUpstream.localPort,
            directPort = directPort,
            connectTimeoutMs = 300,
            localTerminationTimeoutMs = 1000,
            directAvailable = { true },
            originalLookup = { InetSocketAddress("127.0.0.3", directUpstream.localPort) },
            routeProvider = { snapshot },
            bindRemote = {},
            routeOutcome = { _, _, _, _ -> },
            tlsTerminationRoute = {
                TlsTerminationRoute(
                    domain = "github.com",
                    includeSubdomains = false,
                    method = TlsTerminationMethod.NO_SNI,
                    localAddress = InetSocketAddress(InetAddress.getLoopbackAddress(), terminator.localPort),
                    upstreamAddress = "127.0.0.2",
                )
            },
        )
        try {
            assertTrue(listener.start { null })
            Socket().use { client ->
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), directPort), 1000)
                client.soTimeout = 2500
                client.getOutputStream().apply { write(clientHello("github.com")); flush() }
                assertEquals(0x16, client.getInputStream().read())
            }
            assertEquals(1, terminatorAccepted.get())
            assertEquals(0, directAttempts.get())
            for (attempt in 0 until 50) {
                if (listener.stats().terminatedTlsTotal == 1L) break
                Thread.sleep(10)
            }
            assertEquals(1L, listener.stats().terminatedTlsTotal)
        } finally {
            listener.stop()
            terminator.close()
            directUpstream.close()
            terminatorThread.join(1000)
            directThread.join(1000)
        }
    }

    @Test
    fun `观察到TLS Alert后不得重试候选且健康记失败`() {
        val accepted = AtomicInteger()
        val routeSucceeded = AtomicReference<Boolean>()
        val upstream = ServerSocket().apply {
            bind(InetSocketAddress("0.0.0.0", 0))
        }
        val upstreamThread = Thread {
            while (!upstream.isClosed) {
                val socket = try {
                    upstream.accept()
                } catch (_: Throwable) {
                    break
                }
                accepted.incrementAndGet()
                Thread({
                    socket.use {
                        try {
                            it.soTimeout = 1000
                            it.getInputStream().read(ByteArray(4096))
                            // 中继的两条 TLS record 间隔 200ms；保持连接到第二段发送完再回应。
                            Thread.sleep(300)
                            it.getOutputStream().apply { write(0x15); flush() }
                        } catch (_: Throwable) {
                        }
                    }
                }, "GHD-TestNoRetryUpstream").apply { isDaemon = true; start() }
            }
        }.apply { isDaemon = true; start() }
        val directPort = ServerSocket(0).use { it.localPort }
        val now = System.currentTimeMillis()
        fun candidate(address: String, latency: Long) = EndpointCandidate(
            "github.com", address, CandidateSource.BUNDLED, now, 0, latency,
            RouteCapability.FRAGMENTED_TLS,
        )
        val snapshot = RouteSnapshot(
            8, now, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web",
                    candidates = listOf(candidate("127.0.0.1", 1), candidate("127.0.0.2", 2)),
                ),
            ),
            emptySet(),
        )
        val original = InetSocketAddress("127.0.0.3", upstream.localPort)
        val listener = TransparentTcpListener(
            tcpBasePort = 7900,
            vipStart = 10,
            vipEnd = 11,
            remotePort = upstream.localPort,
            directPort = directPort,
            connectTimeoutMs = 1500,
            serverHelloTimeoutMs = 800,
            directAvailable = { true },
            originalLookup = { original },
            routeProvider = { snapshot },
            bindRemote = {},
            routeOutcome = { _, _, success, _ -> routeSucceeded.set(success) },
        )
        try {
            assertTrue(listener.start { null })
            Socket().use { client ->
                client.setSoLinger(true, 0)
                client.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), directPort), 1000)
                client.getOutputStream().apply { write(clientHello("github.com")); flush() }
                Thread.sleep(50)
            }
            Thread.sleep(900)
            assertEquals("服务器数据出现后不得连接第二候选", 1, accepted.get())
            assertEquals("TLS Alert 不得提升候选健康度", false, routeSucceeded.get())
        } finally {
            listener.stop()
            upstream.close()
            upstreamThread.join(1000)
        }
    }
}

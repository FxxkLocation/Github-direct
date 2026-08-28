package org.xiyu.githubdirect.root

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.Closeable
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class SniGateRouteVerifierTest {
    @Test
    fun `deadline closes active resource and rejects a late registration`() {
        val firstClosed = CountDownLatch(1)
        val lateClosed = AtomicBoolean(false)
        RouteVerificationDeadline(40).use { deadline ->
            deadline.register(Closeable { firstClosed.countDown() })

            assertTrue(
                "active resource should be closed at the hard deadline",
                firstClosed.await(2, TimeUnit.SECONDS),
            )
            assertTrue(deadline.isExpired())
            val failure = runCatching {
                deadline.register(Closeable { lateClosed.set(true) })
            }.exceptionOrNull()
            assertTrue(failure is IllegalStateException)
            assertTrue(lateClosed.get())
        }
    }

    @Test
    fun `blackhole TLS handshake is physically closed at global deadline`() {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val accepted = CountDownLatch(1)
        val peerClosed = CountDownLatch(1)
        val serverFailure = AtomicReference<Throwable?>()
        val serverThread = Thread({
            try {
                server.accept().use { peer ->
                    accepted.countDown()
                    peer.soTimeout = 3_000
                    val buffer = ByteArray(8 * 1024)
                    while (peer.getInputStream().read(buffer) >= 0) Unit
                    peerClosed.countDown()
                }
            } catch (_: SocketTimeoutException) {
                // The assertion below reports a missing physical close more clearly.
            } catch (t: Throwable) {
                if (!server.isClosed) serverFailure.set(t)
            }
        }, "GHD-TestTlsBlackhole").apply {
            isDaemon = true
            start()
        }

        try {
            val resource = checkNotNull(javaClass.classLoader?.getResource("test-ca.pem"))
            val verifier = SniGateRouteVerifier(
                caCertificate = File(resource.toURI()),
                connectTimeoutMs = 5_000,
                globalTimeoutMs = 150,
            )
            val plan = TlsTerminationPlan(
                generation = 1L,
                routes = listOf(
                    TlsTerminationRoute(
                        domain = "example.com",
                        includeSubdomains = false,
                        method = TlsTerminationMethod.NO_SNI,
                        localAddress = InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort),
                        upstreamAddress = "203.0.113.8",
                    ),
                ),
            )

            val startedAt = System.nanoTime()
            val result = verifier.verify(plan)
            val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)

            assertTrue(
                "blackhole server should receive the local TLS connection",
                accepted.await(1, TimeUnit.SECONDS),
            )
            assertTrue(
                "verification should obey a bounded hard deadline, elapsed=${elapsedMs}ms",
                elapsedMs < 2_000,
            )
            assertTrue(result.plan.routes.isEmpty())
            assertTrue(result.failures["example.com"].orEmpty().contains("deadline"))
            assertTrue(
                "deadline must close the transport fd, not only interrupt its Future",
                peerClosed.await(2, TimeUnit.SECONDS),
            )
            assertFalse(
                "verification worker must not leak after deadline",
                waitForVerifierThread(timeoutMs = 1_000),
            )
            serverFailure.get()?.let { throw AssertionError("blackhole server failed", it) }
        } finally {
            runCatching { server.close() }
            serverThread.join(1_000)
        }
    }

    /** Returns true when a verifier thread is still alive after the bounded wait. */
    private fun waitForVerifierThread(timeoutMs: Long): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        do {
            val alive = Thread.getAllStackTraces().keys.any {
                it.name == "GHD-SniGateVerify" && it.isAlive
            }
            if (!alive) return false
            Thread.sleep(5)
        } while (System.nanoTime() < deadline)
        return true
    }
}

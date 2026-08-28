package org.xiyu.githubdirect.root

import android.os.Build
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.routing.suffixProbeDomain
import java.io.Closeable
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

data class SniGateRouteVerification(
    val plan: TlsTerminationPlan,
    val attempted: Int,
    val failures: Map<String, String>,
)

/**
 * 对本机 sni-gate 做端到端 TLS 握手。
 *
 * sni-gate 在 HTTP/2 镜像路径中先完成上游握手，再向本地客户端出示动态叶证书。因此这里
 * 的成功同时证明：本地 CA 链/主机名正确、上游 TCP 可达、ECH（若适用）被接受，以及
 * 上游公开证书按真实内层域名校验通过。这里只显式信任本设备公开 CA，不使用 TrustAll。
 */
class SniGateRouteVerifier(
    private val caCertificate: File,
    private val connectTimeoutMs: Int = ROUTE_TIMEOUT_MS,
    private val globalTimeoutMs: Long = GLOBAL_TIMEOUT_MS,
) {
    fun verify(plan: TlsTerminationPlan): SniGateRouteVerification {
        if (plan.routes.isEmpty()) return SniGateRouteVerification(plan, 0, emptyMap())
        require(connectTimeoutMs > 0) { "connect timeout must be positive" }
        require(globalTimeoutMs > 0L) { "global timeout must be positive" }
        val sslContext = buildSslContext(caCertificate)
        val workers = minOf(MAX_WORKERS, plan.routes.size).coerceAtLeast(1)
        val executor = Executors.newFixedThreadPool(workers) { runnable ->
            Thread(runnable, "GHD-SniGateVerify").apply { isDaemon = true }
        }
        val deadline = RouteVerificationDeadline(globalTimeoutMs)
        return try {
            val tasks = plan.routes.map { route ->
                Callable { verifyOne(sslContext, route, deadline) }
            }
            val futures = executor.invokeAll(tasks, globalTimeoutMs, TimeUnit.MILLISECONDS)
            val verified = ArrayList<TlsTerminationRoute>(plan.routes.size)
            val failures = LinkedHashMap<String, String>()
            for ((index, future) in futures.withIndex()) {
                val route = plan.routes[index]
                val result = when {
                    future.isCancelled -> Result.failure(IllegalStateException("global deadline exceeded"))
                    else -> runCatching { future.get() }.getOrElse { Result.failure(it) }
                }
                if (result.isSuccess) {
                    verified += route
                } else {
                    val error = result.exceptionOrNull()
                    failures[route.domain] = (
                        error?.javaClass?.simpleName.orEmpty() + ": " +
                            error?.message.orEmpty()
                        ).trim().take(MAX_ERROR_CHARS)
                }
            }
            SniGateRouteVerification(
                plan = TlsTerminationPlan(plan.generation, verified),
                attempted = plan.routes.size,
                failures = failures,
            )
        } finally {
            // Future.cancel(true) cannot reliably interrupt Conscrypt's native socket read. Closing
            // the registered transport is the hard cancellation boundary and also releases its fd.
            deadline.close()
            executor.shutdownNow()
            try {
                executor.awaitTermination(WORKER_SHUTDOWN_GRACE_MS, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private fun verifyOne(
        context: SSLContext,
        route: TlsTerminationRoute,
        deadline: RouteVerificationDeadline,
    ): Result<Unit> = runCatching {
        for (verificationDomain in verificationDomainsFor(route)) {
            try {
                verifyDomain(context, route, verificationDomain, deadline)
            } catch (t: Throwable) {
                val failure = if (deadline.isExpired()) {
                    IllegalStateException("global deadline exceeded", t)
                } else {
                    t
                }
                throw IllegalStateException(
                    "$verificationDomain: ${failure.javaClass.simpleName}: ${failure.message.orEmpty()}",
                    failure,
                )
            }
        }
    }

    private fun verifyDomain(
        context: SSLContext,
        route: TlsTerminationRoute,
        verificationDomain: String,
        deadline: RouteVerificationDeadline,
    ) {
        // Keep the raw transport separately so the deadline thread can close the fd without first
        // acquiring any provider-internal SSLSocket handshake monitor.
        val transport = Socket()
        deadline.register(transport)
        try {
            transport.soTimeout = connectTimeoutMs
            transport.connect(route.localAddress, connectTimeoutMs)
            deadline.requireOpen()
            val socket = context.socketFactory.createSocket(
                transport,
                verificationDomain,
                route.localAddress.port,
                false,
            ) as SSLSocket
            try {
                socket.soTimeout = connectTimeoutMs
                socket.sslParameters = socket.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    serverNames = listOf(SNIHostName(verificationDomain))
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        applicationProtocols = arrayOf("h2", "http/1.1")
                    }
                }
                socket.startHandshake()
                check(socket.session.peerCertificates.isNotEmpty()) {
                    "gateway returned no certificate"
                }
                deadline.requireOpen()
            } finally {
                runCatching { socket.close() }
            }
        } finally {
            deadline.unregister(transport)
            runCatching { transport.close() }
        }
    }

    private fun buildSslContext(certificate: File): SSLContext {
        require(certificate.isFile && certificate.length() in 1..MAX_CA_BYTES) {
            "invalid local CA certificate"
        }
        val ca = certificate.inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCertificate(input)
        }
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("github-direct-device-ca", ca)
        }
        val trustManagers = TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(keyStore) }
            .trustManagers
        return SSLContext.getInstance("TLS").apply {
            init(null, trustManagers, SecureRandom())
        }
    }

    companion object {
        private const val MAX_WORKERS = 4
        private const val ROUTE_TIMEOUT_MS = 8_000
        private const val GLOBAL_TIMEOUT_MS = 35_000L
        private const val WORKER_SHUTDOWN_GRACE_MS = 1_000L
        private const val MAX_ERROR_CHARS = 180
        private const val MAX_CA_BYTES = 64L * 1024L
    }
}

/**
 * Thread interruption is only a cooperative cancellation signal. This deadline owns every raw
 * transport used by a verification batch and closes them at the hard cutoff, including transports
 * registered concurrently with expiry.
 */
internal class RouteVerificationDeadline(timeoutMs: Long) : Closeable {
    private val timeoutMs = timeoutMs.also {
        require(it > 0L) { "deadline must be positive" }
    }
    private val lock = Any()
    private val active = LinkedHashSet<Closeable>()
    private var expired = false
    private val scheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "GHD-SniGateDeadline").apply { isDaemon = true }
    }
    private val alarm: ScheduledFuture<*> = scheduler.schedule(
        { expireAndClose() },
        this.timeoutMs,
        TimeUnit.MILLISECONDS,
    )

    fun register(closeable: Closeable) {
        val closeImmediately = synchronized(lock) {
            if (expired) true else {
                active += closeable
                false
            }
        }
        if (closeImmediately) {
            closeQuietly(closeable)
            throw IllegalStateException("global deadline exceeded")
        }
    }

    fun unregister(closeable: Closeable) {
        synchronized(lock) { active -= closeable }
    }

    fun isExpired(): Boolean = synchronized(lock) { expired }

    fun requireOpen() {
        check(!isExpired()) { "global deadline exceeded" }
    }

    override fun close() {
        alarm.cancel(false)
        expireAndClose()
        scheduler.shutdownNow()
    }

    private fun expireAndClose() {
        val closeables = synchronized(lock) {
            if (expired) {
                emptyList()
            } else {
                expired = true
                active.toList().also { active.clear() }
            }
        }
        closeables.forEach(::closeQuietly)
    }

    private fun closeQuietly(closeable: Closeable) {
        runCatching { closeable.close() }
    }
}

/**
 * NO-SNI 后缀用一层代表子域验证固定 IP 的通配证书能力；裸域可能本来就不提供服务，
 * 不能据此否定整个域族。ECH 后缀用裸域验证机制可用性。更深层及实际动态域名仍由
 * sni-gate 按每次真实 SNI 独立查询 ECH、校验证书，不匹配时 fail-close。
 */
internal fun verificationDomainsFor(route: TlsTerminationRoute): List<String> {
    val domain = requireNotNull(DnsNames.normalize(route.domain)) { "invalid route domain" }
    if (!route.includeSubdomains) return listOf(domain)
    if (route.method == TlsTerminationMethod.ECH) return listOf(domain)
    val child = requireNotNull(suffixProbeDomain(domain)) {
        "route domain is too long for representative suffix verification"
    }
    return listOf(child)
}

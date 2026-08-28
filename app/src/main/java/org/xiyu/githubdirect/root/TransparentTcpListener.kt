package org.xiyu.githubdirect.root

import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.net.TlsClientHelloRecords
import org.xiyu.githubdirect.core.routing.EndpointCandidate
import org.xiyu.githubdirect.core.routing.EndpointPlan
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.data.DirectEngine
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.ClosedSelectorException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

interface TcpListener {
    /** 最近一次 start 失败的有界诊断；成功后清空。 */
    val lastFailureDetail: String get() = ""
    fun start(resolveRealIp: (Int) -> ByteArray?): Boolean
    fun stop()
    fun alive(): Boolean
    fun stats(): ListenerStats
    /** 只有 ::1 directPort 已实际监听时才返回 true。 */
    fun ipv6DirectActive(): Boolean = false
    /** 只有 127.0.0.1 directPort 已实际监听时才返回 true。 */
    fun directActive(): Boolean = true
}

data class ListenerStats(
    val acceptedTotal: Long,
    val rejectedTotal: Long,
    val completedSessions: Long,
    val activeSessions: Int,
    /** 无可见可信 SNI 且原 IP 不能唯一归组；可能是 ECH、非 TLS 或截断 ClientHello。 */
    val unclassifiedTlsTotal: Long = 0,
    /** 经已受系统信任的每设备 CA 在本机终止并重建的 TLS 会话。 */
    val terminatedTlsTotal: Long = 0,
)

/**
 * Root TCP 数据面：
 * - vIP 端口保持兼容；
 * - JNI 可用时额外监听 directPort，借 SO_ORIGINAL_DST 接管启用平台的真实/污染 IP；
 * - 先缓冲最多 64 KiB ClientHello，以 SNI/原目的地址选择候选并应用 record 分片；
 * - 无法由启用规则确认的平台流量原样连接原目的地，不进行 TLS 修改。
 */
class TransparentTcpListener(
    private val tcpBasePort: Int = DEFAULT_BASE_PORT,
    private val vipStart: Int = 10,
    private val vipEnd: Int = 254,
    private val remotePort: Int = DEFAULT_REMOTE_PORT,
    private val directPort: Int = DEFAULT_DIRECT_PORT,
    private val connectTimeoutMs: Int = 2500,
    private val idleTimeoutMs: Int = 60_000,
    private val initialHelloTimeoutMs: Int = 1000,
    private val serverHelloTimeoutMs: Int = 1600,
    private val localTerminationTimeoutMs: Int = 3500,
    private val maxSessions: Int = 128,
    private val pumpBufferSize: Int = 8192,
    private val directAvailable: () -> Boolean = {
        OriginalDestination.available() && (DirectEngine.settings()?.isRealIpRedirectEnabled() != false)
    },
    private val adaptiveCandidatesEnabled: () -> Boolean = {
        DirectEngine.settings()?.isAdaptiveCandidatesEnabled() != false
    },
    private val tlsFragmentV2Enabled: () -> Boolean = {
        DirectEngine.settings()?.isTlsFragmentV2Enabled() != false
    },
    private val originalLookup: (Socket) -> InetSocketAddress? = OriginalDestination::lookup,
    private val routeProvider: () -> RouteSnapshot = { DirectEngine.routeSnapshot() },
    private val trustedRelayDomain: (String?) -> Boolean = DirectEngine::isTrustedRelayDomain,
    private val bindRemote: (Socket) -> Unit = { socket -> DirectEngine.binder()?.bindSocket(socket) },
    private val routeOutcome: (String, String, Boolean, Boolean) -> Unit = { domain, address, success, fragmented ->
        DirectEngine.reportRouteOutcome(domain, address, success, fragmented)
    },
    /** 严格 DoH 的短 TTL 精确域地址；仅作本次连接竞速提示，不视为持久已验证候选。 */
    private val runtimeAddresses: (String) -> List<String> = { domain ->
        DirectEngine.relayTable()?.lookup(domain).orEmpty()
    },
    private val tlsTerminationRoute: (String?) -> TlsTerminationRoute? =
        TlsTerminationRouteRegistry::routeFor,
) : TcpListener {

    private class Session(
        val client: Socket,
        val remote: Socket,
        val finishCount: AtomicInteger = AtomicInteger(2),
    )

    private data class InitialData(
        val bytes: ByteArray,
        val inspection: TlsClientHelloRecords.Inspection,
    )

    private data class RouteChoice(
        val domain: String?,
        val original: InetSocketAddress,
        val routeConfirmed: Boolean,
    )

    /** [variant] 只用于允许同一候选采用新的随机 record 布局重试。 */
    internal data class Attempt(val address: String, val fragment: Boolean, val variant: Int = 0)
    private data class Connected(val attempt: Attempt, val socket: Socket)
    private class DoNotRetryAfterServerData(cause: Throwable) : Exception(cause)

    @Volatile private var running = false
    @Volatile
    override var lastFailureDetail: String = ""
        private set
    private var selector: Selector? = null
    private var resolveRealIp: ((Int) -> ByteArray?)? = null
    private val channels = CopyOnWriteArrayList<ServerSocketChannel>()
    private val sessions = ConcurrentHashMap<Session, Boolean>()
    private val pendingClients = ConcurrentHashMap.newKeySet<Socket>()
    private val sessionCount = AtomicInteger(0)
    private val statsAccepted = AtomicLong(0)
    private val statsRejected = AtomicLong(0)
    private val statsCompleted = AtomicLong(0)
    private val statsUnclassified = AtomicLong(0)
    private val statsTerminated = AtomicLong(0)
    @Volatile private var directBound = false
    @Volatile private var directIpv6Bound = false

    @Synchronized
    override fun start(resolveRealIp: (Int) -> ByteArray?): Boolean {
        if (running) return true
        requireNotNull(resolveRealIp)
        require(vipStart in 1..255 && vipEnd in vipStart..255)
        lastFailureDetail = ""
        val sel = try {
            Selector.open()
        } catch (t: Throwable) {
            lastFailureDetail = "selector: ${failureText(t)}"
            return false
        }
        val bound = mutableListOf<ServerSocketChannel>()
        var bindTarget = ""
        try {
            for (vip in vipStart..vipEnd) {
                val port = vipToPort(vip, tcpBasePort)
                bindTarget = "127.0.0.1:$port"
                bind(sel, port, IPV4_LOOPBACK).also(bound::add)
            }
            directBound = directAvailable()
            if (directBound) {
                bindTarget = "127.0.0.1:$directPort"
                bind(sel, directPort, IPV4_LOOPBACK).also(bound::add)
                // IPv6 loopback 与 IPv4 loopback 是不同本地地址，可安全复用同一端口；
                // 失败时先保留 IPv4，RootBackend 会在准备安装 IPv6 规则时拒绝并回滚。
                bindTarget = "[::1]:$directPort"
                directIpv6Bound = runCatching {
                    bind(sel, directPort, IPV6_LOOPBACK).also(bound::add)
                }.onFailure { t ->
                    lastFailureDetail = "$bindTarget: ${failureText(t)}"
                }.isSuccess
            }
        } catch (t: Throwable) {
            lastFailureDetail = "$bindTarget: ${failureText(t)}"
            bound.forEach(::closeQuietly)
            closeQuietly(sel)
            directBound = false
            directIpv6Bound = false
            return false
        }
        this.resolveRealIp = resolveRealIp
        selector = sel
        channels.addAll(bound)
        running = true
        Thread({ selectorLoop(sel) }, "GHD-TcpSelector").apply { isDaemon = true; start() }
        return true
    }

    private fun bind(selector: Selector, port: Int, address: InetAddress): ServerSocketChannel =
        ServerSocketChannel.open().apply {
            setOption(StandardSocketOptions.SO_REUSEADDR, true)
            configureBlocking(false)
            // OUTPUT/REDIRECT 数据面只需要 loopback，禁止暴露到 LAN。
            socket().bind(InetSocketAddress(address, port))
            register(selector, SelectionKey.OP_ACCEPT)
        }

    @Synchronized
    override fun stop() {
        running = false
        closeQuietly(selector)
        selector = null
        channels.forEach(::closeQuietly)
        channels.clear()
        pendingClients.forEach(::closeQuietly)
        pendingClients.clear()
        sessions.keys.forEach { session ->
            closeQuietly(session.client)
            closeQuietly(session.remote)
        }
        sessions.clear()
        sessionCount.set(0)
        directBound = false
        directIpv6Bound = false
    }

    override fun alive(): Boolean = running && selector?.isOpen == true && channels.all { it.isOpen }

    override fun stats(): ListenerStats = ListenerStats(
        acceptedTotal = statsAccepted.get(),
        rejectedTotal = statsRejected.get(),
        completedSessions = statsCompleted.get(),
        activeSessions = sessionCount.get(),
        unclassifiedTlsTotal = statsUnclassified.get(),
        terminatedTlsTotal = statsTerminated.get(),
    )

    fun realDestinationInterceptionActive(): Boolean = directBound

    override fun ipv6DirectActive(): Boolean = directBound && directIpv6Bound

    override fun directActive(): Boolean = directBound

    private fun selectorLoop(sel: Selector) {
        while (running) {
            try {
                if (sel.select(500) == 0) continue
                val iterator = sel.selectedKeys().iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()
                    if (key.isValid && key.isAcceptable) accept(key.channel() as ServerSocketChannel)
                }
            } catch (_: ClosedSelectorException) {
                break
            } catch (_: Throwable) {
            }
        }
    }

    private fun accept(channel: ServerSocketChannel) {
        val accepted = runCatching { channel.accept() }.getOrNull() ?: return
        val client = try {
            // ServerSocketChannel 本身是 non-blocking；accepted channel 明确切回 blocking，
            // 后续双向 pump 直接使用 SocketChannel.read/write 的独立读写锁。
            accepted.configureBlocking(true)
            accepted.socket()
        } catch (_: Throwable) {
            closeQuietly(accepted)
            return
        }
        if (sessionCount.incrementAndGet() > maxSessions) {
            sessionCount.decrementAndGet()
            statsRejected.incrementAndGet()
            closeQuietly(client)
            return
        }
        statsAccepted.incrementAndGet()
        pendingClients += client
        val localPort = client.localPort
        Thread({ bootstrap(client, localPort) }, "GHD-TcpBootstrap").apply { isDaemon = true; start() }
    }

    private fun bootstrap(client: Socket, localPort: Int) {
        var transferredToSession = false
        try {
            client.soTimeout = initialHelloTimeoutMs
            val initial = readInitial(client)
            if (initial.bytes.isEmpty()) throw SocketException("client closed before initial data")
            val vip = portToVip(localPort, tcpBasePort)
            transferredToSession = if (vip >= 0) {
                bootstrapVip(client, vip, initial)
            } else if (directBound && localPort == directPort) {
                bootstrapDirect(client, initial)
            } else {
                false
            }
            if (!transferredToSession) reject()
        } catch (_: Throwable) {
            reject()
        } finally {
            pendingClients.remove(client)
            // 成功路径已把计数所有权移交 Session；显式标志避免极短会话结束后的双重释放竞态。
            if (!transferredToSession) {
                closeQuietly(client)
                sessionCount.decrementAndGet()
            }
        }
    }

    private fun bootstrapVip(client: Socket, vip: Int, initial: InitialData): Boolean {
        val real = resolveRealIp?.invoke(vip) ?: return false
        if (real.size != 4 && real.size != 16) return false
        val address = InetAddress.getByAddress(real).hostAddress ?: return false
        val snapshot = routeProvider()
        val complete = initial.inspection as? TlsClientHelloRecords.Inspection.Complete
        val sni = complete?.serverName
        val plan = sni?.let(snapshot::planFor)
        val trustedSni = trustedRelayDomain(sni)
        if (plan != null || trustedSni) {
            val choice = RouteChoice(
                domain = sni,
                original = InetSocketAddress(address, remotePort),
                routeConfirmed = true,
            )
            // 已发布 TLS 路由已经通过本机 CA、真实上游和原主机名的端到端握手；优先走
            // 该路径，避免浏览器的首次 WebSocket 在直连/分片超时后不再重试。
            val established = tryTlsTermination(client, initial, tlsTerminationRoute(sni))
                ?: establishRoute(client, initial, choice, buildAttempts(choice, snapshot))
                ?: return false
            beginPumps(client, established)
            return true
        }

        // 无法从 ClientHello 归类时保持旧语义：只连接 vIP 映射地址，不扩散到其他候选。
        val socket = connectSingle(address, remotePort, connectTimeoutMs)
            ?: return false
        return try {
            writeInitial(socket, initial.bytes, fragment = tlsFragmentV2Enabled())
            beginPumps(client, socket)
            true
        } catch (t: Throwable) {
            closeQuietly(socket)
            throw t
        }
    }

    private fun bootstrapDirect(client: Socket, initial: InitialData): Boolean {
        val original = originalLookup(client) ?: return false
        // 规则只接管 TCP/443；拒绝任何直接访问监听端口的连接，避免把 relay 暴露成通用代理。
        if (original.port != remotePort) return false
        val snapshot = routeProvider()
        val complete = initial.inspection as? TlsClientHelloRecords.Inspection.Complete
        val sni = complete?.serverName
        val plan = sni?.let(snapshot::planFor)
        val originalAddress = original.address.hostAddress ?: return false
        val exactGroup = uniqueExactEndpointGroup(snapshot, originalAddress)
        val trustedSni = trustedRelayDomain(sni)
        if (sni == null && exactGroup == null) statsUnclassified.incrementAndGet()
        val choice = RouteChoice(
            domain = sni,
            original = original,
            // 可见且命中启用规则的 SNI 即可确认分类；若该域没有专属候选，buildAttempts 只会对
            // 原目的地址分片，不会把它错误改路由到其他域的候选。
            routeConfirmed = plan != null || trustedSni || (sni == null && exactGroup != null),
        )
        if (!choice.routeConfirmed) {
            val remote = connectSingle(originalAddress, original.port, connectTimeoutMs) ?: return false
            return try {
                remote.getOutputStream().apply { write(initial.bytes); flush() }
                beginPumps(client, remote)
                true
            } catch (t: Throwable) {
                closeQuietly(remote)
                throw t
            }
        }

        val attempts = buildAttempts(choice, snapshot)
        val established = tryTlsTermination(client, initial, tlsTerminationRoute(sni))
            ?: establishRoute(client, initial, choice, attempts)
            ?: return false
        beginPumps(client, established)
        return true
    }

    private fun buildAttempts(choice: RouteChoice, snapshot: RouteSnapshot): List<Attempt> {
        val originalAddress = choice.original.address.hostAddress ?: return emptyList()
        if (!adaptiveCandidatesEnabled()) {
            return listOf(Attempt(originalAddress, fragment = tlsFragmentV2Enabled()))
        }
        val candidates: List<EndpointCandidate> = choice.domain?.let(snapshot::candidatesFor).orEmpty()
        val allowFragment = tlsFragmentV2Enabled()
        val runtime = choice.domain?.let(runtimeAddresses)?.asSequence()
            ?.filter { IpAddresses.parseIpAddress(it) != null }
            ?.toList()
            .orEmpty()
        return planAttempts(candidates, runtime, originalAddress, allowFragment)
    }

    /**
     * 已发布的本地 sni-gate 路由是首选：连接只到 loopback，不经过 NetworkBinder；必须观察
     * 到真正的 ServerHello/Handshake record 才向客户端提交任何字节。ECH 不可用、上游证书
     * 不匹配或本地进程失效时返回 null，调用方再回退到候选/分片路径。
     */
    private fun tryTlsTermination(
        client: Socket,
        initial: InitialData,
        route: TlsTerminationRoute?,
    ): Socket? {
        route ?: return null
        val socket = Socket()
        return try {
            socket.connect(route.localAddress, minOf(500, localTerminationTimeoutMs))
            socket.tcpNoDelay = true
            socket.soTimeout = localTerminationTimeoutMs
            socket.getOutputStream().apply {
                write(initial.bytes)
                flush()
            }
            val first = ByteArray(16 * 1024)
            val count = socket.getInputStream().read(first)
            if (!isTlsServerHandshakeRecord(first, count)) {
                closeQuietly(socket)
                return null
            }
            client.getOutputStream().apply {
                write(first, 0, count)
                flush()
            }
            statsTerminated.incrementAndGet()
            socket
        } catch (_: Throwable) {
            closeQuietly(socket)
            null
        }
    }

    private fun establishRoute(
        client: Socket,
        initial: InitialData,
        choice: RouteChoice,
        attempts: List<Attempt>,
    ): Socket? {
        if (attempts.isEmpty()) return null
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(connectTimeoutMs.toLong())
        val raceAttempts = attempts.distinctBy(Attempt::address).take(2)
        val raced = connectRace(raceAttempts, choice.original.port, deadline)
        val attempted = LinkedHashSet<Attempt>()
        if (raced != null) {
            attempted += raced.attempt
            tryEstablished(client, initial, choice, raced, deadline)?.let { return it }
        }
        for (attempt in attempts) {
            if (!attempted.add(attempt)) continue
            if (System.nanoTime() >= deadline) break
            val socket = connectSingle(
                attempt.address,
                choice.original.port,
                remainingMs(deadline),
            ) ?: continue
            tryEstablished(client, initial, choice, Connected(attempt, socket), deadline)?.let { return it }
        }
        return null
    }

    private fun tryEstablished(
        client: Socket,
        initial: InitialData,
        choice: RouteChoice,
        connected: Connected,
        deadline: Long,
    ): Socket? {
        val remote = connected.socket
        var serverBytesObserved = false
        var tlsHandshakeObserved = false
        return try {
            if (System.nanoTime() >= deadline) throw SocketTimeoutException("route deadline exceeded")
            writeInitial(
                remote,
                initial.bytes,
                connected.attempt.fragment,
                connected.attempt.variant,
            )
            remote.soTimeout = minOf(serverHelloTimeoutMs, remainingMs(deadline))
            val first = ByteArray(16 * 1024)
            val count = remote.getInputStream().read(first)
            if (count <= 0) throw SocketException("upstream closed before ServerHello")
            // 从观察到任何服务器数据开始就禁止重试；即使写客户端时失败，也不能冒险
            // 在客户端可能已收到部分字节后切换另一条 TLS 连接。
            serverBytesObserved = true
            tlsHandshakeObserved = isTlsServerHandshakeRecord(first, count)
            client.getOutputStream().apply { write(first, 0, count); flush() }
            choice.domain?.let {
                runCatching {
                    routeOutcome(it, connected.attempt.address, tlsHandshakeObserved, connected.attempt.fragment)
                }
            }
            remote
        } catch (t: Throwable) {
            closeQuietly(remote)
            if (serverBytesObserved) {
                choice.domain?.let {
                    runCatching {
                        routeOutcome(it, connected.attempt.address, tlsHandshakeObserved, connected.attempt.fragment)
                    }
                }
                throw DoNotRetryAfterServerData(t)
            }
            choice.domain?.let {
                runCatching { routeOutcome(it, connected.attempt.address, false, connected.attempt.fragment) }
            }
            null
        }
    }

    /** 第一个候选立即连接，第二个延迟 225ms；首个 TCP 成功者胜。 */
    private fun connectRace(attempts: List<Attempt>, port: Int, deadline: Long): Connected? {
        if (attempts.isEmpty()) return null
        if (attempts.size == 1) {
            return connectSingle(attempts[0].address, port, remainingMs(deadline))
                ?.let { Connected(attempts[0], it) }
        }
        val pool = Executors.newFixedThreadPool(2) { runnable ->
            Thread(runnable, "GHD-ConnectRace").apply { isDaemon = true }
        }
        val open = ConcurrentHashMap.newKeySet<Socket>()
        val won = AtomicBoolean(false)
        val completion = ExecutorCompletionService<Connected?>(pool)
        attempts.take(2).forEachIndexed { index, attempt ->
            completion.submit {
                if (index == 1) Thread.sleep(CONNECT_HEDGE_DELAY_MS)
                val socket = Socket()
                open += socket
                try {
                    bindRemote(socket)
                    socket.connect(InetSocketAddress(attempt.address, port), remainingMs(deadline))
                    socket.tcpNoDelay = true
                    if (won.compareAndSet(false, true)) {
                        // 由调用方接管；在 connectRace finally 中从 open 集合摘除。
                        Connected(attempt, socket)
                    } else {
                        open.remove(socket)
                        closeQuietly(socket)
                        null
                    }
                } catch (_: Throwable) {
                    open.remove(socket)
                    closeQuietly(socket)
                    null
                }
            }
        }
        var selected: Connected? = null
        return try {
            for (ignored in 0 until 2) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) break
                val future = completion.poll(remaining, TimeUnit.NANOSECONDS) ?: break
                val connected = runCatching { future.get() }.getOrNull()
                if (connected != null) {
                    selected = connected
                    break
                }
            }
            selected
        } finally {
            open.filter { it !== selected?.socket }.forEach(::closeQuietly)
            selected?.socket?.let(open::remove)
            pool.shutdownNow()
        }
    }

    private fun connectSingle(address: String, port: Int, timeout: Int): Socket? {
        val socket = Socket()
        return try {
            bindRemote(socket)
            socket.connect(InetSocketAddress(address, port), timeout.coerceAtLeast(1))
            socket.tcpNoDelay = true
            socket
        } catch (_: Throwable) {
            closeQuietly(socket)
            null
        }
    }

    private fun writeInitial(socket: Socket, bytes: ByteArray, fragment: Boolean, variant: Int = 0) {
        val output = socket.getOutputStream()
        val fragmentEntropy = ThreadLocalRandom.current().nextLong() xor variant.toLong()
        val fragmented = if (fragment) {
            TlsClientHelloRecords.fragment(bytes, entropy = fragmentEntropy)
        } else {
            null
        }
        if (fragmented == null) {
            output.write(bytes)
            output.flush()
            return
        }
        val writePlan = TlsClientHelloRecords.tcpWritePlan(
            fragmented.bytes,
            entropy = fragmentEntropy xor WRITE_LAYOUT_ENTROPY_SALT,
        )
        val writeEnds = writePlan.writeEnds
        var start = 0
        for ((index, end) in writeEnds.withIndex()) {
            if (end <= start || end > fragmented.bytes.size) continue
            output.write(fragmented.bytes, start, end - start)
            output.flush()
            start = end
            if (index == writePlan.urgentAfterWriteIndex && start < fragmented.bytes.size) {
                // OOB 不进入 TLS 正常字节流；不支持 urgent data 时保护性退化为纯分片。
                runCatching { socket.sendUrgentData('a'.code) }
            }
            if (start < fragmented.bytes.size) Thread.sleep(TlsClientHelloRecords.WRITE_INTERVAL_MS)
        }
    }

    private fun readInitial(client: Socket): InitialData {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(initialHelloTimeoutMs.toLong())
        var inspection: TlsClientHelloRecords.Inspection = TlsClientHelloRecords.Inspection.NeedMore
        while (output.size() < TlsClientHelloRecords.MAX_CLIENT_HELLO && System.nanoTime() < deadline) {
            client.soTimeout = remainingMs(deadline)
            val remainingCapacity = TlsClientHelloRecords.MAX_CLIENT_HELLO - output.size()
            val count = try {
                client.getInputStream().read(buffer, 0, minOf(buffer.size, remainingCapacity))
            } catch (_: SocketTimeoutException) {
                break
            }
            if (count < 0) break
            output.write(buffer, 0, count)
            inspection = TlsClientHelloRecords.inspect(output.toByteArray())
            if (inspection !is TlsClientHelloRecords.Inspection.NeedMore) break
        }
        return InitialData(output.toByteArray(), inspection)
    }

    private fun beginPumps(client: Socket, remote: Socket) {
        client.soTimeout = idleTimeoutMs
        remote.soTimeout = idleTimeoutMs
        val session = Session(client, remote)
        sessions[session] = true
        Thread({ pumpOneDirection(session, true) }, "GHD-TcpPumpA").apply { isDaemon = true; start() }
        Thread({ pumpOneDirection(session, false) }, "GHD-TcpPumpB").apply { isDaemon = true; start() }
    }

    private fun pumpOneDirection(session: Session, forward: Boolean) {
        try {
            val clientChannel = session.client.channel
            if (clientChannel != null) {
                // Android SocketAdaptor 的 InputStream/OutputStream 共用 SocketChannel.blockingLock：
                // 一侧阻塞 read 会让另一侧永远无法 write。直接调用 channel.read/write 使用
                // 独立读写锁，才能实现真正的 TLS 全双工中继。
                if (forward) {
                    copy(clientChannel, session.remote.getOutputStream())
                } else {
                    copy(session.remote.getInputStream(), clientChannel)
                }
            } else if (forward) {
                copy(session.client.getInputStream(), session.remote.getOutputStream())
            } else {
                copy(session.remote.getInputStream(), session.client.getOutputStream())
            }
        } catch (_: Throwable) {
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
        val buffer = ByteArray(pumpBufferSize)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return
            output.write(buffer, 0, count)
            output.flush()
        }
    }

    private fun copy(input: java.nio.channels.SocketChannel, output: OutputStream) {
        val buffer = ByteBuffer.allocate(pumpBufferSize)
        while (true) {
            buffer.clear()
            val count = input.read(buffer)
            if (count < 0) return
            if (count == 0) continue
            output.write(buffer.array(), 0, count)
            output.flush()
        }
    }

    private fun copy(input: InputStream, output: java.nio.channels.SocketChannel) {
        val bytes = ByteArray(pumpBufferSize)
        while (true) {
            val count = input.read(bytes)
            if (count < 0) return
            val buffer = ByteBuffer.wrap(bytes, 0, count)
            while (buffer.hasRemaining()) output.write(buffer)
        }
    }

    private fun reject() {
        statsRejected.incrementAndGet()
    }

    private fun remainingMs(deadline: Long): Int =
        TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()).toInt().coerceAtLeast(1)

    private fun closeQuietly(closeable: AutoCloseable?) {
        try {
            closeable?.close()
        } catch (_: Throwable) {
        }
    }

    private fun failureText(t: Throwable): String =
        "${t.javaClass.simpleName}: ${t.message.orEmpty()}".trim().take(320)

    companion object {
        private val IPV4_LOOPBACK: InetAddress =
            InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        private val IPV6_LOOPBACK: InetAddress =
            InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
        const val DEFAULT_BASE_PORT = 7000
        const val DEFAULT_REMOTE_PORT = 443
        const val DEFAULT_DIRECT_PORT = 7443
        private const val CONNECT_HEDGE_DELAY_MS = 225L
        private const val MAX_ROUTE_ATTEMPTS = 5
        private const val WRITE_LAYOUT_ENTROPY_SALT = -7046029254386353131L

        fun vipToPort(vip: Int, base: Int = DEFAULT_BASE_PORT): Int = base + vip

        fun portToVip(port: Int, base: Int = DEFAULT_BASE_PORT): Int =
            if (port in base + 10..base + 254) port - base else -1

        internal fun uniqueExactEndpointGroup(
            snapshot: RouteSnapshot,
            address: String,
            now: Long = System.currentTimeMillis(),
        ): String? =
            snapshot.plans.values.asSequence()
                .filter { plan ->
                    plan.candidates.any { candidate ->
                        candidate.address == address && candidate.usable(now)
                    }
                }
                .map(EndpointPlan::endpointGroup)
                .distinct()
                .take(2)
                .toList()
                .singleOrNull()

        internal fun planAttempts(
            candidates: List<EndpointCandidate>,
            runtimeAddresses: List<String>,
            originalAddress: String,
            allowFragment: Boolean,
        ): List<Attempt> {
            val primary = ArrayList<Attempt>()
            val retries = ArrayList<Attempt>()
            val primaryAddresses = LinkedHashSet<String>()
            fun addPrimary(attempt: Attempt) {
                if (primaryAddresses.add(attempt.address)) primary += attempt else retries += attempt
            }

            // 先排列每个 IP 的首次策略，确保 225ms hedge 是不同地址之间竞速，而非同 IP 双连接。
            candidates.asSequence()
                // NO_SNI 候选发送原始 ClientHello 必然退回已知失败路径，只能交给本地终止器。
                .filter { it.capability != RouteCapability.NO_SNI_TLS }
                .map { candidate ->
                    Attempt(
                        candidate.address,
                        allowFragment && candidate.capability != RouteCapability.DIRECT_TLS,
                    )
                }
                .forEach(::addPrimary)

            // 严格 DoH 的同域短 TTL 地址只作为本次连接提示，不提升为已验证候选。
            runtimeAddresses.asSequence()
                .map { Attempt(it, fragment = allowFragment) }
                .forEach(::addPrimary)

            // 浏览器已经选择的原目的地址必须在同 IP 布局重试之前获得一次机会。
            addPrimary(Attempt(originalAddress, fragment = allowFragment))

            // DIRECT 状态可能因网络切换失效；服务器返回任何字节前允许同 IP 分片重试。
            if (allowFragment) {
                retries += candidates.asSequence()
                    .filter { it.capability == RouteCapability.DIRECT_TLS }
                    .map { Attempt(it.address, fragment = true) }
                // 分片规避具有路径/分段时序随机性；FRAGMENTED 候选允许再生成一次布局。
                retries += candidates.asSequence()
                    .filter { it.capability == RouteCapability.FRAGMENTED_TLS }
                    .map { Attempt(it.address, fragment = true, variant = 1) }
            }
            return (primary + retries).distinct().take(MAX_ROUTE_ATTEMPTS)
        }

        /** TLS 1.2/1.3 可继续握手时，服务器对 ClientHello 的首个 record 是 Handshake(22)。 */
        internal fun isTlsServerHandshakeRecord(bytes: ByteArray, count: Int = bytes.size): Boolean =
            count in 1..bytes.size && (bytes[0].toInt() and 0xff) == TLS_CONTENT_TYPE_HANDSHAKE

        fun pump(socketA: Socket, socketB: Socket, idleTimeoutMs: Long, bufferSize: Int = 8192) {
            try {
                socketA.soTimeout = idleTimeoutMs.toInt()
                socketB.soTimeout = idleTimeoutMs.toInt()
            } catch (_: Throwable) {
            }
            val first = Thread({ copyOneWay(socketA, socketB, bufferSize) }, "GHD-PumpA").apply {
                isDaemon = true
            }
            val second = Thread({ copyOneWay(socketB, socketA, bufferSize) }, "GHD-PumpB").apply {
                isDaemon = true
            }
            first.start()
            second.start()
            joinQuietly(first)
            closeStatic(socketA)
            closeStatic(socketB)
            joinQuietly(second)
        }

        private fun copyOneWay(from: Socket, to: Socket, bufferSize: Int) {
            try {
                val buffer = ByteArray(bufferSize)
                while (true) {
                    val count = from.getInputStream().read(buffer)
                    if (count < 0) return
                    to.getOutputStream().apply { write(buffer, 0, count); flush() }
                }
            } catch (_: Throwable) {
            }
        }

        private fun joinQuietly(thread: Thread) {
            try {
                thread.join()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }

        private fun closeStatic(closeable: AutoCloseable?) {
            try {
                closeable?.close()
            } catch (_: Throwable) {
            }
        }

        private const val TLS_CONTENT_TYPE_HANDSHAKE = 22
    }
}

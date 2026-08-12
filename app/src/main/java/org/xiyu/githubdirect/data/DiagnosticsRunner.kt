package org.xiyu.githubdirect.data

import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.net.NetworkBinder
import org.xiyu.githubdirect.core.net.TcpProbe
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.TransportPolicy
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Collections
import java.util.EnumMap
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** 单服务单阶段结果。 */
enum class Stage { RULE, DNS, TCP, TLS, BACKEND, END_TO_END }

enum class StageStatus { PENDING, RUNNING, OK, FAIL, TIMEOUT, SKIPPED }

data class StageResult(
    val stage: Stage,
    val status: StageStatus,
    val detail: String,
    val latencyMs: Long = -1,
)

data class ServiceDiagResult(
    val serviceId: String,
    val displayName: String,
    val stages: Map<Stage, StageResult>,
)

/** 诊断用 DNS 操作（生产实现 [RealDiagOps]；测试注入 fake）。 */
interface DiagDnsOps {
    /** A 查询，返回 IPv4 字符串列表；失败/无有效结果 → null。实现负责自身超时。 */
    fun resolveA(domain: String): List<String>?
}

/** 诊断用 TCP 操作（§55 TCP 阶段）。 */
interface DiagTcpOps {
    /** 探测 ip:port 的 TCP 连通性。 */
    fun probeTcp(ip: String, port: Int, timeoutMs: Long): Boolean
}

/** 诊断用 TLS 操作（§55 TLS 阶段；§56 socket 释放由实现负责）。 */
interface DiagTlsOps {
    /** TLS 握手 + hostname 校验（该域）；成功返回协议版本（如 "TLS1.3"），失败 → null。 */
    fun probeTls(ip: String, domain: String, port: Int, timeoutMs: Long): String?
}

/**
 * 完整诊断执行器（§52-§56）：纯逻辑、UI 无关，依赖全部接口化注入（纯 JVM 可测）。
 *
 * 每服务六阶段链：RULE → DNS → TCP → TLS → BACKEND → END_TO_END
 * - RULE：`registry.match(该服务 testEndpoints 首域)` 命中且 serviceId 一致 → OK（附 transport 名）
 * - DNS：resolveA 成功且 v4 非空 → OK（首个 IP + 延迟）；失败 → FAIL；超过 per-stage 截止 → TIMEOUT
 * - TCP：对解析出的 IP:443 真实探测；DNS 失败/超时 → SKIPPED
 * - TLS：仅 TCP OK 时执行（握手 + hostname 校验）；TCP 失败 → SKIPPED
 * - BACKEND：backendInfo() 非空 → OK（附描述）；空 → FAIL「无后端」
 * - END_TO_END：TCP+TLS 均 OK → OK（延迟和）；否则 SKIPPED
 *
 * 并发模型：单监督者线程（runFull 调用方）+ ExecutorCompletionService，
 * 同一时刻在飞阶段数 ≤ min(concurrency, 服务数)，每个阶段都有独立的 per-stage 截止时间。
 * 单服务异常/超时只标该服务 FAIL/TIMEOUT，不中断整体（partial results）。
 * cancel() 立即终止：中断在飞阶段 + 丢弃未开始任务（executor.shutdownNow）。
 * 不输出任何 HTTP 内容/token/cookie（只网络元数据）。
 */
class DiagnosticsRunner(
    private val registry: RuleRegistry?,        // 可注入 mock
    private val dnsOps: DiagDnsOps,             // 或抽象 DiagOps（生产见 [RealDiagOps]）
    private val tcpProbe: DiagTcpOps,
    private val tlsOps: DiagTlsOps,
    private val backendInfo: () -> String?,     // 当前 backend 描述
    private val executor: ExecutorService,
    private val clock: () -> Long = System::currentTimeMillis,
    private val perStageTimeoutMs: Long = PER_STAGE_TIMEOUT_MS,
    private val overallDeadlineMs: Long = OVERALL_DEADLINE_MS,
    private val concurrency: Int = CONCURRENCY,
) {

    @Volatile
    private var cancelled = false

    @Volatile
    private var running = false

    @Volatile
    private var supervisorThread: Thread? = null

    /** 在飞阶段（cancel 线程与监督者线程共享；仅存已提交未完成的任务）。 */
    private val inFlight = ConcurrentHashMap.newKeySet<Future<StageResult>>()
    private val launchTime = ConcurrentHashMap<Future<StageResult>, Long>()
    private val serviceOf = ConcurrentHashMap<Future<StageResult>, Int>()

    val isRunning: Boolean get() = running

    /** 立即终止：中断在飞阶段 + 丢弃未开始任务。可重复调用，线程安全。 */
    fun cancel() {
        cancelled = true
        for (f in inFlight) {
            try {
                f.cancel(true)
            } catch (_: Throwable) {
            }
        }
        try {
            executor.shutdownNow()
        } catch (_: Throwable) {
        }
        supervisorThread?.interrupt()
    }

    /**
     * 完整诊断：所有启用服务。返回 (results, cancelled)；任何路径都不抛异常。
     * 每完成一个服务回调一次 onProgress(done, total, current)。
     */
    fun runFull(
        onProgress: (done: Int, total: Int, current: ServiceDiagResult) -> Unit,
    ): Pair<List<ServiceDiagResult>, Boolean> {
        if (running) return emptyList<ServiceDiagResult>() to false
        val targets = resolveTargets()
        if (targets.isEmpty()) return emptyList<ServiceDiagResult>() to false
        cancelled = false
        running = true
        supervisorThread = Thread.currentThread()
        return try {
            supervise(targets, onProgress)
        } finally {
            running = false
            supervisorThread = null
        }
    }

    // ==================== 服务列表与阶段执行 ====================

    private class Target(val serviceId: String, val displayName: String, val domain: String?)

    private class ServiceState(val target: Target) {
        val results = EnumMap<Stage, StageResult>(Stage::class.java)
        var stageIndex = 0
        var dnsIp: String? = null
        var ruleOk = false
        var tcpOk = false
        var tlsOk = false
    }

    private fun resolveTargets(): List<Target> {
        val reg = registry ?: return emptyList()
        val out = ArrayList<Target>()
        for (p in reg.enabledProfiles()) {
            val domain = p.testEndpoints.firstOrNull()
                ?.let { extractDomain(it) }
                ?.let { DnsNames.normalize(it) }
            out.add(Target(p.id, p.displayName, domain))
        }
        return out
    }

    /** 从 testEndpoint（可能带 scheme/路径/端口）提取裸域名（纯函数）。 */
    private fun extractDomain(raw: String): String? {
        var s = raw.trim()
        val scheme = s.indexOf("://")
        if (scheme >= 0) s = s.substring(scheme + 3)
        val slash = s.indexOf('/')
        if (slash >= 0) s = s.substring(0, slash)
        val query = s.indexOf('?')
        if (query >= 0) s = s.substring(0, query)
        val port = s.indexOf(':')
        if (port >= 0) s = s.substring(0, port)
        return if (s.isEmpty()) null else s
    }

    private fun transportShort(t: TransportPolicy): String = when (t) {
        TransportPolicy.CLEAN_DNS -> "clean"
        TransportPolicy.DIRECT_IP -> "direct"
        TransportPolicy.TLS_FRAGMENT_RELAY -> "relay"
        TransportPolicy.NXDOMAIN -> "block"
        TransportPolicy.PASSTHROUGH -> "passthrough"
    }

    /** 监督者：CompletionService 调度 + per-stage 截止 + 整体 deadline + 取消。 */
    private fun supervise(
        targets: List<Target>,
        onProgress: (done: Int, total: Int, current: ServiceDiagResult) -> Unit,
    ): Pair<List<ServiceDiagResult>, Boolean> {
        val n = targets.size
        val completion = ExecutorCompletionService<StageResult>(executor)
        val states = targets.map { ServiceState(it) }
        val results = arrayOfNulls<ServiceDiagResult>(n)
        val pending = ArrayDeque<Int>()
        for (i in 0 until n) pending.addLast(i)
        val limit = minOf(concurrency, n)
        val overallDeadline = clock() + overallDeadlineMs
        var doneCount = 0

        /** 收尾一个服务（正常 / 取消 / 中止共用）：补齐剩余阶段并回调进度。 */
        fun finalizeService(i: Int, cancelledOut: Boolean) {
            if (results[i] != null) return
            val st = states[i]
            while (st.stageIndex < STAGES.size) {
                val stage = STAGES[st.stageIndex]
                if (!st.results.containsKey(stage)) {
                    st.results[stage] = StageResult(
                        stage, StageStatus.SKIPPED,
                        if (cancelledOut) "已取消" else "已中止", 0,
                    )
                }
                st.stageIndex++
            }
            doneCount++
            results[i] = ServiceDiagResult(
                st.target.serviceId, st.target.displayName,
                Collections.unmodifiableMap(EnumMap(st.results)),
            )
            onProgress(doneCount, n, results[i]!!)
        }

        /** 提交服务 i 的下一个阶段。executor 已关闭（cancel 竞态）→ 该服务后续阶段全部标已取消。 */
        fun launch(i: Int) {
            val st = states[i]
            if (st.stageIndex >= STAGES.size) return
            val stage = STAGES[st.stageIndex]
            val f = try {
                completion.submit(Callable { runStage(st, stage) })
            } catch (t: Throwable) {
                while (st.stageIndex < STAGES.size) {
                    st.results[STAGES[st.stageIndex]] =
                        StageResult(STAGES[st.stageIndex], StageStatus.SKIPPED, "已取消", 0)
                    st.stageIndex++
                }
                return
            }
            inFlight.add(f)
            serviceOf[f] = i
            launchTime[f] = clock()
        }

        /** 管道填充：未开始的服务最多 limit 个在飞。 */
        fun fill() {
            while (pending.isNotEmpty() && inFlight.size < limit) {
                launch(pending.removeFirst())
            }
        }

        var cancelledOut = false
        try {
            fill()
            while (doneCount < n && !cancelled) {
                if (inFlight.isEmpty()) break // 防御（fill 保证管道非空）
                val now = clock()
                if (now >= overallDeadline) break
                // 等待窗口：整体 deadline 与所有在飞阶段的 per-stage 截止取最近
                var waitMs = overallDeadline - now
                for (f in inFlight) {
                    val stageDeadline = (launchTime[f] ?: now) + perStageTimeoutMs
                    if (stageDeadline <= now) {
                        waitMs = 0
                        break
                    }
                    waitMs = minOf(waitMs, stageDeadline - now)
                }
                val completed = try {
                    completion.poll(maxOf(waitMs, 1L), TimeUnit.MILLISECONDS)
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    null
                }
                if (cancelled) break
                if (completed == null) {
                    if (clock() >= overallDeadline) break
                    // 有阶段超过 per-stage 截止 → 只标该服务 TIMEOUT，其余服务继续（partial）
                    val now2 = clock()
                    val overdue = inFlight.filter {
                        now2 - (launchTime[it] ?: now2) >= perStageTimeoutMs
                    }
                    if (overdue.isEmpty()) continue // 防御
                    for (fut in overdue) {
                        inFlight.remove(fut)
                        try {
                            fut.cancel(true)
                        } catch (_: Throwable) {
                        }
                        val i = serviceOf.remove(fut) ?: continue
                        val st = states[i]
                        val stage = STAGES[st.stageIndex]
                        st.results[stage] = StageResult(stage, StageStatus.TIMEOUT, "超时", perStageTimeoutMs)
                        st.stageIndex++
                        launch(i)
                    }
                    continue
                }
                // 一个阶段完成
                inFlight.remove(completed)
                val i = serviceOf.remove(completed) ?: continue
                val st = states[i]
                val stage = STAGES[st.stageIndex]
                val outcome = try {
                    completed.get()
                } catch (t: Throwable) {
                    StageResult(stage, StageStatus.FAIL, "已取消", 0)
                }
                st.results[stage] = outcome
                st.stageIndex++
                if (st.stageIndex >= STAGES.size) {
                    finalizeService(i, cancelledOut)
                } else {
                    launch(i)
                }
                fill()
            }
            if (doneCount < n) {
                cancelledOut = cancelled
                for (i in 0 until n) {
                    finalizeService(i, cancelledOut)
                }
            }
        } catch (t: Throwable) {
            // 监督者异常不外抛：已完成的保留，未完成的按中止标记（partial results）
            cancelledOut = true
            for (i in 0 until n) {
                try {
                    finalizeService(i, cancelledOut)
                } catch (_: Throwable) {
                }
            }
        } finally {
            for (f in inFlight) {
                try {
                    f.cancel(true)
                } catch (_: Throwable) {
                }
            }
            inFlight.clear()
            launchTime.clear()
            serviceOf.clear()
        }
        // 防御：任何路径下每个服务都必然有结果（finalize 幂等 + 兜底空 stages）
        return (0 until n).map { i ->
            results[i] ?: ServiceDiagResult(
                targets[i].serviceId, targets[i].displayName, emptyMap()
            )
        } to cancelledOut
    }

    /** 单阶段执行（不抛异常；op 自身异常 → FAIL）。 */
    private fun runStage(st: ServiceState, stage: Stage): StageResult = try {
        when (stage) {
            Stage.RULE -> ruleStage(st)
            Stage.DNS -> dnsStage(st)
            Stage.TCP -> tcpStage(st)
            Stage.TLS -> tlsStage(st)
            Stage.BACKEND -> backendStage()
            Stage.END_TO_END -> e2eStage(st)
        }
    } catch (t: Throwable) {
        StageResult(stage, StageStatus.FAIL, "异常: ${t.message ?: t.javaClass.simpleName}", 0)
    }

    private fun ruleStage(st: ServiceState): StageResult {
        val domain = st.target.domain
        if (domain == null) return StageResult(Stage.RULE, StageStatus.FAIL, "无测试端点", 0)
        val reg = registry
        if (reg == null) return StageResult(Stage.RULE, StageStatus.FAIL, "规则引擎不可用", 0)
        val start = clock()
        val match = reg.match(domain)
        val ms = clock() - start
        if (match == null) return StageResult(Stage.RULE, StageStatus.FAIL, "规则未命中", ms)
        if (match.serviceId != st.target.serviceId) {
            val other = reg.profile(match.serviceId)?.displayName ?: match.serviceId
            return StageResult(Stage.RULE, StageStatus.FAIL, "命中其他服务($other)", ms)
        }
        st.ruleOk = true
        return StageResult(Stage.RULE, StageStatus.OK, "MATCH(${transportShort(match.policy.transport)})", ms)
    }

    private fun dnsStage(st: ServiceState): StageResult {
        val domain = st.target.domain
        if (domain == null) return StageResult(Stage.DNS, StageStatus.SKIPPED, "无测试端点", 0)
        val start = clock()
        val v4 = dnsOps.resolveA(domain)
        val ms = clock() - start
        if (v4 == null || v4.isEmpty()) return StageResult(Stage.DNS, StageStatus.FAIL, "解析失败", ms)
        st.dnsIp = v4.first()
        return StageResult(Stage.DNS, StageStatus.OK, v4.first(), ms)
    }

    private fun tcpStage(st: ServiceState): StageResult {
        val ip = st.dnsIp
        if (ip == null) return StageResult(Stage.TCP, StageStatus.SKIPPED, "DNS 未通过", 0)
        val start = clock()
        val ok = tcpProbe.probeTcp(ip, TCP_PORT, TCP_PROBE_TIMEOUT_MS)
        val ms = clock() - start
        st.tcpOk = ok
        return if (ok) StageResult(Stage.TCP, StageStatus.OK, ip, ms)
        else StageResult(Stage.TCP, StageStatus.FAIL, "连接失败", ms)
    }

    private fun tlsStage(st: ServiceState): StageResult {
        if (!st.tcpOk) return StageResult(Stage.TLS, StageStatus.SKIPPED, "TCP 未通过", 0)
        val ip = st.dnsIp ?: return StageResult(Stage.TLS, StageStatus.SKIPPED, "无 IP", 0)
        val domain = st.target.domain ?: return StageResult(Stage.TLS, StageStatus.SKIPPED, "无测试端点", 0)
        val start = clock()
        val proto = tlsOps.probeTls(ip, domain, TCP_PORT, TLS_PROBE_TIMEOUT_MS)
        val ms = clock() - start
        st.tlsOk = proto != null
        return if (proto != null) StageResult(Stage.TLS, StageStatus.OK, proto, ms)
        else StageResult(Stage.TLS, StageStatus.FAIL, "握手失败", ms)
    }

    private fun backendStage(): StageResult {
        val start = clock()
        val info = backendInfo()
        val ms = clock() - start
        return if (info != null && info.isNotBlank()) StageResult(Stage.BACKEND, StageStatus.OK, info, ms)
        else StageResult(Stage.BACKEND, StageStatus.FAIL, "无后端", ms)
    }

    private fun e2eStage(st: ServiceState): StageResult {
        if (!st.tcpOk || !st.tlsOk) return StageResult(Stage.END_TO_END, StageStatus.SKIPPED, "前置未通过", 0)
        val tcpLat = st.results[Stage.TCP]?.latencyMs ?: 0
        val tlsLat = st.results[Stage.TLS]?.latencyMs ?: 0
        return StageResult(Stage.END_TO_END, StageStatus.OK, "", (tcpLat + tlsLat).coerceAtLeast(0))
    }

    companion object {
        const val CONCURRENCY = 4
        const val PER_STAGE_TIMEOUT_MS = 8_000L
        const val OVERALL_DEADLINE_MS = 120_000L
        const val TCP_PROBE_TIMEOUT_MS = 3_000L
        const val TLS_PROBE_TIMEOUT_MS = 5_000L

        private const val TCP_PORT = 443
        private val STAGES = Stage.values()
    }
}

/**
 * 生产 DiagOps（§55/§56）：真实 DNS/TCP/TLS 探测。
 * - DNS：注入的 [EndpointResolver]（MainActivity 以短超时 + 单服务器构造，避免多服务器回退拖过 per-stage）
 * - TCP：[TcpProbe]（绑 NetworkBinder 防环回）
 * - TLS：SSLSocket 连接 + startHandshake + hostnameVerifier（该域）；socket 全部 finally close
 */
class RealDiagOps(
    private val resolver: EndpointResolver?,
    private val binder: NetworkBinder?,
) : DiagDnsOps, DiagTcpOps, DiagTlsOps {

    override fun resolveA(domain: String): List<String>? {
        val r = resolver ?: return null
        val v4 = r.resolveA(domain, null) ?: return null
        if (v4.isEmpty()) return null
        return v4.map { IpAddresses.ipv4ToString(it) }
    }

    override fun probeTcp(ip: String, port: Int, timeoutMs: Long): Boolean {
        val b = binder ?: return false
        return TcpProbe.isTcpReachable(ip, port, timeoutMs.toInt(), b)
    }

    override fun probeTls(ip: String, domain: String, port: Int, timeoutMs: Long): String? {
        val addrBytes = IpAddresses.parseIpv4(ip) ?: return null
        var ssl: SSLSocket? = null
        try {
            // Android SSLSocketFactory 无分层 createSocket(Socket,...)；未连接创建 + 绑网 + connect
            ssl = SSLSocketFactory.getDefault().createSocket() as? SSLSocket
            if (ssl == null) return null
            binder?.bindSocket(ssl) // 防环回（VPN 进程绑底层物理网络）
            ssl.connect(InetSocketAddress(InetAddress.getByAddress(addrBytes), port), TLS_CONNECT_TIMEOUT_MS)
            ssl.soTimeout = timeoutMs.toInt()
            ssl.startHandshake()
            val verified = try {
                HttpsURLConnection.getDefaultHostnameVerifier().verify(domain, ssl.session)
            } catch (t: Throwable) {
                false
            }
            if (!verified) return null
            val p = ssl.session.protocol ?: return null
            return if (p.startsWith("TLSv")) "TLS" + p.removePrefix("TLSv") else p
        } catch (t: Throwable) {
            return null
        } finally {
            // §56：socket 释放（finally close 兜底，任何路径不泄漏）
            try {
                ssl?.close()
            } catch (_: Throwable) {
            }
        }
    }

    companion object {
        private const val TLS_CONNECT_TIMEOUT_MS = 2_500
    }
}

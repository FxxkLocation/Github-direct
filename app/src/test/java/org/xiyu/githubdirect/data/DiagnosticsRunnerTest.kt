package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.rules.DomainRule
import org.xiyu.githubdirect.core.rules.ExactMatcher
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.TransportPolicy
import org.xiyu.githubdirect.test.InMemorySettingsStore
import org.xiyu.githubdirect.test.buildRegistry
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * DiagnosticsRunner 纯 JVM 测试：依赖全部接口化注入（fake DiagOps / 真实小线程池 / 假 backend），
 * 不真联网。验证六阶段链、SKIPPED 语义、per-stage 超时 partial、cancel、进度回调与全失败不抛。
 */
class DiagnosticsRunnerTest {

    // ==================== fakes ====================

    private class FakeDns(private val impl: (String) -> List<String>?) : DiagDnsOps {
        override fun resolveA(domain: String): List<String>? = impl(domain)
    }

    private class FakeTcp(private val impl: (String, Int) -> Boolean) : DiagTcpOps {
        val calls = ArrayList<Pair<String, Int>>()

        override fun probeTcp(ip: String, port: Int, timeoutMs: Long): Boolean {
            calls.add(ip to port)
            return impl(ip, port)
        }
    }

    private class FakeTls(private val impl: (String, String) -> String?) : DiagTlsOps {
        val calls = ArrayList<Pair<String, String>>()

        override fun probeTls(ip: String, domain: String, port: Int, timeoutMs: Long): String? {
            calls.add(ip to domain)
            return impl(ip, domain)
        }
    }

    private fun profile(
        id: String,
        name: String,
        endpoint: String,
        transport: TransportPolicy = TransportPolicy.TLS_FRAGMENT_RELAY,
        ruleDomain: String? = null,
        priority: Int = 10,
    ): ServiceProfile {
        val endpointDomain = endpoint.substring(
            endpoint.indexOf("//") + 2,
            endpoint.indexOf("/", endpoint.indexOf("//") + 2),
        )
        return ServiceProfile(
            id = id,
            displayName = name,
            category = "test",
            enabledByDefault = true,
            priority = priority,
            domains = listOf(
                DomainRule(id = "$id-r", matcher = ExactMatcher(ruleDomain ?: endpointDomain), transport = transport)
            ),
            testEndpoints = listOf(endpoint),
        )
    }

    private fun registryOf(vararg ps: ServiceProfile): RuleRegistry =
        buildRegistry(InMemorySettingsStore(), *ps)

    private fun buildRunner(
        registry: RuleRegistry?,
        dns: DiagDnsOps,
        tcp: DiagTcpOps = FakeTcp { _, _ -> true },
        tls: DiagTlsOps = FakeTls { _, _ -> "TLS1.3" },
        backend: () -> String? = { "Root Transparent ACTIVE" },
        perStage: Long = 2_000,
        deadline: Long = 15_000,
    ): Pair<DiagnosticsRunner, ExecutorService> {
        val ex = Executors.newFixedThreadPool(2)
        val r = DiagnosticsRunner(
            registry = registry,
            dnsOps = dns,
            tcpProbe = tcp,
            tlsOps = tls,
            backendInfo = backend,
            executor = ex,
            perStageTimeoutMs = perStage,
            overallDeadlineMs = deadline,
        )
        return r to ex
    }

    private fun stages(r: ServiceDiagResult) = r.stages

    // ==================== 测试 ====================

    /** 规则命中 → RULE OK 附 transport 名；未命中/命中其他服务 → RULE FAIL；其余阶段不受影响。 */
    @Test
    fun testRuleHitAndMiss() {
        // 命中两态：relay / clean
        val reg = registryOf(
            profile("svcA", "Svc A", "https://a.example.com/", TransportPolicy.TLS_FRAGMENT_RELAY),
            profile("svcB", "Svc B", "https://b.example.com/", TransportPolicy.CLEAN_DNS),
        )
        val (runner, ex) = buildRunner(reg, FakeDns({ listOf("1.2.3.4") }),
            FakeTcp({ _, _ -> true }), FakeTls({ _, _ -> "TLS1.3" }))
        try {
            val (results, cancelled) = runner.runFull { _, _, _ -> }
            assertFalse(cancelled)
            assertEquals(2, results.size)
            val a = results.first { it.serviceId == "svcA" }
            assertEquals(StageStatus.OK, stages(a)[Stage.RULE]?.status)
            assertEquals("MATCH(relay)", stages(a)[Stage.RULE]?.detail)
            val b = results.first { it.serviceId == "svcB" }
            assertEquals(StageStatus.OK, stages(b)[Stage.RULE]?.status)
            assertEquals("MATCH(clean)", stages(b)[Stage.RULE]?.detail)
            assertEquals(StageStatus.OK, stages(a)[Stage.DNS]?.status)
        } finally {
            ex.shutdownNow()
        }

        // 未命中：testEndpoint 域不属于任何启用规则
        val regMiss = registryOf(
            profile("svcA", "Svc A", "https://nope.example.com/", ruleDomain = "a.example.com")
        )
        val (runner2, ex2) = buildRunner(regMiss, FakeDns({ listOf("1.2.3.4") }))
        try {
            val (results2, _) = runner2.runFull { _, _, _ -> }
            val a2 = results2.single()
            assertEquals(StageStatus.FAIL, stages(a2)[Stage.RULE]?.status)
            assertEquals("规则未命中", stages(a2)[Stage.RULE]?.detail)
            // 规则未命中不阻塞后续网络诊断
            assertEquals(StageStatus.OK, stages(a2)[Stage.DNS]?.status)
        } finally {
            ex2.shutdownNow()
        }

        // 命中其他服务：svcB 优先级更高，svcA 的测试端点命中 svcB 的规则
        val regCross = registryOf(
            profile("svcA", "Svc A", "https://b.example.com/", ruleDomain = "a.example.com", priority = 10),
            profile("svcB", "Svc B", "https://b.example.com/", ruleDomain = "b.example.com", priority = 20),
        )
        val (runner3, ex3) = buildRunner(regCross, FakeDns({ listOf("1.2.3.4") }))
        try {
            val (results3, _) = runner3.runFull { _, _, _ -> }
            val a3 = results3.first { it.serviceId == "svcA" }
            assertEquals(StageStatus.FAIL, stages(a3)[Stage.RULE]?.status)
            assertEquals("命中其他服务(Svc B)", stages(a3)[Stage.RULE]?.detail)
        } finally {
            ex3.shutdownNow()
        }
    }

    /** DNS 成功 → TCP 用解析出的 IP 执行；DNS 失败 → TCP/TLS SKIPPED 且不再探测。 */
    @Test
    fun testDnsSuccessRunsTcp_dnsFailSkipsTcp() {
        val reg = registryOf(
            profile("svcA", "Svc A", "https://a.example.com/"),
            profile("svcB", "Svc B", "https://b.example.com/"),
        )
        val dns = FakeDns { if (it == "a.example.com") listOf("9.8.7.6") else null }
        val tcp = FakeTcp({ _, _ -> true })
        val tls = FakeTls({ _, _ -> "TLS1.3" })
        val (runner, ex) = buildRunner(reg, dns, tcp, tls)
        try {
            val (results, cancelled) = runner.runFull { _, _, _ -> }
            assertFalse(cancelled)
            val a = results.first { it.serviceId == "svcA" }
            assertEquals(StageStatus.OK, stages(a)[Stage.DNS]?.status)
            assertEquals("9.8.7.6", stages(a)[Stage.DNS]?.detail)
            assertEquals(StageStatus.OK, stages(a)[Stage.TCP]?.status)
            assertEquals(StageStatus.OK, stages(a)[Stage.TLS]?.status)
            assertEquals(StageStatus.OK, stages(a)[Stage.END_TO_END]?.status)

            val b = results.first { it.serviceId == "svcB" }
            assertEquals(StageStatus.FAIL, stages(b)[Stage.DNS]?.status)
            assertEquals(StageStatus.SKIPPED, stages(b)[Stage.TCP]?.status)
            assertEquals(StageStatus.SKIPPED, stages(b)[Stage.TLS]?.status)
            assertEquals(StageStatus.SKIPPED, stages(b)[Stage.END_TO_END]?.status)

            // TCP 只对成功解析的 IP 探测（svcA 一次，且 IP 正确）
            assertEquals(1, tcp.calls.size)
            assertEquals("9.8.7.6" to 443, tcp.calls[0])
            assertEquals(1, tls.calls.size)
        } finally {
            ex.shutdownNow()
        }
    }

    /** TLS 仅在 TCP OK 后执行；TCP FAIL → TLS SKIPPED 且不握手。 */
    @Test
    fun testTlsOnlyAfterTcpOk() {
        val reg = registryOf(
            profile("svcA", "Svc A", "https://a.example.com/"),
            profile("svcB", "Svc B", "https://b.example.com/"),
        )
        val dns = FakeDns { domain ->
            if (domain == "a.example.com") listOf("1.1.1.1") else listOf("2.2.2.2")
        }
        val tcp = FakeTcp({ ip, _ -> ip == "2.2.2.2" })
        val tls = FakeTls({ _, _ -> "TLS1.2" })
        val (runner, ex) = buildRunner(reg, dns, tcp, tls)
        try {
            val (results, _) = runner.runFull { _, _, _ -> }
            val a = results.first { it.serviceId == "svcA" }
            assertEquals(StageStatus.FAIL, stages(a)[Stage.TCP]?.status)
            assertEquals(StageStatus.SKIPPED, stages(a)[Stage.TLS]?.status)
            assertEquals(StageStatus.SKIPPED, stages(a)[Stage.END_TO_END]?.status)

            val b = results.first { it.serviceId == "svcB" }
            assertEquals(StageStatus.OK, stages(b)[Stage.TCP]?.status)
            assertEquals(StageStatus.OK, stages(b)[Stage.TLS]?.status)
            assertEquals("TLS1.2", stages(b)[Stage.TLS]?.detail)
            assertEquals(StageStatus.OK, stages(b)[Stage.END_TO_END]?.status)
            assertEquals(0, tls.calls.count { it.second == "a.example.com" })
            assertEquals(1, tls.calls.count { it.second == "b.example.com" })
        } finally {
            ex.shutdownNow()
        }
    }

    /** 单服务 per-stage 超时只标该服务 TIMEOUT，其他服务正常完成（partial results）。 */
    @Test
    fun testSingleServiceTimeoutMarksOnlyThatService() {
        val reg = registryOf(
            profile("svcA", "Svc A", "https://a.example.com/"),
            profile("svcB", "Svc B", "https://b.example.com/"),
        )
        val block = CountDownLatch(1)
        val dns = FakeDns { domain ->
            if (domain == "a.example.com") {
                try {
                    block.await() // 阻塞直到被 cancel 中断
                } catch (ie: InterruptedException) {
                    // 被中断：监督者已按 TIMEOUT 记录
                }
                null
            } else {
                listOf("1.2.3.4")
            }
        }
        val (runner, ex) = buildRunner(reg, dns, FakeTcp({ _, _ -> true }), FakeTls({ _, _ -> "TLS1.3" }),
            perStage = 300, deadline = 5_000)
        try {
            val (results, cancelled) = runner.runFull { _, _, _ -> }
            assertFalse(cancelled)
            assertEquals(2, results.size)

            val a = results.first { it.serviceId == "svcA" }
            assertEquals(StageStatus.TIMEOUT, stages(a)[Stage.DNS]?.status)
            assertEquals("超时", stages(a)[Stage.DNS]?.detail)
            assertEquals(StageStatus.SKIPPED, stages(a)[Stage.TCP]?.status)
            assertEquals(StageStatus.SKIPPED, stages(a)[Stage.TLS]?.status)
            assertEquals(StageStatus.SKIPPED, stages(a)[Stage.END_TO_END]?.status)

            val b = results.first { it.serviceId == "svcB" }
            assertEquals(StageStatus.OK, stages(b)[Stage.DNS]?.status)
            assertEquals(StageStatus.OK, stages(b)[Stage.TCP]?.status)
            assertEquals(StageStatus.OK, stages(b)[Stage.TLS]?.status)
            assertEquals(StageStatus.OK, stages(b)[Stage.END_TO_END]?.status)
        } finally {
            block.countDown()
            ex.shutdownNow()
        }
    }

    /** cancel：未开始的服务不执行；返回 cancelled=true；已开始的阶段被中断。 */
    @Test
    fun testCancelStopsRemainingServices() {
        val reg = registryOf(
            profile("svcA", "Svc A", "https://a.example.com/"),
            profile("svcB", "Svc B", "https://b.example.com/"),
            profile("svcC", "Svc C", "https://c.example.com/"),
        )
        // concurrency=2 → 只有 A/B 启动；C 保持未开始
        val blockA = CountDownLatch(1)
        val blockB = CountDownLatch(1)
        val startedA = CountDownLatch(1)
        val startedB = CountDownLatch(1)
        val interruptA = AtomicBoolean(false)
        val interruptB = AtomicBoolean(false)
        val dns = FakeDns { domain ->
            if (domain == "a.example.com") {
                startedA.countDown()
                try {
                    blockA.await()
                } catch (ie: InterruptedException) {
                    interruptA.set(true)
                }
                null
            } else if (domain == "b.example.com") {
                startedB.countDown()
                try {
                    blockB.await()
                } catch (ie: InterruptedException) {
                    interruptB.set(true)
                }
                null
            } else {
                listOf("5.6.7.8")
            }
        }
        val ex = Executors.newFixedThreadPool(2)
        val runner = DiagnosticsRunner(
            registry = reg, dnsOps = dns,
            tcpProbe = FakeTcp({ _, _ -> true }),
            tlsOps = FakeTls({ _, _ -> "TLS1.3" }),
            backendInfo = { "VPN ACTIVE" },
            executor = ex,
            perStageTimeoutMs = 2_000,
            overallDeadlineMs = 60_000,
            concurrency = 2,
        )
        var pair: Pair<List<ServiceDiagResult>, Boolean>? = null
        val thread = Thread {
            pair = runner.runFull { _, _, _ -> }
        }
        thread.start()
        try {
            // 两个已启动服务的 DNS 都进入阻塞后，C 仍未被调度
            assertTrue("svcA 的 DNS 应已启动", startedA.await(3, TimeUnit.SECONDS))
            assertTrue("svcB 的 DNS 应已启动", startedB.await(3, TimeUnit.SECONDS))
            runner.cancel()
            thread.join(5_000)
            assertFalse("诊断线程应在 cancel 后退出", thread.isAlive)

            val (results, cancelled) = pair!!
            assertTrue(cancelled)
            assertEquals(3, results.size)

            // A/B：已开始的阶段被中断（RULE 已完成，DNS 被中断后按取消标记）
            for (id in listOf("svcA", "svcB")) {
                val s = results.first { it.serviceId == id }
                assertEquals(StageStatus.OK, stages(s)[Stage.RULE]?.status)
                assertEquals(StageStatus.SKIPPED, stages(s)[Stage.DNS]?.status)
                assertEquals(StageStatus.SKIPPED, stages(s)[Stage.TCP]?.status)
                assertEquals(StageStatus.SKIPPED, stages(s)[Stage.END_TO_END]?.status)
            }
            // 已开始的阶段被中断：interrupt 传递到 op 线程是异步的（launch 先 submit 后
            // 入 inFlight 的窗口内 cancel 可能只经 shutdownNow 间接中断），此处有界轮询
            // 等待"最终收到中断"，避免与 op 线程的调度竞态（完整套件下曾 flaky）。
            // 若 runner 取消逻辑真的失效，上面的 thread.join(5000) 断言会先失败，此轮询不会掩盖。
            val interruptDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while ((!interruptA.get() || !interruptB.get()) && System.nanoTime() < interruptDeadline) {
                Thread.sleep(1)
            }
            assertTrue("阻塞中的 svcA DNS op 应收到中断", interruptA.get())
            assertTrue("阻塞中的 svcB DNS op 应收到中断", interruptB.get())

            // C：未开始的服务完全不执行（全部 SKIPPED）
            val c = results.first { it.serviceId == "svcC" }
            assertEquals(StageStatus.SKIPPED, stages(c)[Stage.RULE]?.status)
            assertTrue(stages(c).values.all { it.status == StageStatus.SKIPPED })
        } finally {
            blockA.countDown()
            blockB.countDown()
            ex.shutdownNow()
        }
    }

    /** 进度回调次数 == 完成服务数，done 递增 1..n。 */
    @Test
    fun testProgressCallbackCount() {
        val reg = registryOf(
            profile("svcA", "Svc A", "https://a.example.com/"),
            profile("svcB", "Svc B", "https://b.example.com/"),
            profile("svcC", "Svc C", "https://c.example.com/"),
        )
        val dns = FakeDns { listOf("1.2.3.4") }
        val (runner, ex) = buildRunner(reg, dns)
        try {
            val seen = AtomicInteger(0)
            val names = ArrayList<String>()
            val (results, _) = runner.runFull { done, total, current ->
                seen.incrementAndGet()
                assertEquals(3, total)
                assertEquals(seen.get(), done)
                names.add(current.displayName)
            }
            assertEquals(3, seen.get())
            assertEquals(3, results.size)
            assertEquals(3, names.size)
            assertTrue(names.containsAll(listOf("Svc A", "Svc B", "Svc C")))
        } finally {
            ex.shutdownNow()
        }
    }

    /** 全部失败（op 抛异常 / 无后端）不抛异常，返回 FAIL/SKIPPED 状态。 */
    @Test
    fun testAllFailuresDoNotThrow() {
        val reg = registryOf(
            profile("svcA", "Svc A", "https://a.example.com/"),
            profile("svcB", "Svc B", "https://b.example.com/"),
        )
        val dns = FakeDns { throw RuntimeException("dns boom") }
        val tcp = FakeTcp { _, _ -> throw RuntimeException("tcp boom") }
        val tls = FakeTls { _, _ -> throw RuntimeException("tls boom") }
        val (runner, ex) = buildRunner(reg, dns, tcp, tls, backend = { null })
        try {
            val (results, cancelled) = runner.runFull { _, _, _ -> }
            assertFalse(cancelled)
            assertEquals(2, results.size)
            for (r in results) {
                assertEquals(StageStatus.FAIL, stages(r)[Stage.DNS]?.status)
                assertEquals(StageStatus.SKIPPED, stages(r)[Stage.TCP]?.status)
                assertEquals(StageStatus.SKIPPED, stages(r)[Stage.TLS]?.status)
                assertEquals(StageStatus.FAIL, stages(r)[Stage.BACKEND]?.status)
                assertEquals("无后端", stages(r)[Stage.BACKEND]?.detail)
                assertEquals(StageStatus.SKIPPED, stages(r)[Stage.END_TO_END]?.status)
            }
        } finally {
            ex.shutdownNow()
        }
    }

    /** registry 为 null（组件不可用）→ 空结果，不抛异常。 */
    @Test
    fun testNullRegistryReturnsEmpty() {
        val (runner, ex) = buildRunner(null, FakeDns({ listOf("1.2.3.4") }))
        try {
            val (results, cancelled) = runner.runFull { _, _, _ -> }
            assertFalse(cancelled)
            assertTrue(results.isEmpty())
        } finally {
            ex.shutdownNow()
        }
    }
}

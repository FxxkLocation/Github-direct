package org.xiyu.githubdirect.root

import android.content.Context
import android.os.Build
import android.os.SystemClock
import org.xiyu.githubdirect.core.data.Nat64FallbackActivation
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.data.DirectEngine
import java.io.File
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket

data class SniGateRuntimeStatus(
    val active: Boolean,
    val generation: Long = 0L,
    val routeCount: Int = 0,
    val nat64RouteCount: Int = 0,
    val nat64Operator: String = "",
    val nat64ExpectedAsn: String = "",
    val nat64ExpectedRegion: String = "",
    val nat64Verified: Boolean = false,
    val nat64ObservedIp: String = "",
    val nat64ObservedAsn: String = "",
    val nat64ObservedOperator: String = "",
    val nat64ObservedRegion: String = "",
    val nat64ObservedAt: Long = 0L,
    val nat64ProbeDetail: String = "",
    val detail: String = "",
)

/**
 * sni-gate 进程生命周期。
 *
 * 可执行文件来自 APK 资产并先在应用 UID 下做 SHA-256 校验，再复制到固定 Root 临时目录；
 * CA 私钥只在 noBackupFilesDir 首次生成，权限固定为 0600，绝不写入 APK/Root 模块。
 */
class SniGateRuntime(
    context: Context,
    private val shell: RootShell = RootShell(),
    private val nat64EgressProbe: Nat64EgressProbe = Nat64EgressProbe(),
) {
    private val app = context.applicationContext
    private val stateDir = File(app.noBackupFilesDir, "sni-gate")
    private val caDir = File(stateDir, "ca")
    private val caCert = File(caDir, "ca.crt")
    private val caKey = File(caDir, "ca.key")
    private val certStore = File(stateDir, "certs")
    private val configFile = File(stateDir, "sni-gate.toml")
    private val assetStageDir = File(stateDir, "bin")

    @Volatile
    private var activePlan = TlsTerminationPlan.EMPTY

    /** 启动时的完整待验证计划；与 [activePlan] 的已验证子集分开保存。 */
    @Volatile
    private var activeRequestedPlan = TlsTerminationPlan.EMPTY

    @Volatile
    private var lastStatus = SniGateRuntimeStatus(false)

    @Volatile
    private var activeNat64Activation: Nat64FallbackActivation? = null

    @Volatile
    private var lastNat64Observation = Nat64EgressObservation.NONE

    fun certificateFile(): File = caCert

    fun status(): SniGateRuntimeStatus = lastStatus

    @Synchronized
    fun ensureCaGenerated(): Result<DeviceCertificateAuthority> = runCatching {
        runCatching { DeviceCertificateAuthority.load(caCert) }.getOrNull()?.let { return@runCatching it }
        val status = startInternal(TlsTerminationPlanner.caBootstrapPlan(), publish = false)
        check(status.active) { status.detail.ifBlank { "sni-gate CA generation failed" } }
        try {
            waitForCertificate()
            fixCertificatePermissions()
            DeviceCertificateAuthority.load(caCert)
        } finally {
            stopInternal(clearRoutes = false)
        }
    }

    /**
     * 调用方必须先确认 CA 已在当前系统信任视图中。启动失败只清空可选路由，不影响原
     * TransparentTcpListener / iptables 数据面。
     */
    @Synchronized
    fun ensureRunning(snapshot: RouteSnapshot): SniGateRuntimeStatus {
        val eligibleNat64Domains = DirectEngine.enabledNat64FallbackDomains()
        val configuredNat64 = DirectEngine.settings()?.nat64FallbackConfig()?.activationOrNull()
        activeNat64Activation = configuredNat64
        lastNat64Observation = when {
            configuredNat64 == null -> Nat64EgressObservation.NONE
            eligibleNat64Domains.isEmpty() -> Nat64EgressObservation(
                observedAt = System.currentTimeMillis(),
                detail = "没有已启用且允许 NAT64 的 OpenAI/ChatGPT 规则",
            )
            else -> nat64EgressProbe.probe(configuredNat64)
        }
        val verifiedNat64 = configuredNat64?.takeIf { lastNat64Observation.verified }
        val plan = TlsTerminationPlanner.plan(
            snapshot = snapshot,
            enabledRelayDomains = DirectEngine.enabledRelayDomains(),
            enabledRelaySuffixes = DirectEngine.enabledRelaySuffixes(),
            enabledEchConfigDomains = DirectEngine.enabledEchConfigDomains(),
            nat64FallbackEligibleDomains = eligibleNat64Domains,
            nat64Fallback = verifiedNat64,
        )
        if (plan.routes.isEmpty()) {
            stopInternal(clearRoutes = true, clearNat64State = false)
            return failed("没有可发布的 TLS 终止路由")
        }
        if (canReuseSniGatePlan(activeRequestedPlan, plan, activePlan, isLocalPortOpen())) {
            TlsTerminationRouteRegistry.publish(activePlan)
            return statusFor(activePlan).also {
                lastStatus = it
            }
        }
        return startInternal(plan, publish = true)
    }

    @Synchronized
    fun stop() {
        stopInternal(clearRoutes = true)
    }

    private fun startInternal(plan: TlsTerminationPlan, publish: Boolean): SniGateRuntimeStatus {
        TlsTerminationRouteRegistry.clear()
        activePlan = TlsTerminationPlan.EMPTY
        activeRequestedPlan = TlsTerminationPlan.EMPTY
        val binary = try {
            prepareBinary()
        } catch (t: Throwable) {
            return failed("运行时准备失败：${failureText(t)}")
        }
        try {
            stateDir.mkdirs()
            caDir.mkdirs()
            certStore.mkdirs()
            writeConfig(plan)
        } catch (t: Throwable) {
            return failed("配置写入失败：${failureText(t)}")
        }

        launch(binary)?.let { return failed(it) }
        runCatching { fixCertificatePermissions() }

        var publishPlan = plan
        var verification: SniGateRouteVerification? = null
        if (publish) {
            verification = try {
                SniGateRouteVerifier(caCert).verify(plan)
            } catch (t: Throwable) {
                stopRootProcess()
                return failed("TLS 终止路由验证失败：${failureText(t)}")
            }
            publishPlan = verification.plan
            if (publishPlan.routes.isEmpty()) {
                stopRootProcess()
                return failed(
                    "没有通过真实 ECH/证书握手的 TLS 终止路由（尝试 ${verification.attempted}）",
                )
            }
            // 监听器也只保留通过验证的域名，避免未发布路由仍能被其他本机进程直接使用。
            if (publishPlan.routes.size != plan.routes.size) {
                try {
                    writeConfig(publishPlan)
                } catch (t: Throwable) {
                    stopRootProcess()
                    return failed("已验证配置写入失败：${failureText(t)}")
                }
                launch(binary)?.let { return failed(it) }
            }
        }

        activeRequestedPlan = plan
        activePlan = publishPlan
        if (publish) TlsTerminationRouteRegistry.publish(publishPlan)
        val detail = verification?.let {
            "已验证 ${publishPlan.routes.size}/${it.attempted} 条本机 TLS 终止路由"
        }.orEmpty()
        return statusFor(publishPlan, detail).also { lastStatus = it }
    }

    private fun statusFor(plan: TlsTerminationPlan, detail: String = ""): SniGateRuntimeStatus {
        val nat64Routes = plan.routes.filter { it.nat64Prefix != null }
        val representative = nat64Routes.firstOrNull()
        val configured = activeNat64Activation
        val observation = lastNat64Observation
        val combinedDetail = buildList {
            if (detail.isNotBlank()) add(detail)
            if (configured != null && !observation.verified && observation.detail.isNotBlank()) {
                add("NON_STRICT_NAT64 未激活：${observation.detail}")
            }
        }.joinToString("；")
        return SniGateRuntimeStatus(
            active = true,
            generation = plan.generation,
            routeCount = plan.routes.size,
            nat64RouteCount = nat64Routes.size,
            nat64Operator = configured?.operator ?: representative?.nat64Operator.orEmpty(),
            nat64ExpectedAsn = configured?.expectedAsn
                ?: representative?.nat64ExpectedAsn.orEmpty(),
            nat64ExpectedRegion = configured?.expectedRegion
                ?: representative?.nat64ExpectedRegion.orEmpty(),
            nat64Verified = observation.verified,
            nat64ObservedIp = observation.publicIp,
            nat64ObservedAsn = observation.asn,
            nat64ObservedOperator = observation.operator,
            nat64ObservedRegion = observation.region,
            nat64ObservedAt = observation.observedAt,
            nat64ProbeDetail = observation.detail,
            detail = combinedDetail,
        )
    }

    private fun writeConfig(plan: TlsTerminationPlan) {
        val config = SniGateConfigRenderer.render(
            plan,
            SniGateConfigPaths(
                caCert = caCert.absolutePath,
                caKey = caKey.absolutePath,
                certStore = certStore.absolutePath,
            ),
        )
        writeAtomically(configFile, config)
    }

    /** 返回 null 表示成功，否则返回可展示的失败原因。 */
    private fun launch(binary: File): String? {
        stopRootProcess()
        val start = shell.execTrustedScript(
            startScript(binary, configFile),
            timeoutSec = START_COMMAND_TIMEOUT_SECONDS,
        )
        if (start.ok && waitForLocalPort()) return null
        val log = readFailureLog()
        stopRootProcess()
        return "sni-gate 启动失败：${start.diagnosticSummary(220)}" +
            if (log.isBlank()) "" else "；$log"
    }

    private fun prepareBinary(): File {
        val abi = Build.SUPPORTED_ABIS.firstOrNull(EXPECTED_SHA256::containsKey)
            ?: error("unsupported ABI: ${Build.SUPPORTED_ABIS.joinToString()}")
        val expected = checkNotNull(EXPECTED_SHA256[abi])
        assetStageDir.mkdirs()
        val staged = File(assetStageDir, "sni-gate-$VERSION-$abi")
        val valid = staged.isFile && staged.length() in 1..MAX_BINARY_BYTES &&
            sha256(staged).equals(expected, ignoreCase = true)
        if (!valid) {
            val temp = File(assetStageDir, staged.name + ".tmp")
            app.assets.open("sni-gate/$abi/sni-gate").use { input ->
                FileOutputStream(temp).use { output ->
                    input.copyTo(output)
                    output.fd.sync()
                }
            }
            check(sha256(temp).equals(expected, ignoreCase = true)) {
                "asset SHA-256 mismatch for $abi"
            }
            if (staged.exists() && !staged.delete()) error("cannot replace staged binary")
            check(temp.renameTo(staged)) { "cannot commit staged binary" }
        }
        staged.setReadable(true, true)
        staged.setExecutable(true, true)

        val rootBinary = File(ROOT_RUNTIME_DIR, "sni-gate-$VERSION-${expected.take(16)}")
        val install = shell.execTrustedScript(
            installBinaryScript(staged, rootBinary, expected.lowercase()),
            timeoutSec = BINARY_INSTALL_TIMEOUT_SECONDS,
        )
        check(install.ok) { install.diagnosticSummary() }
        return rootBinary
    }

    private fun fixCertificatePermissions() {
        if (!caCert.exists() || !caKey.exists()) return
        val script = buildString {
            appendLine("set -eu")
            appendLine("chown 0:0 ${quote(caCert.absolutePath)} ${quote(caKey.absolutePath)}")
            appendLine("chmod 0644 ${quote(caCert.absolutePath)}")
            appendLine("chmod 0600 ${quote(caKey.absolutePath)}")
        }
        val result = shell.execTrustedScript(script, timeoutSec = 5)
        check(result.ok) { result.diagnosticSummary() }
    }

    private fun waitForCertificate() {
        val deadline = SystemClock.elapsedRealtime() + CERT_WAIT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            if (caCert.isFile && caKey.isFile && caCert.length() > 0L && caKey.length() > 0L) return
            SystemClock.sleep(50)
        }
        error("CA files were not generated before deadline")
    }

    private fun waitForLocalPort(): Boolean {
        val deadline = SystemClock.elapsedRealtime() + START_WAIT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            if (isLocalPortOpen()) return true
            SystemClock.sleep(75)
        }
        return false
    }

    private fun isLocalPortOpen(): Boolean {
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress("127.0.0.1", LOCAL_PORT), 150)
            true
        } catch (_: Throwable) {
            false
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun stopInternal(clearRoutes: Boolean, clearNat64State: Boolean = clearRoutes) {
        if (clearRoutes) TlsTerminationRouteRegistry.clear()
        stopRootProcess()
        activePlan = TlsTerminationPlan.EMPTY
        activeRequestedPlan = TlsTerminationPlan.EMPTY
        if (clearNat64State) {
            activeNat64Activation = null
            lastNat64Observation = Nat64EgressObservation.NONE
        }
        lastStatus = SniGateRuntimeStatus(false)
    }

    private fun stopRootProcess() {
        runCatching {
            shell.execTrustedScript(sniGateStopScript(), timeoutSec = STOP_COMMAND_TIMEOUT_SECONDS)
        }
    }

    private fun readFailureLog(): String {
        val result = runCatching {
            shell.execTrustedScript(
                "tail -n 8 ${quote(ROOT_LOG_FILE)} 2>/dev/null || true\n",
                timeoutSec = 3,
            )
        }.getOrNull() ?: return ""
        return result.text().replace(Regex("\\s+"), " ").trim().take(320)
    }

    private fun failed(detail: String): SniGateRuntimeStatus {
        val configured = activeNat64Activation
        val observation = lastNat64Observation
        return SniGateRuntimeStatus(
            active = false,
            nat64Operator = configured?.operator.orEmpty(),
            nat64ExpectedAsn = configured?.expectedAsn.orEmpty(),
            nat64ExpectedRegion = configured?.expectedRegion.orEmpty(),
            nat64Verified = observation.verified,
            nat64ObservedIp = observation.publicIp,
            nat64ObservedAsn = observation.asn,
            nat64ObservedOperator = observation.operator,
            nat64ObservedRegion = observation.region,
            nat64ObservedAt = observation.observedAt,
            nat64ProbeDetail = observation.detail,
            detail = detail.take(420),
        ).also { lastStatus = it }
    }

    private fun startScript(binary: File, config: File): String = buildString {
        appendLine("set -eu")
        appendLine("mkdir -p ${quote(ROOT_RUNTIME_DIR)}")
        appendLine("chmod 0700 ${quote(ROOT_RUNTIME_DIR)}")
        append(sniGateStopScript())
        appendLine("nohup ${quote(binary.absolutePath)} -c ${quote(config.absolutePath)} >${quote(ROOT_LOG_FILE)} 2>&1 </dev/null &")
        appendLine("pid=\$!")
        appendLine("echo \"\$pid\" > ${quote(ROOT_PID_FILE)}")
        appendLine("sleep 1")
        appendLine("kill -0 \"\$pid\"")
    }

    private fun installBinaryScript(source: File, target: File, expected: String): String = buildString {
        appendLine("set -eu")
        appendLine("mkdir -p ${quote(ROOT_RUNTIME_DIR)}")
        appendLine("chmod 0700 ${quote(ROOT_RUNTIME_DIR)}")
        appendLine("cp -f ${quote(source.absolutePath)} ${quote(target.absolutePath)}")
        appendLine("chown 0:0 ${quote(target.absolutePath)}")
        appendLine("chmod 0700 ${quote(target.absolutePath)}")
        appendLine("actual=\$(sha256sum ${quote(target.absolutePath)} | cut -d ' ' -f 1)")
        appendLine("[ \"\$actual\" = ${quote(expected)} ]")
    }

    private fun writeAtomically(target: File, text: String) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, target.name + ".tmp")
        FileOutputStream(temp).use { output ->
            output.write(text.toByteArray(Charsets.UTF_8))
            output.fd.sync()
        }
        if (target.exists() && !target.delete()) error("cannot replace ${target.name}")
        check(temp.renameTo(target)) { "cannot commit ${target.name}" }
    }

    private fun sha256(file: File): String =
        file.inputStream().use { input ->
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
            digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }

    private fun quote(raw: String): String {
        require(raw.isNotBlank() && raw.none { it == '\u0000' || it == '\r' || it == '\n' })
        return "'" + raw.replace("'", "'\\''") + "'"
    }

    private fun failureText(t: Throwable): String =
        "${t.javaClass.simpleName}: ${t.message.orEmpty()}".trim().take(260)

    companion object {
        const val VERSION = "2.1.0-ghd1"
        const val LOCAL_PORT = 7444
        const val ROOT_RUNTIME_DIR = "/data/local/tmp/github-direct-sni-gate"
        const val ROOT_PID_FILE = "$ROOT_RUNTIME_DIR/sni-gate.pid"
        const val ROOT_LOG_FILE = "$ROOT_RUNTIME_DIR/sni-gate.log"

        val EXPECTED_SHA256: Map<String, String> = mapOf(
            "arm64-v8a" to "fe53d3d6d9e66d50d75b59ebcb0650104b19c365b149f7376f14249b96cbb163",
            "armeabi-v7a" to "9cfec31971a60da60945bc01c22e7bf72431063edb87739554e719cf18ae3e3f",
            "x86_64" to "8b9cfcf2c6d46ce0ab25e345cf519dc433b53a1a3bc304be99283add7e200b49",
        )

        private const val MAX_BINARY_BYTES = 32L * 1024L * 1024L
        private const val START_WAIT_MS = 5_000L
        private const val CERT_WAIT_MS = 5_000L
        private const val START_COMMAND_TIMEOUT_SECONDS = 12
        private const val STOP_COMMAND_TIMEOUT_SECONDS = 5
        private const val BINARY_INSTALL_TIMEOUT_SECONDS = 20
    }
}

internal fun sniGateStopScript(): String = buildString {
    appendLine("PID_FILE='${SniGateRuntime.ROOT_PID_FILE}'")
    appendLine("if [ -s \"\$PID_FILE\" ]; then")
    appendLine("  pid=\$(cat \"\$PID_FILE\" 2>/dev/null || true)")
    appendLine("  case \"\$pid\" in ''|*[!0-9]*) pid='' ;; esac")
    appendLine("  if [ -n \"\$pid\" ] && [ -r \"/proc/\$pid/cmdline\" ]; then")
    appendLine("    cmd=\$(tr '\\000' ' ' < \"/proc/\$pid/cmdline\" 2>/dev/null || true)")
    appendLine(
        "    case \"\$cmd\" in ${SniGateRuntime.ROOT_RUNTIME_DIR}/sni-gate-*) " +
            "kill \"\$pid\" 2>/dev/null || true ;; esac",
    )
    appendLine("  fi")
    appendLine("  rm -f \"\$PID_FILE\"")
    appendLine("fi")
}

internal fun canReuseSniGatePlan(
    activeRequestedPlan: TlsTerminationPlan,
    requestedPlan: TlsTerminationPlan,
    publishedPlan: TlsTerminationPlan,
    localPortOpen: Boolean,
): Boolean =
    localPortOpen && publishedPlan.routes.isNotEmpty() && activeRequestedPlan == requestedPlan

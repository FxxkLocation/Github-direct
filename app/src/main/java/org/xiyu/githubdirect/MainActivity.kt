package org.xiyu.githubdirect

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ImageView
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.RadioGroup
import android.widget.Switch
import android.widget.TextView
import io.github.libxposed.service.XposedService
import org.xiyu.githubdirect.core.data.DiagLog
import org.xiyu.githubdirect.core.dns.DoHServers
import org.xiyu.githubdirect.core.dns.EndpointResolver
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.net.TcpProbe
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode
import org.xiyu.githubdirect.core.rules.DnsNames
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.TransportPolicy
import org.xiyu.githubdirect.data.BackendManager
import org.xiyu.githubdirect.data.DiagnosticsRunner
import org.xiyu.githubdirect.data.DirectEngine
import org.xiyu.githubdirect.data.PrivateDnsMode
import org.xiyu.githubdirect.data.PrivateDnsState
import org.xiyu.githubdirect.data.RealDiagOps
import org.xiyu.githubdirect.data.ServiceDiagResult
import org.xiyu.githubdirect.data.Stage
import org.xiyu.githubdirect.data.StageStatus
import org.xiyu.githubdirect.vpn.DnsVpnService
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class MainActivity : Activity(), App.ServiceStateListener {

    private lateinit var statusText: TextView
    private lateinit var statusIndicator: View
    private lateinit var frameworkText: TextView
    private lateinit var dnsResultText: TextView
    private lateinit var diagDnsBtn: Button
    private lateinit var diagTcpBtn: Button
    private lateinit var diagFullBtn: Button
    private lateinit var vpnBtn: Button
    private lateinit var tgBtn: Button
    private lateinit var starBtn: Button
    private lateinit var servicesBtn: Button
    private lateinit var vpnStatusText: TextView
    private lateinit var progressSpinner: ProgressBar
    private lateinit var logoIcon: ImageView
    private lateinit var diagSwitch: Switch
    private lateinit var statServices: TextView
    private lateinit var statRules: TextView
    private lateinit var statPool: TextView
    private lateinit var modeGroup: RadioGroup
    private lateinit var scopeGroup: RadioGroup
    private lateinit var backendStatusText: TextView
    private lateinit var privateDnsWarning: TextView
    private lateinit var btnPickApps: Button
    private var backendManager: BackendManager? = null
    private var syncAnimatorSet: AnimatorSet? = null
    private var fullRunner: DiagnosticsRunner? = null

    private val VPN_REQUEST_CODE = 100

    private companion object {
        const val QUICK_DIAG_MAX_ENDPOINTS = 8
        const val DIAG_WORKERS = 4
        const val DIAG_DOH_TIMEOUT_MS = 1500
        const val DIAG_TCP_TIMEOUT_MS = 3000
        const val DIAG_OVERALL_TIMEOUT_MS = 12_000L
        const val DIAG_FULL_DOH_TIMEOUT_MS = 3000
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.status)
        statusIndicator = findViewById(R.id.status_indicator)
        frameworkText = findViewById(R.id.framework_info)
        dnsResultText = findViewById(R.id.dns_results)
        diagDnsBtn = findViewById(R.id.btn_diag_dns)
        diagTcpBtn = findViewById(R.id.btn_diag_tcp)
        diagFullBtn = findViewById(R.id.btn_diag_full)
        vpnBtn = findViewById(R.id.btn_vpn)
        tgBtn = findViewById(R.id.btn_tg)
        starBtn = findViewById(R.id.btn_star)
        servicesBtn = findViewById(R.id.btn_services)
        vpnStatusText = findViewById(R.id.vpn_status)
        progressSpinner = findViewById(R.id.progress_spinner)
        logoIcon = findViewById(R.id.logo)
        diagSwitch = findViewById(R.id.diag_switch)
        statServices = findViewById(R.id.stat_services)
        statRules = findViewById(R.id.stat_rules)
        statPool = findViewById(R.id.stat_pool)
        modeGroup = findViewById(R.id.mode_group)
        scopeGroup = findViewById(R.id.scope_group)
        backendStatusText = findViewById(R.id.backend_status)
        privateDnsWarning = findViewById(R.id.private_dns_warning)
        btnPickApps = findViewById(R.id.btn_pick_apps)

        statusText.text = getString(R.string.status_waiting)
        frameworkText.text = ""
        dnsResultText.text = getString(R.string.console_hint)

        // 引擎装配（诊断 / 统计 / 服务开关共用同一实例）
        DirectEngine.ensureInit(this, false)
        DirectEngine.settings()?.let { s ->
            diagSwitch.isChecked = s.isDiagEnabled()
            DiagLog.setEnabled(s.isDiagEnabled())
        }
        // 服务开关变更 → 刷新统计行
        DirectEngine.registry()?.addChangeListener { _, _ ->
            runOnUiThread { refreshStats() }
        }

        diagSwitch.setOnCheckedChangeListener { _, checked ->
            DirectEngine.settings()?.setDiagEnabled(checked)
            DiagLog.setEnabled(checked)
        }
        diagDnsBtn.setOnClickListener { runDnsDiag() }
        diagTcpBtn.setOnClickListener { runTcpDiag() }
        diagFullBtn.setOnClickListener { onFullDiagClicked() }
        vpnBtn.setOnClickListener { toggleVpn() }
        servicesBtn.setOnClickListener { startActivity(Intent(this, ServiceManagerActivity::class.java)) }

        tgBtn.setOnClickListener { openUrl("https://t.me/+BUfEUGzViTg2YWU1") }
        starBtn.setOnClickListener { openUrl("https://github.com/FxxkLocation/Github-direct") }

        initBackendControls()
        updateVpnUi()
        refreshStats()
        (application as App).addServiceStateListener(this)
    }

    override fun onResume() {
        super.onResume()
        refreshStats()
        updateVpnUi()
        refreshPrivateDnsWarning()
    }

    // ==================== 后端模式 / 应用范围（§15/§40） ====================

    private fun initBackendControls() {
        backendManager = BackendManager.get(this)
        val settings = DirectEngine.settings()
        // 先按持久化值勾选，再挂监听（避免初始化触发写回）
        modeGroup.check(
            when (settings?.backendMode() ?: BackendMode.AUTO) {
                BackendMode.ROOT_TRANSPARENT -> R.id.rb_mode_root
                BackendMode.VPN -> R.id.rb_mode_vpn
                BackendMode.XPOSED_ONLY -> R.id.rb_mode_xposed
                BackendMode.AUTO -> R.id.rb_mode_auto
            }
        )
        scopeGroup.check(
            when (settings?.appScopeMode() ?: AppScopeMode.ALL_APPS) {
                AppScopeMode.SELECTED_APPS -> R.id.rb_scope_selected
                AppScopeMode.EXCLUDED_APPS -> R.id.rb_scope_excluded
                AppScopeMode.ALL_APPS -> R.id.rb_scope_all
            }
        )
        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            val mode = when (checkedId) {
                R.id.rb_mode_root -> BackendMode.ROOT_TRANSPARENT
                R.id.rb_mode_vpn -> BackendMode.VPN
                R.id.rb_mode_xposed -> BackendMode.XPOSED_ONLY
                else -> BackendMode.AUTO
            }
            DirectEngine.settings()?.setBackendMode(mode)
            refreshBackendStatus()
        }
        scopeGroup.setOnCheckedChangeListener { _, checkedId ->
            val mode = when (checkedId) {
                R.id.rb_scope_selected -> AppScopeMode.SELECTED_APPS
                R.id.rb_scope_excluded -> AppScopeMode.EXCLUDED_APPS
                else -> AppScopeMode.ALL_APPS
            }
            DirectEngine.settings()?.setAppScopeMode(mode)
        }
        btnPickApps.setOnClickListener { showAppPicker() }
        backendManager?.addBackendListener { _, active, message ->
            runOnUiThread {
                refreshBackendStatus()
                if (!active && message.isNotBlank()) {
                    dnsResultText.text = message
                }
            }
        }
    }

    private fun refreshBackendStatus() {
        val bm = backendManager ?: return
        val mode = bm.currentMode()
        val active = bm.isBackendActive()
        val base = when {
            mode == BackendMode.ROOT_TRANSPARENT && active -> R.string.backend_status_root
            mode == BackendMode.VPN && active -> R.string.backend_status_vpn
            mode == BackendMode.XPOSED_ONLY && active -> R.string.backend_status_xposed
            mode == BackendMode.ROOT_TRANSPARENT && !active -> R.string.backend_status_failed
            else -> R.string.backend_status_none
        }
        val caps = bm.cachedRootCapabilities()
        val capsLine = when {
            caps == null -> getString(R.string.root_caps_unknown)
            caps.requiredOk() -> getString(R.string.root_caps_ok)
            else -> getString(R.string.root_caps_no)
        }
        backendStatusText.text = "${getString(base)}\n$capsLine"
        refreshPrivateDnsWarning()
    }

    /** §35：Root 模式生效且系统 Private DNS 非关闭 → 提示可能经 DoT 绕过直连规则。 */
    private fun refreshPrivateDnsWarning() {
        val bm = backendManager ?: return
        val rootActive = bm.currentMode() == BackendMode.ROOT_TRANSPARENT && bm.isBackendActive()
        val privateDnsNotOff = PrivateDnsState.detect(this) != PrivateDnsMode.OFF
        privateDnsWarning.visibility =
            if (rootActive && privateDnsNotOff) View.VISIBLE else View.GONE
    }

    /** 安装应用多选对话框（原生 ListView+CheckBox，轻量）。 */
    private fun showAppPicker() {
        val pm = packageManager
        val apps = try {
            pm.getInstalledApplications(0).sortedBy { it.loadLabel(pm).toString() }
        } catch (t: Throwable) {
            emptyList()
        }
        if (apps.isEmpty()) {
            dnsResultText.text = getString(R.string.app_picker_empty)
            return
        }
        val labels = apps.map { it.loadLabel(pm).toString() }
        val packages = apps.map { it.packageName }
        val selected = DirectEngine.settings()?.scopedPackages() ?: emptySet()

        val listView = ListView(this)
        listView.choiceMode = ListView.CHOICE_MODE_MULTIPLE
        listView.adapter = ArrayAdapter(
            this, android.R.layout.simple_list_item_multiple_choice, labels
        )
        for (i in packages.indices) {
            if (packages[i] in selected) listView.setItemChecked(i, true)
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.app_picker_title))
            .setView(listView)
            .setPositiveButton(getString(R.string.dialog_ok)) { _, _ ->
                val result = LinkedHashSet<String>()
                val positions = listView.checkedItemPositions
                for (i in 0 until positions.size()) {
                    val pos = positions.keyAt(i)
                    if (positions.valueAt(i) && pos in packages.indices) {
                        result.add(packages[pos])
                    }
                }
                DirectEngine.settings()?.setScopedPackages(result)
            }
            .setNegativeButton(getString(R.string.dialog_cancel), null)
            .show()
    }

    private fun openUrl(url: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onDestroy() {
        // 完整诊断若在运行：中断在飞阶段 + 丢弃未开始任务（诊断线程随后自行收尾）
        fullRunner?.cancel()
        super.onDestroy()
        (application as App).removeServiceStateListener(this)
    }

    override fun onServiceBind(service: XposedService) {
        runOnUiThread {
            statusText.text = getString(R.string.status_active)
            statusIndicator.setBackgroundResource(R.drawable.shape_circle_green)
            val sb = StringBuilder()
            sb.append(getString(R.string.framework_fmt, service.frameworkName,
                service.frameworkVersion, "" + service.frameworkVersionCode))
            sb.append("\n").append(getString(R.string.framework_api, "" + service.apiVersion))
            sb.append("\n").append(getString(R.string.framework_scope, service.scope.joinToString(", ")))
            frameworkText.text = sb.toString()
        }
    }

    override fun onServiceDied(service: XposedService) {
        runOnUiThread {
            statusText.text = getString(R.string.status_disconnected)
            statusIndicator.setBackgroundResource(R.drawable.shape_circle_red)
        }
    }

    // ==================== 统计行 ====================

    private fun refreshStats() {
        DirectEngine.ensureInit(this, false)
        val registry = DirectEngine.registry() ?: return
        val all = DirectEngine.profiles()
        val total = all.size
        val enabled = registry.enabledProfiles().size
        val rules = all.values.sumOf { it.domains.size }
        statServices.text = getString(R.string.stats_fmt_services, enabled, total)
        statRules.text = rules.toString()
        val snap = DirectEngine.pool()?.snapshot()
        statPool.text = if (snap != null) {
            getString(R.string.stats_fmt_pool, snap.active, snap.leased)
        } else {
            getString(R.string.stats_pool_empty)
        }
    }

    // ==================== 通用诊断 ====================

    private fun startLoading() {
        progressSpinner.visibility = View.VISIBLE
        if (syncAnimatorSet == null) {
            val scaleX = ObjectAnimator.ofFloat(logoIcon, "scaleX", 1f, 1.2f).apply {
                repeatCount = ObjectAnimator.INFINITE
                repeatMode = ObjectAnimator.REVERSE
                duration = 600
            }
            val scaleY = ObjectAnimator.ofFloat(logoIcon, "scaleY", 1f, 1.2f).apply {
                repeatCount = ObjectAnimator.INFINITE
                repeatMode = ObjectAnimator.REVERSE
                duration = 600
            }
            val alpha = ObjectAnimator.ofFloat(logoIcon, "alpha", 1f, 0.5f).apply {
                repeatCount = ObjectAnimator.INFINITE
                repeatMode = ObjectAnimator.REVERSE
                duration = 600
            }
            syncAnimatorSet = AnimatorSet().apply {
                playTogether(scaleX, scaleY, alpha)
                interpolator = AccelerateDecelerateInterpolator()
            }
        }
        syncAnimatorSet?.start()
        diagDnsBtn.isEnabled = false
        diagTcpBtn.isEnabled = false
        diagFullBtn.isEnabled = false
        diagDnsBtn.alpha = 0.5f
        diagTcpBtn.alpha = 0.5f
        diagFullBtn.alpha = 0.5f
    }

    private fun stopLoading() {
        progressSpinner.visibility = View.INVISIBLE
        syncAnimatorSet?.cancel()
        logoIcon.scaleX = 1f
        logoIcon.scaleY = 1f
        logoIcon.alpha = 1f
        diagDnsBtn.isEnabled = true
        diagTcpBtn.isEnabled = true
        diagFullBtn.isEnabled = true
        diagDnsBtn.alpha = 1.0f
        diagTcpBtn.alpha = 1.0f
        diagFullBtn.alpha = 1.0f
        diagFullBtn.text = getString(R.string.btn_diag_full)
    }

    /**
     * 快速诊断端点：每个启用 profile 最多取一个 testEndpoint，并设置总量上限。
     * 避免“全部开启”后一次串行探测几十/上百个域名导致 UI 长时间转圈。
     */
    private fun diagEndpoints(limit: Int = QUICK_DIAG_MAX_ENDPOINTS): List<String> {
        val registry = DirectEngine.registry() ?: return emptyList()
        val result = LinkedHashSet<String>()
        for (p in registry.enabledProfiles()) {
            val raw = p.testEndpoints.firstOrNull() ?: continue
            val d = endpointDomain(raw) ?: continue
            val norm = DnsNames.normalize(d) ?: continue
            result.add(norm)
            if (result.size >= limit) break
        }
        return result.toList()
    }

    /** 从 testEndpoint（可能带 scheme/路径/端口）提取裸域名。 */
    private fun endpointDomain(raw: String): String? {
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

    private fun transportLabel(t: TransportPolicy): String = when (t) {
        TransportPolicy.PASSTHROUGH -> getString(R.string.tp_passthrough)
        TransportPolicy.CLEAN_DNS -> getString(R.string.tp_clean_dns)
        TransportPolicy.DIRECT_IP -> getString(R.string.tp_direct_ip)
        TransportPolicy.TLS_FRAGMENT_RELAY -> getString(R.string.tp_tls_fragment)
        TransportPolicy.NXDOMAIN -> getString(R.string.tp_nxdomain)
    }

    /** 命中信息头：域名 → 命中服务 → transport 策略。 */
    private fun appendHitHeader(
        sb: StringBuilder,
        registry: RuleRegistry,
        domain: String,
        match: org.xiyu.githubdirect.core.rules.RuleMatch?,
    ) {
        val svcName = match?.let { registry.profile(it.serviceId)?.displayName } ?: "—"
        val transport = match?.let { transportLabel(it.policy.transport) }
            ?: getString(R.string.diag_none)
        sb.append(domain).append(" → ").append(svcName).append(" → ").append(transport).append("\n")
    }

    private fun runDnsDiag() {
        startLoading()
        dnsResultText.text = getString(R.string.diag_dns_running)
        Thread {
            val sb = StringBuilder()
            try {
                sb.append("=== DNS ").append(getString(R.string.btn_diag_dns)).append(" ===\n")
                sb.append(getString(R.string.diag_quick_note, QUICK_DIAG_MAX_ENDPOINTS)).append("\n\n")

                if (!DirectEngine.ensureInit(this, false)) {
                    sb.append(getString(R.string.diag_init_failed)).append("\n")
                } else {
                    val registry = DirectEngine.registry()
                    val binder = DirectEngine.binder()
                    val endpoints = diagEndpoints()
                    if (registry == null || binder == null) {
                        sb.append(getString(R.string.diag_init_failed)).append("\n")
                    } else if (endpoints.isEmpty()) {
                        sb.append(getString(R.string.diag_no_profile)).append("\n")
                    } else {
                        // 诊断使用短 timeout resolver；不要让正式 resolver 的多级回退拖住 UI。
                        val diagResolver = EndpointResolver(
                            binder = binder,
                            servers = DoHServers.DEFAULT,
                            connectTimeoutMs = DIAG_DOH_TIMEOUT_MS,
                            readTimeoutMs = DIAG_DOH_TIMEOUT_MS,
                        )
                        for (entry in runBoundedDiagnostics(endpoints, DIAG_OVERALL_TIMEOUT_MS) { domain ->
                            buildDnsDiagEntry(registry, diagResolver, domain)
                        }) {
                            sb.append(entry)
                        }
                    }
                }
            } catch (t: Throwable) {
                sb.append(getString(R.string.diag_error, t.message ?: t.javaClass.simpleName)).append("\n")
            } finally {
                runOnUiThread {
                    dnsResultText.text = sb.toString()
                    stopLoading()
                }
            }
        }.start()
    }

    /** 单项 DNS 快速诊断：命中链 + A 记录。 */
    private fun buildDnsDiagEntry(
        registry: RuleRegistry,
        resolver: EndpointResolver,
        domain: String,
    ): String {
        val sb = StringBuilder()
        val match = registry.match(domain)
        appendHitHeader(sb, registry, domain, match)
        if (match == null) {
            sb.append("\n")
            return sb.toString()
        }
        if (match.policy.transport == TransportPolicy.NXDOMAIN) {
            sb.append("  ").append(getString(R.string.diag_blocked)).append("\n\n")
            return sb.toString()
        }

        val start = System.currentTimeMillis()
        val v4 = resolver.resolveA(domain, match.policy.cidr)
        val elapsed = System.currentTimeMillis() - start
        if (v4 == null || v4.isEmpty()) {
            sb.append("  ").append(getString(R.string.diag_resolve_fail, elapsed)).append("\n\n")
            return sb.toString()
        }
        val v4s = v4.map { IpAddresses.ipv4ToString(it) }
        sb.append("  A   = ").append(v4s.joinToString(", ")).append("\n")
        sb.append("  ").append(getString(R.string.diag_resolve_ok, elapsed)).append("\n\n")
        return sb.toString()
    }

    private fun runTcpDiag() {
        startLoading()
        dnsResultText.text = getString(R.string.diag_tcp_running)
        Thread {
            val sb = StringBuilder()
            try {
                sb.append("=== ").append(getString(R.string.btn_diag_tcp)).append(" ===\n")
                sb.append(getString(R.string.diag_quick_note, QUICK_DIAG_MAX_ENDPOINTS)).append("\n\n")

                if (!DirectEngine.ensureInit(this, false)) {
                    sb.append(getString(R.string.diag_init_failed)).append("\n")
                } else {
                    val registry = DirectEngine.registry()
                    val binder = DirectEngine.binder()
                    val endpoints = diagEndpoints()
                    if (registry == null || binder == null) {
                        sb.append(getString(R.string.diag_init_failed)).append("\n")
                    } else if (endpoints.isEmpty()) {
                        sb.append(getString(R.string.diag_no_profile)).append("\n")
                    } else {
                        val diagResolver = EndpointResolver(
                            binder = binder,
                            servers = DoHServers.DEFAULT,
                            connectTimeoutMs = DIAG_DOH_TIMEOUT_MS,
                            readTimeoutMs = DIAG_DOH_TIMEOUT_MS,
                        )
                        for (entry in runBoundedDiagnostics(endpoints, DIAG_OVERALL_TIMEOUT_MS) { domain ->
                            buildTcpDiagEntry(registry, diagResolver, domain)
                        }) {
                            sb.append(entry)
                        }
                    }
                }
            } catch (t: Throwable) {
                sb.append(getString(R.string.diag_error, t.message ?: t.javaClass.simpleName)).append("\n")
            } finally {
                runOnUiThread {
                    dnsResultText.text = sb.toString()
                    stopLoading()
                }
            }
        }.start()
    }

    /**
     * 单项连通性诊断：先通过当前 clean resolver 获取 IPv4，再进行真实 TCP/443 connect。
     * InetAddress.isReachable() 不是 TCP 443 测试，因此不再使用。
     */
    private fun buildTcpDiagEntry(
        registry: RuleRegistry,
        resolver: EndpointResolver,
        domain: String,
    ): String {
        val sb = StringBuilder()
        val match = registry.match(domain)
        appendHitHeader(sb, registry, domain, match)
        if (match == null || match.policy.transport == TransportPolicy.NXDOMAIN) {
            if (match?.policy?.transport == TransportPolicy.NXDOMAIN) {
                sb.append("  ").append(getString(R.string.diag_blocked)).append("\n")
            }
            sb.append("\n")
            return sb.toString()
        }

        val binder = DirectEngine.binder()
        if (binder == null) {
            sb.append("  ").append(getString(R.string.diag_init_failed)).append("\n\n")
            return sb.toString()
        }

        val dnsStart = System.currentTimeMillis()
        val v4 = resolver.resolveA(domain, match.policy.cidr)
        val dnsMs = System.currentTimeMillis() - dnsStart
        val ip = v4?.firstOrNull()?.let { IpAddresses.ipv4ToString(it) }
        if (ip == null) {
            sb.append("  ").append(getString(R.string.diag_resolve_fail, dnsMs)).append("\n\n")
            return sb.toString()
        }

        val tcpStart = System.currentTimeMillis()
        val reachable = TcpProbe.isTcpReachable(ip, 443, DIAG_TCP_TIMEOUT_MS, binder)
        val tcpMs = System.currentTimeMillis() - tcpStart
        val status = if (reachable) getString(R.string.diag_reachable)
        else getString(R.string.diag_unreachable)
        sb.append("  ").append(
            getString(R.string.diag_tcp_line, ip, dnsMs, tcpMs, status)
        ).append("\n\n")
        return sb.toString()
    }

    /**
     * 有界并发执行诊断。到达 overall deadline 后未完成任务统一标记超时；
     * 无论任务异常与否，调用方 finally 都会停止 loading。
     */
    private fun runBoundedDiagnostics(
        endpoints: List<String>,
        overallTimeoutMs: Long,
        worker: (String) -> String,
    ): List<String> {
        if (endpoints.isEmpty()) return emptyList()
        val executor = Executors.newFixedThreadPool(minOf(DIAG_WORKERS, endpoints.size))
        return try {
            val tasks = endpoints.map { domain ->
                Callable {
                    try {
                        worker(domain)
                    } catch (t: Throwable) {
                        "$domain\n  ${getString(R.string.diag_error, t.message ?: t.javaClass.simpleName)}\n\n"
                    }
                }
            }
            val futures = executor.invokeAll(tasks, overallTimeoutMs, TimeUnit.MILLISECONDS)
            futures.mapIndexed { index, future ->
                if (future.isCancelled) {
                    "${endpoints[index]}\n  ${getString(R.string.diag_timeout)}\n\n"
                } else {
                    try {
                        future.get()
                    } catch (t: Throwable) {
                        "${endpoints[index]}\n  ${getString(R.string.diag_error, t.message ?: t.javaClass.simpleName)}\n\n"
                    }
                }
            }
        } finally {
            executor.shutdownNow()
        }
    }

    // ==================== 完整诊断（§52-§56，DiagnosticsRunner） ====================

    /** 完整诊断按钮：运行中 → 取消；否则启动。与 quick 诊断互斥（按钮态互斥 + 先 cancel 后启动）。 */
    private fun onFullDiagClicked() {
        val runner = fullRunner
        if (runner != null && runner.isRunning) {
            runner.cancel()
            diagFullBtn.isEnabled = false
            dnsResultText.text = getString(R.string.full_diag_cancelling)
        } else {
            runFullDiag()
        }
    }

    private fun runFullDiag() {
        if (fullRunner?.isRunning == true) return
        startLoading()
        // 完整诊断运行中按钮即「取消」
        diagFullBtn.isEnabled = true
        diagFullBtn.text = getString(R.string.dialog_cancel)
        dnsResultText.text = getString(R.string.full_diag_running)

        val registry = DirectEngine.registry()
        val binder = DirectEngine.binder()
        if (!DirectEngine.ensureInit(this, false) || registry == null || binder == null) {
            dnsResultText.text = getString(R.string.diag_init_failed)
            stopLoading()
            return
        }
        // 短超时 + 单服务器 resolver：避免 6 服务器回退把单阶段拖过 per-stage 8s
        val diagResolver = EndpointResolver(
            binder = binder,
            servers = DoHServers.DEFAULT.take(1),
            connectTimeoutMs = DIAG_FULL_DOH_TIMEOUT_MS,
            readTimeoutMs = DIAG_FULL_DOH_TIMEOUT_MS,
        )
        val ops = RealDiagOps(diagResolver, binder)
        val executor = Executors.newFixedThreadPool(DiagnosticsRunner.CONCURRENCY)
        val runner = DiagnosticsRunner(
            registry = registry,
            dnsOps = ops,
            tcpProbe = ops,
            tlsOps = ops,
            backendInfo = { backendSummary() },
            executor = executor,
        )
        fullRunner = runner
        Thread {
            val (results, cancelled) = try {
                runner.runFull { done, total, current ->
                    runOnUiThread {
                        if (!isFinishing) {
                            dnsResultText.text =
                                getString(R.string.full_diag_progress, done, total, current.displayName)
                        }
                    }
                }
            } catch (t: Throwable) {
                emptyList<ServiceDiagResult>() to false
            } finally {
                // §56：成功/超时/异常路径也必须释放诊断线程池（cancel 路径 runner 已 shutdownNow，重复调用无害）
                executor.shutdownNow()
            }
            runOnUiThread {
                if (!isFinishing) {
                    dnsResultText.text = formatFullDiag(results, cancelled)
                }
                stopLoading()
            }
        }.start()
    }

    /** 当前 backend 描述（BACKEND 阶段 detail）；无生效后端 → null → FAIL「无后端」。 */
    private fun backendSummary(): String? {
        val bm = backendManager ?: return null
        if (!bm.isBackendActive()) return null
        return when (bm.currentMode()) {
            BackendMode.ROOT_TRANSPARENT -> "Root Transparent ACTIVE"
            BackendMode.VPN -> "VPN ACTIVE"
            BackendMode.XPOSED_ONLY -> "Xposed assist"
            else -> "ACTIVE"
        }
    }

    private fun formatFullDiag(results: List<ServiceDiagResult>, cancelled: Boolean): String {
        val sb = StringBuilder()
        sb.append(getString(
            if (cancelled) R.string.full_diag_cancelled else R.string.full_diag_done,
            results.size, results.size
        )).append("\n")
        for (r in results) {
            val parts = listOf(
                fullStageText(r, Stage.RULE),
                fullStageText(r, Stage.DNS),
                fullStageText(r, Stage.TCP),
                fullStageText(r, Stage.TLS),
                fullStageText(r, Stage.BACKEND),
                fullStageText(r, Stage.END_TO_END),
            )
            sb.append("▶ ").append(r.displayName.padEnd(10))
                .append("  ").append(parts.joinToString("  ")).append("\n")
        }
        return sb.toString().trimEnd()
    }

    private fun fullStageText(r: ServiceDiagResult, stage: Stage): String {
        val s = r.stages[stage] ?: return "—"
        val label = when (stage) {
            Stage.RULE -> "Rule"
            Stage.DNS -> "DNS"
            Stage.TCP -> "TCP"
            Stage.TLS -> "TLS"
            Stage.BACKEND -> "BACKEND"
            Stage.END_TO_END -> "E2E"
        }
        return when (s.status) {
            StageStatus.OK -> when (stage) {
                Stage.RULE -> "Rule ${s.detail}"
                Stage.DNS -> "DNS OK ${s.latencyMs}ms"
                Stage.TCP -> "TCP OK ${s.latencyMs}ms"
                Stage.TLS -> "TLS OK(${s.detail})"
                Stage.BACKEND -> "BACKEND OK"
                Stage.END_TO_END -> "E2E OK"
            }
            StageStatus.SKIPPED -> "$label SKIPPED"
            StageStatus.TIMEOUT -> "$label FAIL(${s.detail})"
            else -> "$label ${s.status.name}(${s.detail})"
        }
    }

    // ==================== 后端开关（统一走 BackendManager） ====================

    private fun toggleVpn() {
        val bm = backendManager ?: return
        if (bm.isBackendActive()) {
            stopProxy()
        } else {
            startProxy()
        }
    }

    /**
     * 统一后端启动入口（§15/§17）：按当前设置的 backend mode 走对应流程。
     * AUTO 解析出 ROOT → 弹确认（Root 不占 VPN slot）；确认走 root，取消走 VPN。
     */
    private fun startProxy() {
        val bm = backendManager ?: return
        when (DirectEngine.settings()?.backendMode() ?: BackendMode.AUTO) {
            BackendMode.AUTO -> {
                val resolved = bm.resolveAuto()
                if (resolved == BackendMode.ROOT_TRANSPARENT) {
                    AlertDialog.Builder(this)
                        .setTitle(getString(R.string.root_dialog_title))
                        .setMessage(getString(R.string.root_dialog_message))
                        .setPositiveButton(getString(R.string.root_dialog_use_root)) { _, _ ->
                            if (!bm.start(BackendMode.ROOT_TRANSPARENT)) {
                                dnsResultText.text = getString(R.string.proxy_start_failed, "Root 后端启动失败")
                            }
                            refreshBackendStatus()
                        }
                        .setNegativeButton(getString(R.string.root_dialog_use_vpn)) { _, _ ->
                            startVpnFlow()
                        }
                        .show()
                } else {
                    startVpnFlow()
                }
            }
            BackendMode.ROOT_TRANSPARENT -> {
                if (!bm.start(BackendMode.ROOT_TRANSPARENT)) {
                    dnsResultText.text = getString(R.string.proxy_start_failed, "Root 后端启动失败")
                }
                refreshBackendStatus()
            }
            BackendMode.VPN -> startVpnFlow()
            BackendMode.XPOSED_ONLY -> {
                bm.start(BackendMode.XPOSED_ONLY)
                refreshBackendStatus()
            }
        }
    }

    /** VPN 授权流：VpnService.prepare → 授权回调后记录模式并启动服务。 */
    private fun startVpnFlow() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            launchVpnService()
        }
    }

    private fun stopProxy() {
        backendManager?.stop()
        vpnBtn.postDelayed({ updateVpnUi() }, 500)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                launchVpnService()
            } else {
                dnsResultText.text = getString(R.string.vpn_authorize_denied)
            }
        }
    }

    private fun launchVpnService() {
        // 先记录模式并执行互斥（停 root），再启动服务
        backendManager?.start(BackendMode.VPN)
        val intent = Intent(this, DnsVpnService::class.java)
        intent.action = DnsVpnService.ACTION_START
        startForegroundService(intent)
        vpnBtn.postDelayed({ updateVpnUi() }, 1000)
    }

    private fun updateVpnUi() {
        val active = backendManager?.isBackendActive() == true
        if (active) {
            vpnBtn.text = getString(R.string.vpn_off)
            vpnBtn.setBackgroundResource(R.drawable.btn_danger)
            vpnStatusText.text = getString(R.string.vpn_status_on)
            vpnStatusText.setTextColor(getColor(R.color.colorSuccess))
        } else {
            vpnBtn.text = getString(R.string.vpn_on)
            vpnBtn.setBackgroundResource(R.drawable.btn_primary)
            vpnStatusText.text = getString(R.string.vpn_status_off)
            vpnStatusText.setTextColor(getColor(R.color.textColorSecondary))
        }
        refreshBackendStatus()
        refreshPrivateDnsWarning()
    }
}

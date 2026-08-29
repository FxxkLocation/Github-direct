package org.xiyu.githubdirect

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.Button
import android.widget.ImageView
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.RadioGroup
import android.widget.Switch
import android.widget.TextView
import io.github.libxposed.service.XposedService
import org.xiyu.githubdirect.core.data.DiagLog
import org.xiyu.githubdirect.core.data.Nat64FallbackConfig
import org.xiyu.githubdirect.core.data.ScopeDefaults
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
import org.xiyu.githubdirect.root.RootRelayService
import org.xiyu.githubdirect.root.AndroidSystemCaInstaller
import org.xiyu.githubdirect.root.DeviceCertificateAuthority
import org.xiyu.githubdirect.root.SniGateRuntime
import org.xiyu.githubdirect.root.SystemCaState
import org.xiyu.githubdirect.root.SystemCaStatus
import org.xiyu.githubdirect.vpn.DnsVpnService
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

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
    private lateinit var btnPickEmbeddedTls: Button
    private lateinit var rootAutoStartSwitch: Switch
    private lateinit var adaptiveCandidatesSwitch: Switch
    private lateinit var realIpRedirectSwitch: Switch
    private lateinit var tlsFragmentV2Switch: Switch
    private lateinit var tlsTerminationSwitch: Switch
    private lateinit var nat64FallbackSwitch: Switch
    private lateinit var nat64StatusText: TextView
    private lateinit var btnConfigureNat64: Button
    private lateinit var caStatusText: TextView
    private lateinit var btnInstallCa: Button
    private lateinit var btnRemoveCa: Button
    private var backendManager: BackendManager? = null
    private var frameworkSummary: String = ""
    private var syncAnimatorSet: AnimatorSet? = null
    private var fullRunner: DiagnosticsRunner? = null
    private val backendExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "GHD-Backend").apply { isDaemon = true }
    }
    private val rootProbeInFlight = AtomicBoolean(false)
    private val caStatusInFlight = AtomicBoolean(false)
    private val caOperationInFlight = AtomicBoolean(false)
    @Volatile private var lastSystemCaStatus = SystemCaStatus(SystemCaState.NOT_GENERATED)
    private var tlsTerminationUiUpdate = false
    private var nat64UiUpdate = false

    private val VPN_REQUEST_CODE = 100

    private companion object {
        const val QUICK_DIAG_MAX_ENDPOINTS = 8
        const val DIAG_WORKERS = 4
        const val DIAG_DOH_TIMEOUT_MS = 1500
        const val DIAG_TCP_TIMEOUT_MS = 3000
        const val DIAG_OVERALL_TIMEOUT_MS = 12_000L
        const val DIAG_FULL_DOH_TIMEOUT_MS = 3000
        const val HOOK_HEARTBEAT_STALE_MS = 120_000L
        val PLATFORM_CLIENT_PACKAGES = setOf(
            "com.google.android.googlequicksearchbox",
            "com.google.android.youtube",
            "com.google.android.apps.youtube.music",
            "com.discord",
            "com.discord.canary",
            "com.openai.chatgpt",
        )
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
        btnPickEmbeddedTls = findViewById(R.id.btn_pick_embedded_tls)
        rootAutoStartSwitch = findViewById(R.id.switch_root_autostart)
        adaptiveCandidatesSwitch = findViewById(R.id.switch_adaptive_candidates)
        realIpRedirectSwitch = findViewById(R.id.switch_real_ip_redirect)
        tlsFragmentV2Switch = findViewById(R.id.switch_tls_fragment_v2)
        tlsTerminationSwitch = findViewById(R.id.switch_tls_termination)
        nat64FallbackSwitch = findViewById(R.id.switch_nat64_fallback)
        nat64StatusText = findViewById(R.id.nat64_status)
        btnConfigureNat64 = findViewById(R.id.btn_configure_nat64)
        caStatusText = findViewById(R.id.ca_status)
        btnInstallCa = findViewById(R.id.btn_install_ca)
        btnRemoveCa = findViewById(R.id.btn_remove_ca)

        statusText.text = getString(R.string.status_waiting)
        frameworkText.text = ""
        dnsResultText.text = getString(R.string.console_hint)

        // 引擎装配（诊断 / 统计 / 服务开关共用同一实例）
        DirectEngine.ensureInit(this, false)
        DirectEngine.settings()?.let { s ->
            diagSwitch.isChecked = s.isDiagEnabled()
            DiagLog.setEnabled(s.isDiagEnabled())
            s.ensureHookHeartbeatToken()
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
        probeRootAsync()
        updateVpnUi()
        refreshStats()
        (application as App).addServiceStateListener(this)
    }

    override fun onResume() {
        super.onResume()
        refreshStats()
        updateVpnUi()
        refreshPrivateDnsWarning()
        refreshHookHeartbeat()
        refreshCaStatusAsync()
        refreshNat64Status()
        val caps = backendManager?.cachedRootCapabilities()
        if (caps?.requiredOk() != true) {
            probeRootAsync()
        }
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
            when (settings?.appScopeMode() ?: ScopeDefaults.MODE) {
                AppScopeMode.SELECTED_APPS -> R.id.rb_scope_selected
                AppScopeMode.EXCLUDED_APPS -> R.id.rb_scope_excluded
                AppScopeMode.ALL_APPS -> R.id.rb_scope_all
            }
        )
        btnPickEmbeddedTls.isEnabled = settings?.appScopeMode() == AppScopeMode.SELECTED_APPS
        rootAutoStartSwitch.isChecked = settings?.isRootAutoStartEnabled() == true
        adaptiveCandidatesSwitch.isChecked = settings?.isAdaptiveCandidatesEnabled() != false
        realIpRedirectSwitch.isChecked = settings?.isRealIpRedirectEnabled() != false
        tlsFragmentV2Switch.isChecked = settings?.isTlsFragmentV2Enabled() != false
        tlsTerminationSwitch.isChecked = settings?.isTlsTerminationEnabled() == true
        nat64FallbackSwitch.isChecked = settings?.nat64FallbackConfig()?.enabled == true
        refreshNat64Status()
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
            btnPickEmbeddedTls.isEnabled = mode == AppScopeMode.SELECTED_APPS
            requestRootRuleRefreshIfActive()
        }
        btnPickApps.setOnClickListener { showAppPicker() }
        btnPickEmbeddedTls.setOnClickListener { showEmbeddedTlsPicker() }
        rootAutoStartSwitch.setOnCheckedChangeListener { _, checked ->
            DirectEngine.settings()?.setRootAutoStartEnabled(checked)
        }
        adaptiveCandidatesSwitch.setOnCheckedChangeListener { _, checked ->
            DirectEngine.settings()?.setAdaptiveCandidatesEnabled(checked)
            requestRootRuleRefreshIfActive()
        }
        realIpRedirectSwitch.setOnCheckedChangeListener { _, checked ->
            DirectEngine.settings()?.setRealIpRedirectEnabled(checked)
            requestRootRuleRefreshIfActive()
        }
        tlsFragmentV2Switch.setOnCheckedChangeListener { _, checked ->
            DirectEngine.settings()?.setTlsFragmentV2Enabled(checked)
            requestRootRuleRefreshIfActive()
        }
        tlsTerminationSwitch.setOnCheckedChangeListener { _, checked ->
            if (tlsTerminationUiUpdate) return@setOnCheckedChangeListener
            if (!checked) {
                DirectEngine.settings()?.setTlsTerminationEnabled(false)
                disableNat64Fallback()
                requestRootRuleRefreshIfActive()
                return@setOnCheckedChangeListener
            }
            if (lastSystemCaStatus.state != SystemCaState.TRUSTED) {
                setTlsTerminationSwitch(false)
                dnsResultText.text = getString(R.string.ca_not_trusted)
                refreshCaStatusAsync()
                return@setOnCheckedChangeListener
            }
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.ca_enable_title))
                .setMessage(getString(R.string.ca_enable_message))
                .setPositiveButton(getString(R.string.dialog_ok)) { _, _ ->
                    DirectEngine.settings()?.setTlsTerminationEnabled(true)
                    requestRootReprobeIfActive()
                }
                .setNegativeButton(getString(R.string.dialog_cancel)) { _, _ ->
                    setTlsTerminationSwitch(false)
                }
                .setOnCancelListener { setTlsTerminationSwitch(false) }
                .show()
        }
        nat64FallbackSwitch.setOnCheckedChangeListener { _, checked ->
            if (nat64UiUpdate) return@setOnCheckedChangeListener
            val store = DirectEngine.settings() ?: return@setOnCheckedChangeListener
            if (!checked) {
                val current = store.nat64FallbackConfig()
                store.setNat64FallbackConfig(current.copy(enabled = false, riskAccepted = false))
                refreshNat64Status()
                requestRootReprobeIfActive()
                return@setOnCheckedChangeListener
            }
            setNat64FallbackSwitch(false)
            if (!tlsTerminationSwitch.isChecked || lastSystemCaStatus.state != SystemCaState.TRUSTED) {
                dnsResultText.text = getString(R.string.nat64_requires_tls)
                refreshNat64Status()
                return@setOnCheckedChangeListener
            }
            if (DirectEngine.enabledNat64FallbackDomains().isEmpty()) {
                dnsResultText.text = getString(R.string.nat64_requires_openai)
                refreshNat64Status()
                return@setOnCheckedChangeListener
            }
            val prepared = store.nat64FallbackConfig().copy(enabled = true, riskAccepted = true)
            if (prepared.activationOrNull() == null) {
                showNat64ConfigDialog(enableAfterSave = true)
            } else {
                confirmNat64Activation(prepared)
            }
        }
        btnConfigureNat64.setOnClickListener {
            showNat64ConfigDialog(enableAfterSave = false)
        }
        btnInstallCa.setOnClickListener { confirmInstallCa() }
        btnRemoveCa.setOnClickListener { confirmRemoveCa() }
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
            mode == BackendMode.XPOSED_ONLY && active && bm.isRootBackendActive() ->
                R.string.backend_status_xposed_root
            mode == BackendMode.XPOSED_ONLY && active -> R.string.backend_status_xposed
            mode == BackendMode.ROOT_TRANSPARENT && !active -> R.string.backend_status_failed
            else -> R.string.backend_status_none
        }
        val caps = bm.cachedRootCapabilities()
        val capsLine = when {
            rootProbeInFlight.get() && caps == null -> getString(R.string.root_caps_probing)
            caps == null -> getString(R.string.root_caps_unknown)
            caps.requiredOk() && caps.ipv6Netfilter -> getString(R.string.root_caps_ok_ipv6)
            caps.requiredOk() -> getString(R.string.root_caps_ok)
            else -> getString(
                R.string.root_caps_no,
                caps.missingRequired().joinToString().ifBlank { "未知" },
            )
        }
        val serviceStatus = RootRelayService.readStatus(this)
        val serviceLine = if (serviceStatus.updatedAt > 0L && serviceStatus.phase != RootRelayService.Phase.STOPPED) {
            buildString {
                append("\nRoot 服务：${serviceStatus.phase.name} · ${serviceStatus.message}")
                append("\n规则 generation ${serviceStatus.ruleGeneration} · 候选 ${serviceStatus.candidateCount} · fail-open ${serviceStatus.failOpenMode}")
                append("\n真实 IP 接管：IPv4 ${if (serviceStatus.realIpRedirect) "已启用" else "未启用"} · IPv6 ${if (serviceStatus.ipv6RealIpRedirect) "已启用" else "未启用"}")
                append("\n本机 TLS 终止：${if (serviceStatus.tlsTerminationActive) "ACTIVE" else "未激活"} · 路由 ${serviceStatus.tlsTerminationRoutes} · CA ${serviceStatus.caState}")
                if (serviceStatus.nat64FallbackActive) {
                    append("\nNON_STRICT_NAT64：ACTIVE · 路由 ${serviceStatus.nat64FallbackRoutes}")
                    if (serviceStatus.nat64Ipv6FallbackDestinations > 0) {
                        append(" · IPv6 UID 回落 ${serviceStatus.nat64Ipv6FallbackDestinations}")
                    }
                    append(" · ${serviceStatus.nat64Operator} · 预期 ${serviceStatus.nat64ExpectedAsn}/${serviceStatus.nat64ExpectedRegion}")
                    if (serviceStatus.nat64Verified) {
                        append(
                            "\nNAT64 实测：${serviceStatus.nat64ObservedIp} · " +
                                "${serviceStatus.nat64ObservedAsn} · " +
                                "${serviceStatus.nat64ObservedOperator} · " +
                                serviceStatus.nat64ObservedRegion,
                        )
                    }
                } else if (serviceStatus.nat64Operator.isNotBlank() &&
                    serviceStatus.nat64ProbeDetail.isNotBlank()
                ) {
                    append("\nNON_STRICT_NAT64：未激活 · ${serviceStatus.nat64ProbeDetail}")
                }
                if (serviceStatus.failureStage.isNotBlank()) append(" · 失败阶段 ${serviceStatus.failureStage}")
                if (serviceStatus.degradationReason.isNotBlank()) {
                    append("\n降级：${serviceStatus.degradationReason}")
                }
            }
        } else {
            ""
        }
        val configuredPackages = DirectEngine.settings()?.scopedPackages().orEmpty()
        val embeddedPackages = DirectEngine.settings()?.embeddedTlsCapturePackages().orEmpty()
        val uidScope = bm.rootScopeUids().sorted()
        val uidText = if (uidScope.isEmpty()) "无" else uidScope.joinToString()
        val rootScopeLine = when (DirectEngine.settings()?.appScopeMode()) {
            AppScopeMode.ALL_APPS -> "\nRoot 作用域：全部应用（模块自身除外）"
            AppScopeMode.EXCLUDED_APPS -> "\nRoot 排除 UID：$uidText"
            else -> "\nRoot 作用域 UID：${if (uidScope.isEmpty()) "尚未解析" else uidText} · 配置包 ${configuredPackages.size} 个"
        }
        val embeddedScopeLine = if (embeddedPackages.isEmpty()) {
            ""
        } else {
            val activeUids = serviceStatus.embeddedCaptureUids.ifEmpty {
                bm.embeddedCaptureUids().sorted()
            }
            val activeText = if (activeUids.isEmpty()) "尚未解析" else activeUids.joinToString()
            "\n内置运行时全 TLS：配置包 ${embeddedPackages.size} 个 · 活动 UID $activeText"
        }
        backendStatusText.text = "${getString(base)}\n$capsLine$serviceLine$rootScopeLine$embeddedScopeLine"
        refreshPrivateDnsWarning()
    }

    private fun requestRootRuleRefreshIfActive() {
        if (DirectEngine.settings()?.isRootServiceEnabled() != true) return
        try {
            RootRelayService.requestRefresh(this)
        } catch (_: Throwable) {
        }
    }

    private fun requestRootReprobeIfActive() {
        if (DirectEngine.settings()?.isRootServiceEnabled() != true) return
        try {
            RootRelayService.requestReprobe(this)
        } catch (_: Throwable) {
        }
    }

    private fun setTlsTerminationSwitch(checked: Boolean) {
        tlsTerminationUiUpdate = true
        try {
            tlsTerminationSwitch.isChecked = checked
        } finally {
            tlsTerminationUiUpdate = false
        }
    }

    private fun setNat64FallbackSwitch(checked: Boolean) {
        nat64UiUpdate = true
        try {
            nat64FallbackSwitch.isChecked = checked
        } finally {
            nat64UiUpdate = false
        }
    }

    private fun disableNat64Fallback() {
        val store = DirectEngine.settings() ?: return
        val current = store.nat64FallbackConfig()
        if (current.enabled || current.riskAccepted) {
            store.setNat64FallbackConfig(current.copy(enabled = false, riskAccepted = false))
        }
        setNat64FallbackSwitch(false)
        refreshNat64Status()
    }

    private fun refreshNat64Status() {
        if (!::nat64StatusText.isInitialized) return
        val config = DirectEngine.settings()?.nat64FallbackConfig() ?: Nat64FallbackConfig.DISABLED
        val prepared = config.copy(enabled = true, riskAccepted = true).activationOrNull()
        val serviceStatus = RootRelayService.readStatus(this)
        val observationMatches = prepared != null &&
            serviceStatus.nat64Operator == prepared.operator &&
            serviceStatus.nat64ExpectedAsn == prepared.expectedAsn &&
            serviceStatus.nat64ExpectedRegion == prepared.expectedRegion
        nat64StatusText.text = when {
            config.enabled && observationMatches && serviceStatus.nat64FallbackActive &&
                serviceStatus.nat64Verified -> getString(
                R.string.nat64_status_active,
                serviceStatus.nat64ObservedIp,
                serviceStatus.nat64ObservedAsn,
                serviceStatus.nat64ObservedOperator,
                serviceStatus.nat64ObservedRegion,
            )
            config.enabled && observationMatches && serviceStatus.nat64ObservedAt > 0L &&
                !serviceStatus.nat64Verified -> getString(
                R.string.nat64_status_probe_failed,
                serviceStatus.nat64ProbeDetail.ifBlank { "无实测结果" },
            )
            config.enabled && prepared != null -> getString(
                R.string.nat64_status_selected,
                prepared.operator,
                prepared.expectedAsn,
                prepared.expectedRegion,
            )
            prepared != null -> getString(
                R.string.nat64_status_configured,
                prepared.operator,
                prepared.expectedAsn,
                prepared.expectedRegion,
            )
            else -> getString(R.string.nat64_status_off)
        }
        setNat64FallbackSwitch(config.enabled && config.activationOrNull() != null)
    }

    private fun showNat64ConfigDialog(enableAfterSave: Boolean) {
        val store = DirectEngine.settings() ?: return
        val current = store.nat64FallbackConfig()
        val padding = (20 * resources.displayMetrics.density).toInt()
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, 0, padding, 0)
        }
        fun field(hint: Int, value: String): EditText = EditText(this).also { edit ->
            edit.hint = getString(hint)
            edit.setText(value)
            edit.setSingleLine(true)
            edit.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            container.addView(edit)
        }
        val prefix = field(R.string.nat64_prefix_hint, current.prefix)
        val operator = field(R.string.nat64_operator_hint, current.operator)
        val asn = field(R.string.nat64_asn_hint, current.expectedAsn)
        val region = field(R.string.nat64_region_hint, current.expectedRegion)
        val dialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.nat64_config_title))
            .setView(container)
            .setPositiveButton(getString(R.string.dialog_ok), null)
            .setNegativeButton(getString(R.string.dialog_cancel), null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val candidate = Nat64FallbackConfig(
                    enabled = true,
                    prefix = prefix.text.toString(),
                    operator = operator.text.toString(),
                    expectedAsn = asn.text.toString(),
                    expectedRegion = region.text.toString(),
                    riskAccepted = true,
                ).normalized()
                if (candidate.activationOrNull() == null) {
                    prefix.error = getString(R.string.nat64_invalid_config)
                    dnsResultText.text = getString(R.string.nat64_invalid_config)
                    return@setOnClickListener
                }
                store.setNat64FallbackConfig(candidate.copy(enabled = false, riskAccepted = false))
                refreshNat64Status()
                requestRootReprobeIfActive()
                dialog.dismiss()
                if (enableAfterSave) confirmNat64Activation(candidate)
            }
        }
        dialog.show()
    }

    private fun confirmNat64Activation(raw: Nat64FallbackConfig) {
        val candidate = raw.copy(enabled = true, riskAccepted = true).normalized()
        val activation = candidate.activationOrNull() ?: run {
            dnsResultText.text = getString(R.string.nat64_invalid_config)
            refreshNat64Status()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.nat64_risk_title))
            .setMessage(
                getString(
                    R.string.nat64_risk_message,
                    activation.prefix,
                    activation.operator,
                    activation.expectedAsn,
                    activation.expectedRegion,
                ),
            )
            .setPositiveButton(getString(R.string.dialog_ok)) { _, _ ->
                DirectEngine.settings()?.setNat64FallbackConfig(candidate)
                setNat64FallbackSwitch(true)
                refreshNat64Status()
                requestRootReprobeIfActive()
            }
            .setNegativeButton(getString(R.string.dialog_cancel)) { _, _ ->
                setNat64FallbackSwitch(false)
                refreshNat64Status()
            }
            .setOnCancelListener {
                setNat64FallbackSwitch(false)
                refreshNat64Status()
            }
            .show()
    }

    private fun confirmInstallCa() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.ca_install_title))
            .setMessage(getString(R.string.ca_install_message))
            .setPositiveButton(getString(R.string.dialog_ok)) { _, _ -> installCaAsync() }
            .setNegativeButton(getString(R.string.dialog_cancel), null)
            .show()
    }

    private fun confirmRemoveCa() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.ca_remove_title))
            .setMessage(getString(R.string.ca_remove_message))
            .setPositiveButton(getString(R.string.dialog_ok)) { _, _ -> removeCaAsync() }
            .setNegativeButton(getString(R.string.dialog_cancel), null)
            .show()
    }

    private fun installCaAsync() {
        if (!caOperationInFlight.compareAndSet(false, true)) return
        setCaControlsBusy(true)
        backendExecutor.execute {
            val runtime = SniGateRuntime(applicationContext)
            val generated = runtime.ensureCaGenerated()
            val operation = generated.getOrNull()?.let { ca ->
                AndroidSystemCaInstaller(applicationContext).install(ca)
            }
            val message = operation?.detail ?: (
                "CA 生成失败：" +
                    (generated.exceptionOrNull()?.message ?: "未知错误").take(300)
                )
            lastSystemCaStatus = operation?.status ?: SystemCaStatus(
                SystemCaState.ERROR,
                detail = message,
            )
            caOperationInFlight.set(false)
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                setCaControlsBusy(false)
                caStatusText.text = formatCaStatus(lastSystemCaStatus)
                dnsResultText.text = message
                refreshBackendStatus()
            }
        }
    }

    private fun removeCaAsync() {
        if (!caOperationInFlight.compareAndSet(false, true)) return
        DirectEngine.settings()?.setTlsTerminationEnabled(false)
        setTlsTerminationSwitch(false)
        disableNat64Fallback()
        setCaControlsBusy(true)
        backendExecutor.execute {
            val runtime = SniGateRuntime(applicationContext)
            runtime.stop()
            val ca = runCatching {
                DeviceCertificateAuthority.load(runtime.certificateFile())
            }.getOrNull()
            val operation = AndroidSystemCaInstaller(applicationContext).remove(ca)
            lastSystemCaStatus = operation.status
            caOperationInFlight.set(false)
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                setCaControlsBusy(false)
                caStatusText.text = formatCaStatus(lastSystemCaStatus)
                dnsResultText.text = operation.detail
                requestRootRuleRefreshIfActive()
                refreshBackendStatus()
            }
        }
    }

    private fun refreshCaStatusAsync() {
        if (caOperationInFlight.get() || !caStatusInFlight.compareAndSet(false, true)) return
        backendExecutor.execute {
            val runtime = SniGateRuntime(applicationContext)
            val ca = runCatching {
                DeviceCertificateAuthority.load(runtime.certificateFile())
            }.getOrNull()
            val status = try {
                AndroidSystemCaInstaller(applicationContext).status(ca)
            } catch (t: Throwable) {
                SystemCaStatus(SystemCaState.ERROR, detail = t.message.orEmpty().take(300))
            }
            lastSystemCaStatus = status
            caStatusInFlight.set(false)
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                caStatusText.text = formatCaStatus(status)
                btnRemoveCa.isEnabled = status.state != SystemCaState.NOT_GENERATED
                if (status.state != SystemCaState.TRUSTED) {
                    DirectEngine.settings()?.setTlsTerminationEnabled(false)
                    setTlsTerminationSwitch(false)
                    disableNat64Fallback()
                    requestRootRuleRefreshIfActive()
                }
            }
        }
    }

    private fun setCaControlsBusy(busy: Boolean) {
        btnInstallCa.isEnabled = !busy
        btnRemoveCa.isEnabled = !busy
        tlsTerminationSwitch.isEnabled = !busy
        if (busy) caStatusText.text = getString(R.string.ca_operation_running)
    }

    private fun formatCaStatus(status: SystemCaStatus): String {
        val label = when (status.state) {
            SystemCaState.NOT_GENERATED -> "未生成"
            SystemCaState.GENERATED -> "已生成，未安装"
            SystemCaState.TRUSTED -> "浏览器用户信任已生效"
            SystemCaState.SYSTEM_ONLY -> "仅系统信任（浏览器不兼容）"
            SystemCaState.SYSTEM_USER_CONFLICT -> "系统/用户证书冲突，需重启"
            SystemCaState.BROWSER_POLICY_REQUIRED -> "Edge CA 策略未生效"
            SystemCaState.BROWSER_POLICY_UNSUPPORTED -> "Edge 版本不支持 CA 策略"
            SystemCaState.STAGED_REBOOT_REQUIRED -> "已暂存，等待重启"
            SystemCaState.REMOVE_PENDING -> "等待重启卸载"
            SystemCaState.FOREIGN_MODULE -> "模块 ID 冲突"
            SystemCaState.ERROR -> "错误"
        }
        val fingerprint = status.fingerprintSha256
            .takeIf { it.isNotBlank() }
            ?.let { " · SHA-256 ${it.take(16)}…" }
            .orEmpty()
        val detail = status.detail.takeIf { it.isNotBlank() }?.let { "\n$it" }.orEmpty()
        return "每设备 CA：$label$fingerprint$detail"
    }

    private fun probeRootAsync() {
        val bm = backendManager ?: return
        if (rootProbeInFlight.get()) return
        rootProbeInFlight.set(true)
        refreshBackendStatus()
        backendExecutor.execute {
            try {
                bm.rootCapabilities()
            } catch (t: Throwable) {
                // 探测失败保留缓存空/旧值，UI 显示不可用
            } finally {
                rootProbeInFlight.set(false)
                runOnUiThread {
                    if (!isFinishing) refreshBackendStatus()
                }
            }
        }
    }

    /** §35：Root 模式生效且系统 Private DNS 非关闭 → 提示可能经 DoT 绕过直连规则。 */
    private fun refreshPrivateDnsWarning() {
        val bm = backendManager ?: return
        val rootActive = bm.isRootBackendActive()
        val privateDnsNotOff = PrivateDnsState.detect(this) != PrivateDnsMode.OFF
        privateDnsWarning.visibility =
            if (rootActive && privateDnsNotOff) View.VISIBLE else View.GONE
    }

    /** 安装应用多选对话框。 */
    private fun showAppPicker() {
        val pm = packageManager
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        // 能匹配 example.com 可能只是注册了特定深链，并不代表通用浏览器。只有匹配的
        // http(s) IntentFilter 没有 authority 限制时，才把该包标为通用网页处理器。
        val genericWebPackages = try {
            val flags = android.content.pm.PackageManager.MATCH_ALL or
                android.content.pm.PackageManager.GET_RESOLVED_FILTER
            pm.queryIntentActivities(browserIntent, flags)
                .asSequence()
                .filter { resolved ->
                    resolved.filter?.let { filter ->
                        (filter.hasDataScheme("http") || filter.hasDataScheme("https")) &&
                            filter.authoritiesIterator() == null
                    } == true
                }
                .mapTo(LinkedHashSet()) { it.activityInfo.packageName }
        } catch (_: Throwable) {
            emptySet()
        }
        val apps = try {
            pm.getInstalledApplications(0)
                .asSequence()
                .filter { it.packageName != packageName }
                .sortedWith(
                    compareBy<android.content.pm.ApplicationInfo> {
                        when {
                            it.packageName in PLATFORM_CLIENT_PACKAGES -> 0
                            it.packageName in genericWebPackages -> 1
                            else -> 2
                        }
                    }
                        .thenBy { it.loadLabel(pm).toString().lowercase() }
                        .thenBy { it.packageName },
                )
                .toList()
        } catch (t: Throwable) {
            emptyList()
        }
        if (apps.isEmpty()) {
            dnsResultText.text = getString(R.string.app_picker_empty)
            return
        }
        val labels = apps.map { app ->
            val kind = when {
                app.packageName in PLATFORM_CLIENT_PACKAGES -> "[平台客户端] "
                app.packageName in genericWebPackages -> "[通用网页] "
                else -> "[其他应用] "
            }
            "$kind${app.loadLabel(pm)} · ${app.packageName}"
        }
        val packages = apps.map { it.packageName }
        val selected = DirectEngine.settings()?.scopedPackages() ?: emptySet()

        val checked = BooleanArray(packages.size) { packages[it] in selected }

        AlertDialog.Builder(this)
            // AlertController 原生多选列表会为按钮预留空间；自定义 ListView 在部分横屏 ROM
            // 上会按全部条目测量，把“确定/取消”挤出窗口。
            .setTitle(
                "${getString(R.string.app_picker_title)}\n${getString(R.string.app_picker_hint)}",
            )
            .setMultiChoiceItems(labels.toTypedArray(), checked) { _, which, isChecked ->
                if (which in checked.indices) checked[which] = isChecked
            }
            .setPositiveButton(getString(R.string.dialog_ok)) { _, _ ->
                val result = LinkedHashSet<String>()
                for (i in checked.indices) {
                    if (checked[i]) result.add(packages[i])
                }
                DirectEngine.settings()?.let { settings ->
                    settings.setScopedPackages(result)
                    // 全 TLS 是 scope 的严格子集；取消宿主作用域时同步撤销其扩大接管授权。
                    settings.setEmbeddedTlsCapturePackages(
                        settings.embeddedTlsCapturePackages().intersect(result),
                    )
                }
                requestRootRuleRefreshIfActive()
            }
            .setNegativeButton(getString(R.string.dialog_cancel), null)
            .show()
    }

    /**
     * Android 没有原生 Electron；这里的 Electron-like 指 WebView/Cronet/GeckoView/CEF 等宿主。
     * 二次选择只允许当前 SELECTED scope 的子集，避免在 ALL/EXCLUDED 模式扩大 HTTPS 接管面。
     */
    private fun showEmbeddedTlsPicker() {
        val settings = DirectEngine.settings() ?: return
        val scoped = settings.scopedPackages()
        if (settings.appScopeMode() != AppScopeMode.SELECTED_APPS || scoped.isEmpty()) {
            dnsResultText.text = getString(R.string.embedded_tls_picker_empty)
            return
        }
        val pm = packageManager
        val apps = scoped.mapNotNull { pkg ->
            try {
                pm.getApplicationInfo(pkg, 0)
            } catch (_: Throwable) {
                null
            }
        }.sortedWith(
            compareBy<android.content.pm.ApplicationInfo> {
                it.loadLabel(pm).toString().lowercase()
            }.thenBy { it.packageName },
        )
        if (apps.isEmpty()) {
            dnsResultText.text = getString(R.string.embedded_tls_picker_empty)
            return
        }
        val labels = apps.map { "${it.loadLabel(pm)} · ${it.packageName}" }
        val packages = apps.map { it.packageName }
        val selected = settings.embeddedTlsCapturePackages().intersect(scoped)
        val checked = BooleanArray(packages.size) { packages[it] in selected }
        AlertDialog.Builder(this)
            .setTitle(
                "${getString(R.string.embedded_tls_picker_title)}\n" +
                    getString(R.string.embedded_tls_picker_hint),
            )
            .setMultiChoiceItems(labels.toTypedArray(), checked) { _, which, isChecked ->
                if (which in checked.indices) checked[which] = isChecked
            }
            .setPositiveButton(getString(R.string.dialog_ok)) { _, _ ->
                val result = LinkedHashSet<String>()
                for (i in checked.indices) {
                    if (checked[i]) result += packages[i]
                }
                settings.setEmbeddedTlsCapturePackages(result.intersect(scoped))
                requestRootRuleRefreshIfActive()
                refreshBackendStatus()
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
        backendExecutor.shutdownNow()
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
            sb.append("\nLSPosed 作用域：").append(service.scope.joinToString(", "))
            frameworkSummary = sb.toString()
            refreshHookHeartbeat()
        }
    }

    override fun onServiceDied(service: XposedService) {
        runOnUiThread {
            statusText.text = getString(R.string.status_disconnected)
            statusIndicator.setBackgroundResource(R.drawable.shape_circle_red)
            refreshHookHeartbeat()
        }
    }

    override fun onRemoteSettingsStateChanged(ready: Boolean, message: String) {
        runOnUiThread {
            if (!isFinishing) refreshHookHeartbeat()
        }
    }

    override fun onHookHeartbeatChanged() {
        runOnUiThread {
            if (!isFinishing) refreshHookHeartbeat()
        }
    }

    private fun refreshHookHeartbeat() {
        val app = application as App
        val heartbeat = DirectEngine.settings()?.hookHeartbeats()?.firstOrNull()
        val hitTime = heartbeat?.timestamp?.takeIf { it > 0L }?.let { timestamp ->
            java.text.DateFormat.getDateTimeInstance(
                java.text.DateFormat.SHORT,
                java.text.DateFormat.MEDIUM,
            ).format(java.util.Date(timestamp))
        }.orEmpty()
        val line = when {
            heartbeat == null -> "Hook 状态：尚未收到目标进程运行证明"
            System.currentTimeMillis() - heartbeat.timestamp > HOOK_HEARTBEAT_STALE_MS ->
                "Hook 心跳：已过期 · 最近 ${heartbeat.packageName} · $hitTime"
            else -> "Hook 心跳：${heartbeat.packageName} · ${heartbeat.processName} · $hitTime · generation ${heartbeat.routeGeneration} · ${heartbeat.framework} API ${heartbeat.apiVersion} · DNS 命中 ${heartbeat.hitCount}"
        }
        val remoteLine = if (app.remoteSettingsReady) {
            "远程配置：已同步"
        } else {
            "远程配置：${app.remoteSettingsMessage}"
        }
        frameworkText.text = listOf(frameworkSummary, remoteLine, line)
            .filter { it.isNotBlank() }
            .joinToString("\n")
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
            BackendMode.XPOSED_ONLY ->
                if (bm.isRootBackendActive()) "Xposed + Root Transparent ACTIVE" else "Xposed DNS"
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
     * su / iptables 探测禁止跑在主线程（KernelSU 弹授权或命令超时会 ANR）。
     */
    private fun startProxy() {
        val bm = backendManager ?: return
        when (DirectEngine.settings()?.backendMode() ?: BackendMode.AUTO) {
            BackendMode.AUTO -> {
                vpnBtn.isEnabled = false
                backendExecutor.execute {
                    val resolved = try {
                        bm.resolveAuto()
                    } catch (t: Throwable) {
                        BackendMode.VPN
                    }
                    runOnUiThread {
                        if (isFinishing) return@runOnUiThread
                        vpnBtn.isEnabled = true
                        refreshBackendStatus()
                        if (resolved == BackendMode.ROOT_TRANSPARENT) {
                            AlertDialog.Builder(this)
                                .setTitle(getString(R.string.root_dialog_title))
                                .setMessage(getString(R.string.root_dialog_message))
                                .setPositiveButton(getString(R.string.root_dialog_use_root)) { _, _ ->
                                    startBackendAsync(BackendMode.ROOT_TRANSPARENT)
                                }
                                .setNegativeButton(getString(R.string.root_dialog_use_vpn)) { _, _ ->
                                    startVpnFlow()
                                }
                                .show()
                        } else {
                            startVpnFlow()
                        }
                    }
                }
            }
            BackendMode.ROOT_TRANSPARENT -> startBackendAsync(BackendMode.ROOT_TRANSPARENT)
            BackendMode.VPN -> startVpnFlow()
            BackendMode.XPOSED_ONLY -> startBackendAsync(BackendMode.XPOSED_ONLY)
        }
    }

    private fun startBackendAsync(mode: BackendMode) {
        val bm = backendManager ?: return
        vpnBtn.isEnabled = false
        val beforeGeneration = try {
            RootRelayService.requestStart(this, mode)
        } catch (t: Throwable) {
            vpnBtn.isEnabled = true
            dnsResultText.text = getString(R.string.proxy_start_failed, t.message ?: "无法启动前台服务")
            return
        }
        backendExecutor.execute {
            val serviceStatus = RootRelayService.awaitTerminal(this, beforeGeneration)
            val ok = serviceStatus.phase == RootRelayService.Phase.ACTIVE
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                vpnBtn.isEnabled = true
                if (!ok) {
                    val caps = bm.cachedRootCapabilities()
                    val detail = serviceStatus.message.ifBlank {
                        caps?.missingRequired()?.takeIf { it.isNotEmpty() }?.joinToString()
                            ?: "Root 后端启动失败"
                    }
                    dnsResultText.text = getString(R.string.proxy_start_failed, detail)
                }
                updateVpnUi()
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
        if (backendManager?.currentMode() == BackendMode.VPN || DnsVpnService.isActive()) {
            backendManager?.stop()
        } else {
            try {
                RootRelayService.requestStop(this)
            } catch (t: Throwable) {
                backendManager?.stop()
            }
        }
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

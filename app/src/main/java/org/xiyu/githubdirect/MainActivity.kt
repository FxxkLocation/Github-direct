package org.xiyu.githubdirect

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.Button
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import io.github.libxposed.service.XposedService
import org.xiyu.githubdirect.dns.BuiltinIPs
import org.xiyu.githubdirect.dns.DohResolver
import org.xiyu.githubdirect.dns.GithubDomains
import org.xiyu.githubdirect.vpn.DnsVpnService
import java.net.InetAddress

class MainActivity : Activity(), App.ServiceStateListener {

    private lateinit var statusText: TextView
    private lateinit var statusIndicator: View
    private lateinit var frameworkText: TextView
    private lateinit var dnsResultText: TextView
    private lateinit var testBtn: Button
    private lateinit var refreshBtn: Button
    private lateinit var vpnBtn: Button
    private lateinit var tgBtn: Button
    private lateinit var starBtn: Button
    private lateinit var vpnStatusText: TextView
    private lateinit var progressSpinner: ProgressBar
    private lateinit var logoIcon: ImageView
    private var syncAnimatorSet: AnimatorSet? = null

    private val VPN_REQUEST_CODE = 100

    private val testDomains = arrayOf(
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "gist.github.com",
        "github.githubassets.com",
        "avatars.githubusercontent.com",
        "objects.githubusercontent.com",
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.status)
        statusIndicator = findViewById(R.id.status_indicator)
        frameworkText = findViewById(R.id.framework_info)
        dnsResultText = findViewById(R.id.dns_results)
        testBtn = findViewById(R.id.btn_test)
        refreshBtn = findViewById(R.id.btn_refresh)
        vpnBtn = findViewById(R.id.btn_vpn)
        tgBtn = findViewById(R.id.btn_tg)
        starBtn = findViewById(R.id.btn_star)
        vpnStatusText = findViewById(R.id.vpn_status)
        progressSpinner = findViewById(R.id.progress_spinner)
        logoIcon = findViewById(R.id.logo)

        statusText.text = "等待框架连接..."
        frameworkText.text = ""
        dnsResultText.text = "点击上方按钮进行网络测试"

        testBtn.setOnClickListener { runDnsTest() }
        refreshBtn.setOnClickListener { runConnectivityTest() }
        vpnBtn.setOnClickListener { toggleVpn() }
        
        tgBtn.setOnClickListener { openUrl("https://t.me/+BUfEUGzViTg2YWU1") }
        starBtn.setOnClickListener { openUrl("https://github.com/FxxkLocation/Github-direct") }

        updateVpnUi()
        (application as App).addServiceStateListener(this)
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
        super.onDestroy()
        (application as App).removeServiceStateListener(this)
    }

    override fun onServiceBind(service: XposedService) {
        runOnUiThread {
            statusText.text = "已激活"
            statusIndicator.setBackgroundResource(R.drawable.shape_circle_green)
            val sb = StringBuilder()
            sb.append("框架: ").append(service.frameworkName)
                .append(" v").append(service.frameworkVersion)
                .append(" (").append(service.frameworkVersionCode).append(")")  
            sb.append("\nAPI 版本: ").append(service.apiVersion)
            sb.append("\n作用域: ").append(service.scope.joinToString(", "))     
            frameworkText.text = sb.toString()
        }
    }

    override fun onServiceDied(service: XposedService) {
        runOnUiThread {
            statusText.text = "框架已断开"
            statusIndicator.setBackgroundResource(R.drawable.shape_circle_red)  
        }
    }

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
        testBtn.isEnabled = false
        refreshBtn.isEnabled = false
        testBtn.alpha = 0.5f
        refreshBtn.alpha = 0.5f
    }

    private fun stopLoading() {
        progressSpinner.visibility = View.INVISIBLE
        syncAnimatorSet?.cancel()
        logoIcon.scaleX = 1f
        logoIcon.scaleY = 1f
        logoIcon.alpha = 1f
        testBtn.isEnabled = true
        refreshBtn.isEnabled = true
        testBtn.alpha = 1.0f
        refreshBtn.alpha = 1.0f
    }

    private fun runDnsTest() {
        startLoading()
        dnsResultText.text = "正在解析 GitHub 域名...\n"
        Thread {
            val sb = StringBuilder()
            sb.append("=== DNS 解析状态 ===\n\n")
            for (domain in testDomains) {
                sb.append("▶ ").append(domain).append("\n")
                try {
                    val addrs = DohResolver.resolve(domain)
                    if (addrs != null && addrs.isNotEmpty()) {
                        sb.append("  [DoH] ")
                        for ((i, addr) in addrs.withIndex()) {
                            if (i > 0) sb.append(", ")
                            sb.append(addr.hostAddress)
                        }
                        sb.append("\n")
                    } else {
                        // DoH fallback
                        val builtin = BuiltinIPs.lookup(domain)
                        if (builtin != null && builtin.isNotEmpty()) {
                            sb.append("  [后备IP] ")
                            for ((i, addr) in builtin.withIndex()) {
                                if (i > 0) sb.append(", ")
                                sb.append(addr.hostAddress)
                            }
                            sb.append("\n")
                        } else {
                            sb.append("  [解析失败]\n")
                        }
                    }
                } catch (e: Exception) {
                    sb.append("  [错误]: ").append(e.message).append("\n")    
                }
                sb.append("\n")
            }
            runOnUiThread {
                dnsResultText.text = sb.toString()
                stopLoading()
            }
        }.start()
    }

    private fun runConnectivityTest() {
        startLoading()
        dnsResultText.text = "正在测试 GitHub 连通性...\n"
        Thread {
            val sb = StringBuilder()
            sb.append("=== GitHub 连通性 ===\n\n")
            for (domain in testDomains) {
                sb.append("▶ ").append(domain).append(": ")
                try {
                    val start = System.currentTimeMillis()
                    val addr = InetAddress.getByName(domain)
                    val elapsed = System.currentTimeMillis() - start
                    val reachable = addr.isReachable(3000)
                    sb.append(addr.hostAddress)
                        .append(" (").append(elapsed).append("ms)")
                    if (reachable) {
                        sb.append(" [可达]")
                    } else {
                        sb.append(" ~ [ICMP 被过滤或超时]")
                    }
                } catch (e: Exception) {
                    sb.append("[错误]: ").append(e.message)
                }
                sb.append("\n")
            }
            runOnUiThread {
                dnsResultText.text = sb.toString()
                stopLoading()
            }
        }.start()
    }

    // ==================== VPN Controls ====================

    private fun toggleVpn() {
        if (DnsVpnService.isActive()) {
            stopVpn()
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            launchVpnService()
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, DnsVpnService::class.java)
        intent.action = DnsVpnService.ACTION_STOP
        startService(intent)
        vpnBtn.postDelayed({ updateVpnUi() }, 500)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                launchVpnService()
            } else {
                dnsResultText.text = "[警告] VPN 授权被拒绝"
            }
        }
    }

    private fun launchVpnService() {
        val intent = Intent(this, DnsVpnService::class.java)
        intent.action = DnsVpnService.ACTION_START
        startForegroundService(intent)
        vpnBtn.postDelayed({ updateVpnUi() }, 1000)
    }

    private fun updateVpnUi() {
        if (DnsVpnService.isActive()) {
            vpnBtn.text = "关闭代理"
            vpnBtn.setBackgroundResource(R.drawable.btn_danger)
            vpnStatusText.text = "已开启 — 流量正在代理中"
            vpnStatusText.setTextColor(0xFF2DA44E.toInt())
        } else {
            vpnBtn.text = "开启代理"
            vpnBtn.setBackgroundResource(R.drawable.btn_primary)
            vpnStatusText.text = "已停止 — 开启以代理外部网络请求"      
            vpnStatusText.setTextColor(0xFF57606A.toInt())
        }
    }
}

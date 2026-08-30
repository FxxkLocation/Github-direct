package org.xiyu.githubdirect.root

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.data.AndroidSettingsStore
import java.io.File

enum class SystemCaState {
    NOT_GENERATED,
    GENERATED,
    /** System/APEX trust is active and every selected browser policy that is required is present. */
    TRUSTED,
    /** Browser navigation works, but Android MediaHTTP/native app stacks cannot trust the CA. */
    USER_ONLY,
    /** The CA exists only as a system root; Chromium-family built-in verifiers may ignore it. */
    SYSTEM_ONLY,
    /** The same DER is in user and system stores; the installer must remove the user duplicate. */
    SYSTEM_USER_CONFLICT,
    /** Platform user trust exists, but selected Edge lacks the CA + scoped-DNS policy bundle. */
    BROWSER_POLICY_REQUIRED,
    /** Selected Edge predates Android support for the complete CA + DNS policy bundle. */
    BROWSER_POLICY_UNSUPPORTED,
    STAGED_REBOOT_REQUIRED,
    REMOVE_PENDING,
    FOREIGN_MODULE,
    ERROR,
}

data class SystemCaStatus(
    val state: SystemCaState,
    val fingerprintSha256: String = "",
    val detail: String = "",
    val systemActive: Boolean = false,
    val userTrusted: Boolean = false,
    val browserPolicyRequired: Boolean = false,
    val browserPolicyTrusted: Boolean = false,
)

data class SystemCaOperation(
    val success: Boolean,
    val status: SystemCaStatus,
    val rebootRequired: Boolean,
    val detail: String,
)

/**
 * Installs a per-device public CA without ever copying its private key.
 *
 * Android app/media stacks receive the public DER through a scoped Magisk/KernelSU system module.
 * Selected Edge receives the same DER through its managed CACertificates policy. The old user-root
 * copy is removed only after system trust is active, so the same DER is never left duplicated in
 * Android's user and system stores. The per-device private key never leaves app-private storage.
 */
class AndroidSystemCaInstaller(
    context: Context,
    private val shell: RootShell = RootShell(),
) {
    private val app = context.applicationContext
    private val settings by lazy { AndroidSettingsStore(app) }

    fun status(ca: DeviceCertificateAuthority?): SystemCaStatus {
        if (ca == null) return SystemCaStatus(SystemCaState.NOT_GENERATED)
        val system = systemStatus(ca)
        if (system.state == SystemCaState.FOREIGN_MODULE || system.state == SystemCaState.ERROR) {
            return system
        }
        val user = runKeyChain("status", ca)
        if (!user.ok) {
            return SystemCaStatus(
                SystemCaState.ERROR,
                ca.fingerprintSha256,
                "用户信任库检测失败：${user.detail}",
            )
        }
        val policyRequired = edgePolicyRequired()
        val policySupported = !policyRequired || edgePolicySupported()
        val browserPolicy = if (policyRequired && policySupported) {
            runBrowserPolicy("status", ca)
        } else {
            BrowserPolicyResult(ok = true, present = false, packageName = EDGE_PACKAGE)
        }
        if (!browserPolicy.ok) {
            return SystemCaStatus(
                SystemCaState.ERROR,
                ca.fingerprintSha256,
                "Edge CA/DNS 策略检测失败：${browserPolicy.detail}",
                systemActive = system.systemActive,
                userTrusted = user.present,
                browserPolicyRequired = policyRequired,
            )
        }
        val systemActive = system.systemActive
        val state = when {
            user.present && systemActive -> SystemCaState.SYSTEM_USER_CONFLICT
            systemActive && policyRequired && !policySupported ->
                SystemCaState.BROWSER_POLICY_UNSUPPORTED
            systemActive && policyRequired && !browserPolicy.present ->
                SystemCaState.BROWSER_POLICY_REQUIRED
            system.state == SystemCaState.REMOVE_PENDING -> SystemCaState.REMOVE_PENDING
            systemActive -> SystemCaState.TRUSTED
            system.state == SystemCaState.STAGED_REBOOT_REQUIRED ->
                SystemCaState.STAGED_REBOOT_REQUIRED
            user.present && policyRequired && !policySupported ->
                SystemCaState.BROWSER_POLICY_UNSUPPORTED
            user.present && policyRequired && !browserPolicy.present ->
                SystemCaState.BROWSER_POLICY_REQUIRED
            user.present -> SystemCaState.USER_ONLY
            else -> SystemCaState.GENERATED
        }
        val detail = when (state) {
            SystemCaState.TRUSTED ->
                buildString {
                    append("系统/APEX 信任已生效，可供 Android 媒体与应用网络栈使用")
                    if (policyRequired) append("；Edge CA 与受管 DNS 策略已验证")
                }
            SystemCaState.USER_ONLY ->
                "仅浏览器用户信任已生效（${user.alias}）；Android 媒体/应用网络栈仍不信任"
            SystemCaState.SYSTEM_ONLY ->
                "仅系统/APEX 信任已生效；Chromium 系浏览器不会把它当作用户根"
            SystemCaState.SYSTEM_USER_CONFLICT ->
                "系统/APEX 信任已生效，但同一证书仍在用户信任库；请再次执行安装以精确移除用户副本"
            SystemCaState.BROWSER_POLICY_REQUIRED ->
                "系统 CA 已安装，但所选 Edge 尚未载入 CA/受管 DNS 策略；请再次执行安装"
            SystemCaState.BROWSER_POLICY_UNSUPPORTED ->
                "所选 Edge 版本低于 147，不支持完整 Android CA/DNS 策略；已阻止 TLS 终止"
            SystemCaState.STAGED_REBOOT_REQUIRED ->
                "系统 CA 模块已暂存；重启后再次执行安装以完成用户副本迁移"
            SystemCaState.REMOVE_PENDING ->
                "旧系统 CA 模块已排队移除；重启后可仅保留浏览器用户 CA"
            else -> "每设备 CA 已生成，尚未安装到浏览器用户信任库"
        }
        return SystemCaStatus(
            state,
            ca.fingerprintSha256,
            detail,
            systemActive = systemActive,
            userTrusted = user.present,
            browserPolicyRequired = policyRequired,
            browserPolicyTrusted = browserPolicy.present,
        )
    }

    private fun systemStatus(ca: DeviceCertificateAuthority?): SystemCaStatus {
        if (ca == null) return SystemCaStatus(SystemCaState.NOT_GENERATED)
        val result = shell.execTrustedScript(statusScript(ca), timeoutSec = 6)
        if (!result.ok) {
            return SystemCaStatus(
                SystemCaState.ERROR,
                ca.fingerprintSha256,
                result.diagnosticSummary(),
            )
        }
        val values = result.out.lineSequence()
            .mapNotNull { line ->
                val split = line.trim().split('=', limit = 2)
                if (split.size == 2) split[0] to split[1] else null
            }
            .toMap()
        val moduleExists = values["module"] == "1"
        val owned = values["owned"] == "1"
        val staged = values["staged"] == "1"
        val removePending = values["remove"] == "1"
        val apexTrusted = values["apex"] == "1"
        val legacyTrusted = values["legacy"] == "1"
        val trusted = if (Build.VERSION.SDK_INT >= 34) apexTrusted else apexTrusted || legacyTrusted
        val state = when {
            moduleExists && !owned -> SystemCaState.FOREIGN_MODULE
            removePending -> SystemCaState.REMOVE_PENDING
            trusted -> SystemCaState.TRUSTED
            staged -> SystemCaState.STAGED_REBOOT_REQUIRED
            moduleExists -> SystemCaState.ERROR
            else -> SystemCaState.GENERATED
        }
        val detail = when (state) {
            SystemCaState.TRUSTED -> "系统信任库已加载 ${ca.androidFileName}"
            SystemCaState.STAGED_REBOOT_REQUIRED -> "Root 模块已暂存，重启后进入系统信任库"
            SystemCaState.REMOVE_PENDING -> "卸载已排队，重启后移除系统信任"
            SystemCaState.FOREIGN_MODULE -> "模块 ID $MODULE_ID 已被非本应用目录占用"
            SystemCaState.ERROR -> "已存在的本模块证书与当前每设备 CA 不一致；请先卸载并重启"
            SystemCaState.GENERATED -> "每设备 CA 已生成，尚未安装"
            else -> ""
        }
        return SystemCaStatus(
            state,
            ca.fingerprintSha256,
            detail,
            systemActive = trusted,
        )
    }

    @Synchronized
    fun install(ca: DeviceCertificateAuthority): SystemCaOperation {
        val before = status(ca)
        when (before.state) {
            SystemCaState.TRUSTED -> return SystemCaOperation(
                true,
                before,
                rebootRequired = false,
                detail = "系统/APEX CA 与所需浏览器策略均已验证",
            )
            SystemCaState.FOREIGN_MODULE ->
                return SystemCaOperation(false, before, false, before.detail)
            else -> Unit
        }

        // A browser-policy status error is repairable by reinstalling the owned policy. Only a
        // real legacy system-module error must stop before any trust-store mutation.
        val systemGuard = systemStatus(ca)
        if (systemGuard.state == SystemCaState.FOREIGN_MODULE ||
            systemGuard.state == SystemCaState.ERROR
        ) {
            return SystemCaOperation(false, systemGuard, false, systemGuard.detail)
        }

        val policyRequired = edgePolicyRequired()
        if (policyRequired && !edgePolicySupported()) {
            val failed = SystemCaStatus(
                SystemCaState.BROWSER_POLICY_UNSUPPORTED,
                ca.fingerprintSha256,
                "所选 Edge 版本低于 $MIN_EDGE_POLICY_MAJOR，不支持完整 CA/DNS 策略",
                userTrusted = before.userTrusted,
                browserPolicyRequired = true,
            )
            return SystemCaOperation(false, failed, false, failed.detail)
        }

        if (policyRequired) {
            val policyInstall = runBrowserPolicy("install", ca)
            if (!policyInstall.ok || !policyInstall.present) {
                val failed = SystemCaStatus(
                    SystemCaState.ERROR,
                    ca.fingerprintSha256,
                    "Edge CA/DNS 策略安装失败：${policyInstall.detail}",
                    userTrusted = before.userTrusted,
                    browserPolicyRequired = true,
                )
                return SystemCaOperation(false, failed, false, failed.detail)
            }
        }

        val systemInstall = installSystemForApps(ca)
        if (!systemInstall.success) return systemInstall

        // Keep the current user root until system/APEX trust is visible. This preserves browser
        // connectivity when a root implementation cannot inject the current boot namespace and
        // needs one reboot. Calling install again after reboot completes the exact migration.
        val systemAfter = systemStatus(ca)
        if (!systemAfter.systemActive) {
            val staged = status(ca)
            return SystemCaOperation(
                success = true,
                status = staged,
                rebootRequired = true,
                detail = "系统 CA 模块已暂存；重启后再次执行安装以移除旧用户 CA 副本",
            )
        }

        val userRemoval = runKeyChain("remove", ca)
        if (!userRemoval.ok || userRemoval.present) {
            val failed = SystemCaStatus(
                SystemCaState.SYSTEM_USER_CONFLICT,
                ca.fingerprintSha256,
                "系统信任已生效，但旧用户 CA 无法精确移除：${userRemoval.detail}",
                systemActive = true,
                userTrusted = true,
                browserPolicyRequired = policyRequired,
                browserPolicyTrusted = policyRequired,
            )
            return SystemCaOperation(false, failed, false, failed.detail)
        }
        notifyTrustStoreChanged()
        val after = status(ca)
        return SystemCaOperation(
            success = after.state == SystemCaState.TRUSTED,
            status = after,
            rebootRequired = false,
            detail = if (after.state == SystemCaState.TRUSTED) {
                "每设备 CA 已进入系统/APEX 信任，Edge 策略已就绪，旧用户副本已移除；私钥仍仅位于应用私有目录"
            } else {
                after.detail
            },
        )
    }

    /** Explicit non-browser compatibility path; not used by the default UI. */
    @Synchronized
    internal fun installSystemForApps(ca: DeviceCertificateAuthority): SystemCaOperation {
        val before = systemStatus(ca)
        when (before.state) {
            SystemCaState.TRUSTED -> return SystemCaOperation(
                true, before, rebootRequired = false, detail = "CA 已受系统信任",
            )
            SystemCaState.FOREIGN_MODULE -> return SystemCaOperation(
                false, before, rebootRequired = false, detail = before.detail,
            )
            SystemCaState.REMOVE_PENDING -> return SystemCaOperation(
                false,
                before,
                rebootRequired = true,
                detail = "本模块正在等待卸载；请先重启，再重新安装 CA",
            )
            SystemCaState.ERROR -> return SystemCaOperation(
                false, before, rebootRequired = false, detail = before.detail,
            )
            else -> Unit
        }

        val staging = try {
            buildStagingModule(ca)
        } catch (t: Throwable) {
            val failed = SystemCaStatus(
                SystemCaState.ERROR,
                ca.fingerprintSha256,
                failureText(t),
            )
            return SystemCaOperation(false, failed, false, "CA 模块暂存失败：${failed.detail}")
        }
        val install = shell.execTrustedScript(
            installScript(staging),
            timeoutSec = 20,
        )
        if (!install.ok) {
            val failed = SystemCaStatus(
                SystemCaState.ERROR,
                ca.fingerprintSha256,
                install.diagnosticSummary(),
            )
            return SystemCaOperation(false, failed, false, "Root 模块安装失败：${failed.detail}")
        }

        // 同时注入 PID 1 与 Zygote mount namespace。只更新 PID 1 不会传播到已经
        // unshare 的 Zygote，之后启动的浏览器/媒体进程仍看不到 Conscrypt CA。
        // 失败不撤销持久模块，重启时 post-fs-data/service 会重试。
        val immediate = shell.execTrustedScript(immediateInjectScript(), timeoutSec = 12)
        val after = systemStatus(ca)
        val trustedNow = after.state == SystemCaState.TRUSTED
        val detail = when {
            trustedNow -> "CA 已安装并进入当前系统信任视图；仍建议重启以刷新已运行应用"
            immediate.ok -> "CA 模块已安装；当前进程尚未观察到信任库更新，需重启"
            else -> "CA 模块已安装；即时 APEX 注入失败，重启时将再次加载（${immediate.diagnosticSummary(180)}）"
        }
        return SystemCaOperation(
            success = after.state == SystemCaState.TRUSTED ||
                after.state == SystemCaState.STAGED_REBOOT_REQUIRED,
            status = after,
            rebootRequired = !trustedNow,
            detail = detail,
        )
    }

    @Synchronized
    fun remove(ca: DeviceCertificateAuthority?): SystemCaOperation {
        val before = status(ca)
        val browserRemoval = if (ca != null && edgeInstalled()) {
            runBrowserPolicy("remove", ca)
        } else {
            BrowserPolicyResult(ok = true, present = false, packageName = EDGE_PACKAGE)
        }
        val userRemoval = if (ca != null) {
            runKeyChain("remove", ca)
        } else {
            KeyChainResult(ok = true, present = false, detail = "CA 文件不存在，未删除未知用户证书")
        }
        notifyTrustStoreChanged()

        val moduleRemoval = if (before.state == SystemCaState.FOREIGN_MODULE) {
            RootShell.Result(73, "", "模块 ID 被其他模块占用", timedOut = false)
        } else {
            shell.execTrustedScript(removeScript(), timeoutSec = 6)
        }
        if (!browserRemoval.ok || browserRemoval.present || !userRemoval.ok || !moduleRemoval.ok) {
            val failed = SystemCaStatus(
                SystemCaState.ERROR,
                ca?.fingerprintSha256.orEmpty(),
                listOfNotNull(
                    browserRemoval.detail.takeIf { !browserRemoval.ok || browserRemoval.present },
                    userRemoval.detail.takeIf { !userRemoval.ok },
                    moduleRemoval.diagnosticSummary().takeIf { !moduleRemoval.ok },
                ).joinToString("；"),
            )
            return SystemCaOperation(false, failed, false, "CA 卸载失败：${failed.detail}")
        }
        val after = status(ca)
        val rebootRequired = before.systemActive || before.state in setOf(
            SystemCaState.STAGED_REBOOT_REQUIRED,
            SystemCaState.REMOVE_PENDING,
        ) || systemStatus(ca).state == SystemCaState.REMOVE_PENDING
        return SystemCaOperation(
            success = true,
            status = after,
            rebootRequired = rebootRequired,
            detail = if (rebootRequired) {
                "已精确删除本设备用户 CA，并标记移除 $MODULE_ID；重启后清除系统/APEX 副本"
            } else {
                "已精确删除本设备用户 CA 与 Edge 中的同一策略证书；未触及其他证书"
            },
        )
    }

    private fun runKeyChain(operation: String, ca: DeviceCertificateAuthority): KeyChainResult {
        require(operation == "status" || operation == "install" || operation == "remove")
        val launcher = try {
            RootAppProcessDex.from(app)
        } catch (t: Throwable) {
            return KeyChainResult(false, false, detail = failureText(t))
        }
        val script = "set -eu\n" + launcher.foregroundInvocation(
            KEYCHAIN_HELPER_CLASS,
            listOf(operation, ca.file.absolutePath),
        )
        val result = shell.execTrustedScript(script, timeoutSec = 20)
        val parsed = parseKeyChainResult(result.out)
            ?: return KeyChainResult(
                false,
                false,
                detail = "助手输出无效（${result.diagnosticSummary(220)}）",
            )
        return if (result.ok == parsed.ok) {
            parsed
        } else {
            parsed.copy(
                ok = false,
                detail = "助手退出状态不一致：${result.diagnosticSummary(220)}",
            )
        }
    }

    private fun runBrowserPolicy(
        operation: String,
        ca: DeviceCertificateAuthority,
    ): BrowserPolicyResult {
        require(operation == "status" || operation == "install" || operation == "remove")
        val launcher = try {
            RootAppProcessDex.from(app)
        } catch (t: Throwable) {
            return BrowserPolicyResult(false, false, EDGE_PACKAGE, failureText(t))
        }
        val script = "set -eu\n" + launcher.foregroundInvocation(
            BROWSER_POLICY_HELPER_CLASS,
            listOf(operation, EDGE_PACKAGE, ca.file.absolutePath),
        )
        val result = shell.execTrustedScript(script, timeoutSec = 20)
        val parsed = parseBrowserPolicyResult(result.out)
            ?: return BrowserPolicyResult(
                false,
                false,
                EDGE_PACKAGE,
                "助手输出无效（${result.diagnosticSummary(220)}）",
            )
        return if (result.ok == parsed.ok) {
            parsed
        } else {
            parsed.copy(
                ok = false,
                detail = "助手退出状态不一致：${result.diagnosticSummary(220)}",
            )
        }
    }

    private fun edgeInstalled(): Boolean = edgeVersionName() != null

    private fun edgePolicySupported(): Boolean = (
        edgeVersionName()?.substringBefore('.')?.toIntOrNull()?.let { it >= MIN_EDGE_POLICY_MAJOR }
        ) == true

    private fun edgeVersionName(): String? = try {
        val info = if (Build.VERSION.SDK_INT >= 33) {
            app.packageManager.getPackageInfo(
                EDGE_PACKAGE,
                PackageManager.PackageInfoFlags.of(0L),
            )
        } else {
            @Suppress("DEPRECATION")
            app.packageManager.getPackageInfo(EDGE_PACKAGE, 0)
        }
        info.versionName?.trim()?.takeIf(String::isNotEmpty)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    } catch (_: RuntimeException) {
        null
    }

    private fun edgePolicyRequired(): Boolean = edgePolicyRequired(
        installed = edgeInstalled(),
        scopeMode = settings.appScopeMode(),
        scopedPackages = settings.scopedPackages(),
        embeddedCapturePackages = settings.embeddedTlsCapturePackages(),
    )

    private fun notifyTrustStoreChanged() {
        runCatching {
            shell.execTrustedScript(
                "am broadcast --user 0 -a android.security.action.TRUST_STORE_CHANGED >/dev/null",
                timeoutSec = 6,
            )
        }
    }

    internal data class KeyChainResult(
        val ok: Boolean,
        val present: Boolean,
        val alias: String = "",
        val detail: String = "",
    )

    internal data class BrowserPolicyResult(
        val ok: Boolean,
        val present: Boolean,
        val packageName: String,
        val detail: String = "",
    )

    private fun buildStagingModule(ca: DeviceCertificateAuthority): File {
        require(ANDROID_CERT_NAME.matches(ca.androidFileName))
        val cacheRoot = app.cacheDir.canonicalFile
        val staging = File(cacheRoot, STAGING_DIR_NAME).canonicalFile
        require(staging.parentFile == cacheRoot) { "invalid staging path" }
        if (staging.exists()) check(staging.deleteRecursively()) { "cannot clear CA staging" }
        val certDir = File(staging, "system/etc/security/cacerts")
        check(certDir.mkdirs()) { "cannot create certificate staging directory" }
        ca.file.inputStream().use { input ->
            File(certDir, ca.androidFileName).outputStream().use(input::copyTo)
        }
        File(staging, OWNERSHIP_MARKER).writeText(
            "id=$MODULE_ID\nfingerprint=${ca.fingerprintSha256}\n",
            Charsets.UTF_8,
        )
        File(staging, "module.prop").writeText(
            renderModuleProp(ca.fingerprintSha256),
            Charsets.UTF_8,
        )
        File(staging, "inject-apex.sh").writeText(
            renderInjectScript(ca.androidFileName),
            Charsets.UTF_8,
        )
        File(staging, "post-fs-data.sh").writeText(renderPostFsDataScript(), Charsets.UTF_8)
        File(staging, "service.sh").writeText(renderServiceScript(), Charsets.UTF_8)
        File(staging, "uninstall.sh").writeText(renderUninstallScript(), Charsets.UTF_8)
        return staging
    }

    private fun statusScript(ca: DeviceCertificateAuthority): String {
        val moduleCert = "$MODULE_DIR/system/etc/security/cacerts/${ca.androidFileName}"
        val apexCert = "/apex/com.android.conscrypt/cacerts/${ca.androidFileName}"
        val legacyCert = "/system/etc/security/cacerts/${ca.androidFileName}"
        fun trustedViewProbe(target: String): String =
            "[ -f ${quote(target)} ] && cmp -s ${quote(moduleCert)} ${quote(target)}"

        return buildString {
            appendLine("module=0; owned=0; staged=0; remove=0; apex=0; legacy=0")
            appendLine("[ -e ${quote(MODULE_DIR)} ] && module=1")
            appendLine("[ -f ${quote("$MODULE_DIR/$OWNERSHIP_MARKER")} ] && owned=1")
            appendLine("[ -f ${quote("$MODULE_DIR/remove")} ] && remove=1")
            appendLine("[ -f ${quote(moduleCert)} ] && cmp -s ${quote(ca.file.absolutePath)} ${quote(moduleCert)} && staged=1")
            appendLine("if [ \"\$staged\" = 1 ]; then")
            // Trust must be visible in the calling app's inherited Zygote namespace. Seeing the
            // bind only from PID 1 is insufficient because MediaHTTPConnection runs in-app.
            appendLine("  if ${trustedViewProbe(apexCert)}; then")
            appendLine("    apex=1")
            appendLine("  fi")
            appendLine("  if ${trustedViewProbe(legacyCert)}; then")
            appendLine("    legacy=1")
            appendLine("  fi")
            appendLine("fi")
            appendLine("echo module=\$module")
            appendLine("echo owned=\$owned")
            appendLine("echo staged=\$staged")
            appendLine("echo remove=\$remove")
            appendLine("echo apex=\$apex")
            appendLine("echo legacy=\$legacy")
        }
    }

    private fun installScript(staging: File): String = buildString {
        appendLine("set -eu")
        appendLine("[ -d /data/adb/modules ]")
        appendLine("if [ -e ${quote(MODULE_DIR)} ] && [ ! -f ${quote("$MODULE_DIR/$OWNERSHIP_MARKER")} ]; then exit 73; fi")
        appendLine("rm -rf ${quote(MODULE_STAGE_DIR)}")
        appendLine("mkdir -p ${quote(MODULE_STAGE_DIR)}")
        appendLine("cp -af ${quote(staging.absolutePath)}/. ${quote(MODULE_STAGE_DIR)}/")
        appendLine("chown -R 0:0 ${quote(MODULE_STAGE_DIR)}")
        appendLine("find ${quote(MODULE_STAGE_DIR)} -type d -exec chmod 0755 {} \\;")
        appendLine("find ${quote(MODULE_STAGE_DIR)} -type f -exec chmod 0644 {} \\;")
        appendLine("chmod 0755 ${quote(MODULE_STAGE_DIR)}/post-fs-data.sh ${quote(MODULE_STAGE_DIR)}/service.sh ${quote(MODULE_STAGE_DIR)}/inject-apex.sh ${quote(MODULE_STAGE_DIR)}/uninstall.sh")
        appendLine("chmod 0600 ${quote("$MODULE_STAGE_DIR/$OWNERSHIP_MARKER")}")
        appendLine("rm -f ${quote(MODULE_STAGE_DIR)}/remove ${quote(MODULE_STAGE_DIR)}/disable")
        // v1.0 kept its tmpfs source below MODULE_DIR, making a hot update fail with EBUSY.
        // Detach only that exact legacy source in the caller's namespace before replacing the
        // already ownership-verified module. Existing APEX bind mounts retain their references.
        appendLine("if grep -q ${quote(" $LEGACY_APEX_WORK_DIR ")} /proc/self/mountinfo 2>/dev/null; then")
        appendLine("  umount ${quote(LEGACY_APEX_WORK_DIR)}")
        appendLine("fi")
        appendLine("if [ -e ${quote(MODULE_DIR)} ]; then rm -rf ${quote(MODULE_DIR)}; fi")
        appendLine("mv ${quote(MODULE_STAGE_DIR)} ${quote(MODULE_DIR)}")
    }

    private fun immediateInjectScript(): String =
        "set -eu\n" + renderNamespaceInjectCommands()

    private fun removeScript(): String = buildString {
        appendLine("set -eu")
        appendLine("if [ ! -e ${quote(MODULE_DIR)} ]; then exit 0; fi")
        appendLine("[ -f ${quote("$MODULE_DIR/$OWNERSHIP_MARKER")} ] || exit 73")
        appendLine("touch ${quote("$MODULE_DIR/disable")} ${quote("$MODULE_DIR/remove")}")
    }

    private fun quote(raw: String): String {
        require(raw.isNotBlank() && raw.none { it == '\u0000' || it == '\r' || it == '\n' })
        return "'" + raw.replace("'", "'\\''") + "'"
    }

    private fun failureText(t: Throwable): String =
        "${t.javaClass.simpleName}: ${t.message.orEmpty()}".trim().take(300)

    companion object {
        private const val KEYCHAIN_HELPER_CLASS =
            "org.xiyu.githubdirect.root.AndroidKeyChainRootHelper"
        private const val KEYCHAIN_MARKER = "GHD_KEYCHAIN_V1"
        private const val BROWSER_POLICY_HELPER_CLASS =
            "org.xiyu.githubdirect.root.BrowserPolicyRootHelper"
        private const val BROWSER_POLICY_MARKER = "GHD_BROWSER_POLICY_V1"
        private const val EDGE_PACKAGE = "com.microsoft.emmx"
        private const val MIN_EDGE_POLICY_MAJOR = 147
        const val MODULE_ID = "github_direct_ca"
        const val MODULE_DIR = "/data/adb/modules/$MODULE_ID"
        const val MODULE_STAGE_DIR = "/data/adb/modules/$MODULE_ID.staging"
        const val OWNERSHIP_MARKER = ".github-direct-owned"
        private const val APEX_WORK_DIR = "/data/adb/github-direct-ca-apex"
        private const val LEGACY_APEX_WORK_DIR = "$MODULE_DIR/.apex-cacerts"
        private const val STAGING_DIR_NAME = "github-direct-ca-module"
        private val ANDROID_CERT_NAME = Regex("^[0-9a-f]{8}\\.0$")
        private val USER_CA_ALIAS = Regex("^user:[0-9a-f]{8}\\.[0-9]+$")

        internal fun parseKeyChainResult(output: String): KeyChainResult? {
            val lines = output.trim().lineSequence().map(String::trim).toList()
            if (lines.size != 5 || lines.firstOrNull() != KEYCHAIN_MARKER) return null
            val pairs = lines.drop(1).map { line ->
                val split = line.split('=', limit = 2)
                if (split.size != 2) return null
                split[0] to split[1]
            }
            if (pairs.map { it.first }.toSet() != setOf("ok", "present", "alias", "detail")) {
                return null
            }
            val values = pairs.toMap()
            val ok = when (values["ok"]) {
                "1" -> true
                "0" -> false
                else -> return null
            }
            val present = when (values["present"]) {
                "1" -> true
                "0" -> false
                else -> return null
            }
            val alias = values["alias"].orEmpty()
            val detail = values["detail"].orEmpty()
            if ((present && !USER_CA_ALIAS.matches(alias)) || (!present && alias.isNotEmpty())) {
                return null
            }
            if (detail.length > 240 || detail.any { it == '\u0000' || it == '\r' || it == '\n' }) {
                return null
            }
            return KeyChainResult(ok, present, alias, detail)
        }

        internal fun parseBrowserPolicyResult(output: String): BrowserPolicyResult? {
            val lines = output.trim().lineSequence().map(String::trim).toList()
            if (lines.size != 5 || lines.firstOrNull() != BROWSER_POLICY_MARKER) return null
            val pairs = lines.drop(1).map { line ->
                val split = line.split('=', limit = 2)
                if (split.size != 2) return null
                split[0] to split[1]
            }
            if (pairs.map { it.first }.toSet() != setOf("ok", "present", "package", "detail")) {
                return null
            }
            val values = pairs.toMap()
            val ok = when (values["ok"]) {
                "1" -> true
                "0" -> false
                else -> return null
            }
            val present = when (values["present"]) {
                "1" -> true
                "0" -> false
                else -> return null
            }
            val packageName = values["package"].orEmpty()
            if (packageName != EDGE_PACKAGE) return null
            val detail = values["detail"].orEmpty()
            if (detail.length > 240 || detail.any { it == '\u0000' || it == '\r' || it == '\n' }) {
                return null
            }
            return BrowserPolicyResult(ok, present, packageName, detail)
        }

        internal fun edgePolicyRequired(
            installed: Boolean,
            scopeMode: AppScopeMode,
            scopedPackages: Set<String>,
            embeddedCapturePackages: Set<String>,
        ): Boolean {
            if (!installed) return false
            if (EDGE_PACKAGE in embeddedCapturePackages) return true
            return when (scopeMode) {
                AppScopeMode.ALL_APPS -> true
                AppScopeMode.SELECTED_APPS -> EDGE_PACKAGE in scopedPackages
                AppScopeMode.EXCLUDED_APPS -> EDGE_PACKAGE !in scopedPackages
            }
        }

        internal fun renderModuleProp(fingerprint: String): String = """
            id=$MODULE_ID
            name=GitHub-direct Per-Device CA
            version=1.1
            versionCode=2
            author=GitHub-direct
            description=Per-device public CA only; fingerprint ${fingerprint.take(16)}
        """.trimIndent() + "\n"

        internal fun renderInjectScript(certName: String): String {
            require(ANDROID_CERT_NAME.matches(certName))
            return """
                #!/system/bin/sh
                set -eu
                MODDIR=${'$'}{0%/*}
                CERT="${'$'}MODDIR/system/etc/security/cacerts/$certName"
                APEX=/apex/com.android.conscrypt/cacerts
                WORK="$APEX_WORK_DIR"
                [ -f "${'$'}CERT" ] || exit 1
                [ -d "${'$'}APEX" ] || exit 0
                if [ -f "${'$'}APEX/$certName" ] && cmp -s "${'$'}CERT" "${'$'}APEX/$certName"; then
                  exit 0
                fi
                if grep -q " ${'$'}WORK " /proc/self/mountinfo 2>/dev/null; then
                  cp -f "${'$'}CERT" "${'$'}WORK/$certName"
                else
                  rm -rf "${'$'}WORK"
                  mkdir -p "${'$'}WORK"
                  mount -t tmpfs -o mode=0755 tmpfs "${'$'}WORK"
                  cp -af "${'$'}APEX/." "${'$'}WORK/"
                  cp -f "${'$'}CERT" "${'$'}WORK/$certName"
                fi
                chown 0:0 "${'$'}WORK" "${'$'}WORK"/*
                chmod 0755 "${'$'}WORK"
                chmod 0644 "${'$'}WORK"/*
                chcon u:object_r:system_security_cacerts_file:s0 "${'$'}WORK" "${'$'}WORK"/* 2>/dev/null || true
                if ! cmp -s "${'$'}CERT" "${'$'}APEX/$certName" 2>/dev/null; then
                  mount --bind "${'$'}WORK" "${'$'}APEX"
                fi
            """.trimIndent() + "\n"
        }

        /** Inject the public CA view into PID 1 and both 32/64-bit Zygote namespaces. */
        internal fun renderNamespaceInjectCommands(): String = """
            injected=0
            inject_namespace() {
              target_pid="${'$'}1"
              [ -r "/proc/${'$'}target_pid/ns/mnt" ] || return 0
              if /system/bin/nsenter -t "${'$'}target_pid" -m -- /system/bin/sh "$MODULE_DIR/inject-apex.sh"; then
                injected=1
              fi
              return 0
            }
            if [ -x /system/bin/nsenter ]; then
              inject_namespace 1
              for target_pid in ${'$'}(/system/bin/pidof zygote64 zygote 2>/dev/null || true); do
                [ "${'$'}target_pid" = 1 ] || inject_namespace "${'$'}target_pid"
              done
            elif /system/bin/sh "$MODULE_DIR/inject-apex.sh"; then
              injected=1
            fi
            [ "${'$'}injected" = 1 ]
        """.trimIndent() + "\n"

        internal fun renderPostFsDataScript(): String =
            "#!/system/bin/sh\nset -u\n" + renderNamespaceInjectCommands()

        internal fun renderServiceScript(): String = buildString {
            appendLine("#!/system/bin/sh")
            appendLine("set -u")
            appendLine("i=0")
            appendLine("while [ ! -d /apex/com.android.conscrypt/cacerts ] && [ \"\$i\" -lt 60 ]; do")
            appendLine("  sleep 1")
            appendLine("  i=\$((i + 1))")
            appendLine("done")
            append(renderNamespaceInjectCommands())
        }

        internal fun renderUninstallScript(): String = """
            #!/system/bin/sh
            # 当前 APEX bind mount 在本次启动周期保持不动；重启自然恢复原始只读 APEX。
            rm -rf "$APEX_WORK_DIR" 2>/dev/null || true
            exit 0
        """.trimIndent() + "\n"
    }
}

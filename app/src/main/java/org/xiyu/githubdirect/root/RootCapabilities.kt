package org.xiyu.githubdirect.root

/**
 * Root 能力矩阵（只读探测，设计 §18）。
 * 仅报告与后端启动真正相关的项为必检（RootBackend 用 requiredOk() 门控），
 * ipv6Netfilter / nft / tproxy 本阶段不使用，仅报告。
 */
data class RootCapabilities(
    /** su 可用且能提权成功（`su -c true` 返回 0） */
    val suAvailable: Boolean,
    /** `id -u` 解析出的 root 会话 UID；失败为 -1 */
    val uid: Int,
    /** iptables 命令存在且可执行 */
    val iptables: Boolean,
    /** iptables-save 存在（verify 依赖） */
    val iptablesSave: Boolean,
    /** iptables-restore 存在（原子安装依赖） */
    val iptablesRestore: Boolean,
    /** `-t nat -L OUTPUT` 可读（netfilter nat 表可用） */
    val natOutput: Boolean,
    /** owner 匹配支持 --uid-owner（`-m owner --help` 含 uid-owner） */
    val ownerUidMatch: Boolean,
    /** REDIRECT target 可用（`-j REDIRECT --help` 不报错） */
    val redirectTarget: Boolean,
    /** ip6tables 存在（本阶段不使用，仅报告） */
    val ipv6Netfilter: Boolean,
    /** nft 存在（本阶段不使用，仅报告） */
    val nft: Boolean,
    /** TPROXY target 可用（本阶段不使用，仅报告） */
    val tproxy: Boolean,
    /** getenforce 输出 Enforcing */
    val selinuxEnforcing: Boolean,
) {
    /**
     * 后端 start 门控：所有必需能力齐全才算可启动。
     * 注意：selinuxEnforcing 故意不门控——Android 上强制 SELinux 与 root 能力可共存（su 已被允许）。
     */
    fun requiredOk(): Boolean =
        suAvailable && uid > 0 && iptables && iptablesSave && iptablesRestore &&
            natOutput && ownerUidMatch && redirectTarget
}

/** 探测器抽象（测试注入点）。 */
interface CapabilityProber {
    fun probe(): RootCapabilities
}

/**
 * 只读探测实现：每条命令独立执行（su 单次开销可接受——仅在用户切换开关时调用一次），
 * 带短超时与容错；任何异常/失败 → 对应项 false，绝不抛出。
 */
class RootCapabilityProbe(private val shell: RootShell) : CapabilityProber {

    override fun probe(): RootCapabilities {
        val suAvailable = runShell("true").ok
        val uid = runShell("id -u").out.trim().toIntOrNull() ?: -1
        val iptables = runShell("iptables --version").ok
        val iptablesSave = runShell("command -v iptables-save").okOrBlank()
        val iptablesRestore = runShell("command -v iptables-restore").okOrBlank()
        val natOutput = runShell("iptables -t nat -L OUTPUT -n").ok
        val ownerOut = runShell("iptables -m owner --help")
        val ownerUidMatch = ownerOut.ok && ownerOut.out.contains("uid-owner")
        // 不同 iptables 版本对 `-j TARGET --help` 的表上下文要求不同，任一形式成功即视为可用
        val redirectTarget = runShell("iptables -j REDIRECT --help").ok ||
            runShell("iptables -t nat -j REDIRECT --help").ok
        val ipv6Netfilter = runShell("command -v ip6tables").okOrBlank()
        val nft = runShell("command -v nft").okOrBlank()
        val tproxy = runShell("iptables -j TPROXY --help").ok ||
            runShell("iptables -t mangle -j TPROXY --help").ok
        val selinux = runShell("getenforce")
        val selinuxEnforcing = selinux.ok && selinux.out.contains("Enforcing")

        return RootCapabilities(
            suAvailable = suAvailable,
            uid = uid,
            iptables = iptables,
            iptablesSave = iptablesSave,
            iptablesRestore = iptablesRestore,
            natOutput = natOutput,
            ownerUidMatch = ownerUidMatch,
            redirectTarget = redirectTarget,
            ipv6Netfilter = ipv6Netfilter,
            nft = nft,
            tproxy = tproxy,
            selinuxEnforcing = selinuxEnforcing,
        )
    }

    /** 容错执行：任何异常（含 sanitize 拒绝）→ Result(-1,"","",false)，不传播。 */
    private fun runShell(cmd: String, timeoutSec: Int = 3): RootShell.Result =
        try {
            shell.exec(cmd, timeoutSec = timeoutSec)
        } catch (t: Throwable) {
            RootShell.Result(-1, "", "probe failed: $t", false)
        }

    private fun RootShell.Result.okOrBlank(): Boolean = ok && out.isNotBlank()
}

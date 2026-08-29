package org.xiyu.githubdirect.root

/**
 * Root 能力矩阵（只读探测，设计 §18）。
 *
 * [uid] 是 **应用自身 UID**（给 iptables `--uid-owner` 排除自己），不是 `su` 后的 0。
 * 历史 bug：`su -c id -u` 返回 0，再配 `requiredOk` 的 `uid > 0`，Root 永远过不了门。
 */
data class RootCapabilities(
    /** su 可用且已提权（`id -u` 解析为 0） */
    val suAvailable: Boolean,
    /** 应用 UID；iptables 排除自身流量。非法为 -1 */
    val uid: Int,
    val iptables: Boolean,
    val iptablesSave: Boolean,
    val iptablesRestore: Boolean,
    val natOutput: Boolean,
    val ownerUidMatch: Boolean,
    val redirectTarget: Boolean,
    val ipv6Netfilter: Boolean,
    val nft: Boolean,
    val tproxy: Boolean,
    val selinuxEnforcing: Boolean,
    /** ipset hash:net + timeout 能力；可用时用于原子目的地址集合和 fail-open 租约。 */
    val ipset: Boolean = false,
    /** filter/OUTPUT 的 REJECT target；不可用时 UDP/443 才退化为 DROP。 */
    val rejectTarget: Boolean = false,
    /** ip6tables 的 REJECT target；与 IPv4 分开探测，避免 IPv6 restore 因 target 缺失失败。 */
    val ipv6RejectTarget: Boolean = false,
    /**
     * `ip -6 rule uidrange` + 独立路由表能力。用于设备缺少 ip6tables 数据面时，
     * 仅让所选 UID 对已授权 OpenAI AAAA 快速回退到 IPv4/NAT64。
     */
    val ipv6UidPolicyRouting: Boolean = false,
) {
    fun requiredOk(): Boolean =
        suAvailable && uid > 0 && iptables && iptablesSave && iptablesRestore &&
            natOutput && ownerUidMatch && redirectTarget

    fun missingRequired(): List<String> {
        val missing = ArrayList<String>(8)
        if (!suAvailable) missing += "su"
        if (uid <= 0) missing += "app-uid"
        if (!iptables) missing += "iptables"
        if (!iptablesSave) missing += "iptables-save"
        if (!iptablesRestore) missing += "iptables-restore"
        if (!natOutput) missing += "nat"
        if (!ownerUidMatch) missing += "owner"
        if (!redirectTarget) missing += "REDIRECT"
        return missing
    }
}

interface CapabilityProber {
    fun probe(): RootCapabilities
}

/**
 * 基本为只读探测；owner help 不完整时，仅在不挂接 OUTPUT 的临时自有链中验证匹配器。
 * 失败项记 false，不抛异常。
 *
 * @param appUid [android.os.Process.myUid]，用于 iptables owner 排除；测试可注入。
 */
class RootCapabilityProbe(
    private val shell: RootShell,
    private val appUid: Int,
) : CapabilityProber {

    override fun probe(): RootCapabilities {
        val id = runShell("id -u")
        val suUid = parseUid(id.text())
        val suAvailable = id.ok && suUid == 0

        var iptables = versionOk("iptables")
        if (!iptables) {
            iptables = runShell("iptables -S").ok || runShell("/system/bin/iptables -S").ok
        }

        var iptablesSave = hasCmd("iptables-save", "iptables-legacy-save", "iptables-nft-save")
        var iptablesRestore = hasCmd("iptables-restore", "iptables-legacy-restore", "iptables-nft-restore")
        if (!iptablesSave && iptables) {
            iptablesSave = runShell("iptables-save -t nat").ok || runShell("iptables -S").ok
        }
        if (!iptablesRestore) {
            // RootShell 会关闭 stdin；--version 是 AOSP/netfilter restore 的只读能力探测，
            // 不能仅凭 save 或 `iptables -S` 可用就推断 restore 一定存在。
            iptablesRestore = restoreVersionOk(
                "iptables-restore",
                "iptables-legacy-restore",
                "iptables-nft-restore",
            )
        }

        val natOutput = runShell("iptables -t nat -L OUTPUT -n").ok

        val ownerHelp = runShell("iptables -m owner --help")
        var ownerUidMatch = helpAdvertises(ownerHelp, "uid-owner")
        if (!ownerUidMatch && suAvailable) {
            ownerUidMatch = probeOwnerMatch("iptables", OWNER_PROBE_CHAIN)
        }

        val redirectHelp = runShell("iptables -t nat -j REDIRECT --help")
        val redirectHelp2 = runShell("iptables -j REDIRECT --help")
        var redirectTarget = helpAdvertises(redirectHelp, "REDIRECT") ||
            helpAdvertises(redirectHelp2, "REDIRECT")
        if (!redirectTarget && suAvailable && natOutput) {
            redirectTarget = probeTarget(
                "iptables",
                "nat",
                REDIRECT_PROBE_CHAIN,
                "-p tcp --dport 443 -j REDIRECT --to-ports 7443",
            )
        }

        var ip6tables = versionOk("ip6tables")
        if (!ip6tables) {
            ip6tables = runShell("ip6tables -S").ok || runShell("/system/bin/ip6tables -S").ok
        }
        var ip6tablesSave = hasCmd("ip6tables-save", "ip6tables-legacy-save", "ip6tables-nft-save")
        var ip6tablesRestore = hasCmd(
            "ip6tables-restore",
            "ip6tables-legacy-restore",
            "ip6tables-nft-restore",
        )
        if (!ip6tablesRestore) {
            ip6tablesRestore = restoreVersionOk(
                "ip6tables-restore",
                "ip6tables-legacy-restore",
                "ip6tables-nft-restore",
            )
        }
        if (!ip6tablesSave && ip6tables) {
            ip6tablesSave = runShell("ip6tables-save -t nat").ok || runShell("ip6tables -S").ok
        }
        val ip6NatOutput = runShell("ip6tables -t nat -L OUTPUT -n").ok
        val ip6OwnerHelp = runShell("ip6tables -m owner --help")
        var ip6OwnerUidMatch = helpAdvertises(ip6OwnerHelp, "uid-owner")
        if (!ip6OwnerUidMatch && suAvailable && ip6NatOutput) {
            ip6OwnerUidMatch = probeOwnerMatch("ip6tables", OWNER_PROBE_CHAIN_V6)
        }
        val ip6RedirectHelp = runShell("ip6tables -t nat -j REDIRECT --help")
        val ip6RedirectHelp2 = runShell("ip6tables -j REDIRECT --help")
        var ip6Redirect = helpAdvertises(ip6RedirectHelp, "REDIRECT") ||
            helpAdvertises(ip6RedirectHelp2, "REDIRECT")
        if (!ip6Redirect && suAvailable && ip6NatOutput) {
            ip6Redirect = probeTarget(
                "ip6tables",
                "nat",
                REDIRECT_PROBE_CHAIN_V6,
                "-p tcp --dport 443 -j REDIRECT --to-ports 7443",
            )
        }
        val ipv6Netfilter = ip6tables && ip6tablesSave && ip6tablesRestore && ip6NatOutput &&
            ip6OwnerUidMatch && ip6Redirect
        val nft = hasCmd("nft")
        val tproxyHelp = runShell("iptables -t mangle -j TPROXY --help")
        val tproxy = helpAdvertises(tproxyHelp, "TPROXY")
        val ipsetVersion = runShell("ipset --version")
        val ipset = hasCmd("ipset") || ipsetVersion.ok
        val rejectHelp = runShell("iptables -t filter -j REJECT --help")
        val rejectTarget = helpAdvertises(rejectHelp, "REJECT") ||
            (suAvailable && probeTarget(
                "iptables",
                "filter",
                REJECT_PROBE_CHAIN,
                "-p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable",
            ))
        val rejectHelpV6 = runShell("ip6tables -t filter -j REJECT --help")
        val ipv6RejectTarget = ipv6Netfilter &&
            (helpAdvertises(rejectHelpV6, "REJECT") || probeTarget(
                "ip6tables",
                "filter",
                REJECT_PROBE_CHAIN_V6,
                "-p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable",
            ))
        val ipv6UidPolicyRouting = suAvailable && appUid > 0 && probeIpv6UidPolicyRouting()
        val selinux = runShell("getenforce")
        val selinuxEnforcing = containsIgnoreCase(selinux.text(), "Enforcing")

        return RootCapabilities(
            suAvailable = suAvailable,
            uid = if (appUid > 0) appUid else -1,
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
            ipset = ipset,
            rejectTarget = rejectTarget,
            ipv6RejectTarget = ipv6RejectTarget,
            ipv6UidPolicyRouting = ipv6UidPolicyRouting,
        )
    }

    /**
     * 在文档保留地址上做一次不可达策略探测；规则只匹配应用 UID 与单个 /128，且无真实
     * 业务流量会使用该目标。finally 精确删除本次规则和路由，不触碰 Android 路由表。
     */
    private fun probeIpv6UidPolicyRouting(): Boolean {
        val route =
            "ip -6 route add unreachable $POLICY_PROBE_DESTINATION table $POLICY_PROBE_TABLE"
        val rule =
            "ip -6 rule add priority $POLICY_PROBE_PRIORITY uidrange $appUid-$appUid " +
                "to $POLICY_PROBE_DESTINATION lookup $POLICY_PROBE_TABLE"
        cleanupIpv6UidPolicyProbe()
        val installed = try {
            shell.execStrict(route, rule, timeoutSec = 8).ok
        } catch (_: Throwable) {
            false
        } finally {
            cleanupIpv6UidPolicyProbe()
        }
        return installed
    }

    private fun cleanupIpv6UidPolicyProbe() {
        runCatching {
            shell.exec(
                "ip -6 rule del priority $POLICY_PROBE_PRIORITY uidrange $appUid-$appUid " +
                    "to $POLICY_PROBE_DESTINATION lookup $POLICY_PROBE_TABLE",
                "ip -6 route del unreachable $POLICY_PROBE_DESTINATION table $POLICY_PROBE_TABLE",
                timeoutSec = 5,
            )
        }
    }

    private fun probeOwnerMatch(binary: String, chain: String): Boolean {
        // 先清上次进程中断留下的孤立探测链；它从不挂到任何内建链，不影响设备流量。
        runCatching {
            shell.exec(
                "$binary -t nat -F $chain",
                "$binary -t nat -X $chain",
                timeoutSec = 5,
            )
        }
        val add = try {
            shell.execStrict(
                "$binary -t nat -N $chain",
                "$binary -t nat -A $chain -m owner --uid-owner 1 -j RETURN",
                timeoutSec = 8,
            )
        } catch (t: Throwable) {
            RootShell.Result(-1, "", "probe failed: $t", false)
        } finally {
            runCatching {
                shell.exec(
                    "$binary -t nat -F $chain",
                    "$binary -t nat -X $chain",
                    timeoutSec = 5,
                )
            }
        }
        if (add.ok) return true
        return helpAdvertises(add, "uid-owner") || helpAdvertises(add, "owner")
    }

    private fun versionOk(bin: String): Boolean {
        val r = runShell("$bin --version")
        if (r.ok) return true
        val r2 = runShell("/system/bin/$bin --version")
        return r2.ok
    }

    /** 在未挂接任何内建链的临时链中验证 target；无数据包可达，不改变设备流量。 */
    private fun probeTarget(
        binary: String,
        table: String,
        chain: String,
        rule: String,
    ): Boolean {
        runCatching {
            shell.exec(
                "$binary -t $table -F $chain",
                "$binary -t $table -X $chain",
                timeoutSec = 5,
            )
        }
        val add = try {
            shell.execStrict(
                "$binary -t $table -N $chain",
                "$binary -t $table -A $chain $rule",
                timeoutSec = 8,
            )
        } catch (_: Throwable) {
            RootShell.Result(-1, "", "probe failed", false)
        } finally {
            runCatching {
                shell.exec(
                    "$binary -t $table -F $chain",
                    "$binary -t $table -X $chain",
                    timeoutSec = 5,
                )
            }
        }
        return add.ok
    }

    private fun helpAdvertises(result: RootShell.Result, token: String): Boolean {
        val text = result.text().lowercase()
        if (token.lowercase() !in text) return false
        return MISSING_MARKERS.none { it in text }
    }

    private fun hasCmd(vararg names: String): Boolean {
        for (n in names) {
            for (dir in BIN_DIRS) {
                val probe = runShell("test -x $dir/$n")
                if (probe.ok) return true
            }
        }
        return false
    }

    private fun restoreVersionOk(vararg names: String): Boolean =
        names.any { name -> runShell("$name --version").ok }

    private fun runShell(cmd: String, timeoutSec: Int = 8): RootShell.Result =
        try {
            shell.exec(cmd, timeoutSec = timeoutSec)
        } catch (t: Throwable) {
            RootShell.Result(-1, "", "probe failed: $t", false)
        }

    companion object {
        private val BIN_DIRS = listOf(
            "/system/bin",
            "/system/xbin",
            "/vendor/bin",
            "/debug_ramdisk",
            "/debug_ramdisk/bin",
            "/data/adb/ksu/bin",
        )
        private const val OWNER_PROBE_CHAIN = "GHD_PROBE_OWNER"
        private const val OWNER_PROBE_CHAIN_V6 = "GHD_PROBE_OWNER6"
        private const val REDIRECT_PROBE_CHAIN = "GHD_PROBE_REDIR"
        private const val REDIRECT_PROBE_CHAIN_V6 = "GHD_PROBE_REDIR6"
        private const val REJECT_PROBE_CHAIN = "GHD_PROBE_REJECT"
        private const val REJECT_PROBE_CHAIN_V6 = "GHD_PROBE_REJECT6"
        private const val POLICY_PROBE_DESTINATION = "2001:db8::1/128"
        private const val POLICY_PROBE_TABLE = 52999
        private const val POLICY_PROBE_PRIORITY = 10998
        private val MISSING_MARKERS = listOf(
            "not found",
            "no such",
            "unknown",
            "inaccessible",
            "couldn't load",
            "cannot load",
            "can't initialize",
        )

        /**
         * 从 su 输出里取最后一个纯整数行（兼容 KernelSU 在 stdout 夹日志）。
         * 没有独立数字行时再尝试 `uid=0(root)`。
         */
        fun parseUid(text: String): Int {
            val standalone = text.lineSequence()
                .map { it.trim() }
                .mapNotNull { it.toIntOrNull() }
                .lastOrNull()
            if (standalone != null) return standalone
            val uidEq = UID_EQ.find(text) ?: return -1
            return uidEq.groupValues[1].toIntOrNull() ?: -1
        }

        /** @deprecated 用 [parseUid] */
        fun parseLeadingInt(text: String): Int = parseUid(text)

        fun containsIgnoreCase(text: String, needle: String): Boolean =
            text.contains(needle, ignoreCase = true)

        private val UID_EQ = Regex("""(?im)(?:^|\s)uid=(\d+)""")
    }
}

package org.xiyu.githubdirect.root

import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.routing.RouteSnapshotCodec

/**
 * FirewallRules —— iptables-restore 安装脚本 / 清理命令 / 校验特征行的**纯字符串生成**（不执行）。
 *
 * 规则语义（设计 §20/§23 与端口编码 REDIRECT 决策）：
 * - nat 表自有 chain：`GHD_DNS`（DNS UDP 5354 + TCP 5355 重定向）、`GHD_TCP`（245 条 vIP TCP 重定向）；
 *   filter 表自有 chain：`GHD_UDP_DROP`（vIP UDP 黑洞，QUIC 客户端 TCP 回退）。
 * - 只管理自有 chain：卸载 = 删 OUTPUT jump → flush 自己 chain → 删自己 chain（先删引用再删除）。
 * - 自身 UID 排除：父链规则带 `-m owner ! --uid-owner <selfUid>`；SELECTED 载荷链继承入口匹配，
 *   DoH/relay/探活自身流量不进规则。
 * - 安装用 iptables-restore `--noflush`（原子、不碰他人规则；chain 由 `:GHD_* - [0:0]` 定义，不存在则创建）。
 *
 * App scope 语义：
 * - ALL_APPS（scopeUids=null）：owner 条件 = `! --uid-owner self`，245 条规则直挂在 GHD_TCP。
 * - SELECTED（include=true）：每 UID 只在父链放一条 owner jump，全部 UID 共享一组无 owner 的
 *   `GHD_*_SEL` 载荷链。iptables 无 UID 集合匹配，因此 UID jump 为 O(U)，但 245 条 vIP 与
 *   真实目标规则不再按 UID 复制，整体为 O(U + R)。
 *   显式标记为 Electron-like 宿主的 UID 会在共享目标链返回后追加 TCP/443 全捕获；
 *   IPv6 仅在完整 ip6tables + IPv6 透明监听能力通过时对称启用；
 *   透明监听器只对启用域名应用路由/分片，其余连接按 SO_ORIGINAL_DST 原样透传。
 * - EXCLUDED（include=false）：单链 245 条规则，owner 条件 = `! self` + 每个排除 UID 一条
 *   `! --uid-owner U` 叠加（owner 模块多次匹配可叠加，语义 AND）；上限 8 个，超出抛异常。
 *
 * DNS 与 UDP 黑洞同样应用 scope 语义（SELECTED 分别使用共享链 GHD_DNS_SEL / GHD_UDP_SEL）。
 *
 * 端口编码：vIP 10.0.0.N（N=10..254，245 个）→ 本地监听 tcpBasePort+N（默认 7000+N）。
 */
class FirewallRules(
    private val selfUid: Int,
    private val dnsPort: Int = 5354,
    private val dnsTcpPort: Int = 5355,
    private val tcpBasePort: Int = 7000,
    private val vipSubnet: String = "10.0.0.0/24",
    private val vipStart: Int = 10,
    private val vipEnd: Int = 254,
    /** App scope：null=ALL_APPS；非 null 且 include=true → 仅这些 UID（SELECTED）；include=false → 排除这些 UID（EXCLUDED）。 */
    private val scopeUids: Set<Int>? = null,
    private val scopeInclude: Boolean = true,
    /** SELECTED 中显式启用的 Electron-like/WebView/Cronet 宿主 UID；其他 scope 模式忽略。 */
    private val fullTlsCaptureUids: Set<Int> = emptySet(),
    /** GitHub Meta、已验证候选及观测到的污染目标；分别进入 IPv4/IPv6 数据面。 */
    private val directDestinations: Set<String> = emptySet(),
    private val enableRealIpRedirect: Boolean = false,
    /** 仅在完整 ip6tables nat/owner/REDIRECT/restore 能力探测通过时开启。 */
    private val enableIpv6Redirect: Boolean = false,
    private val directPort: Int = 7443,
    private val useIpSet: Boolean = false,
    private val rejectUdp443: Boolean = false,
    private val rejectIpv6Udp443: Boolean = false,
    /** 仅限当前安全快照中已启用 NAT64 平台域名的 AAAA；必须是精确 /128。 */
    private val nat64Ipv6FallbackDestinations: Set<String> = emptySet(),
    /** ip6tables 不可用时，以 `ip -6 rule uidrange` 对 SELECTED scope 做 IPv4 回落。 */
    private val enableIpv6UidPolicyFallback: Boolean = false,
    val generation: Long = 0,
) {

    private enum class ScopeMode { ALL_APPS, SELECTED, EXCLUDED }

    private val mode: ScopeMode
    private val uids: List<Int>
    private val captureUids: List<Int>
    private val captureUidsV6: List<Int>
    private val directCidrsV4: List<String>
    private val directCidrsV6: List<String>
    private val nat64FallbackUids: List<Int>
    private val nat64FallbackCidrsV6: List<String>
    private val nat64PolicyTable: Int = IPV6_POLICY_TABLE_BASE + (selfUid % IPV6_POLICY_TABLE_SPAN)

    init {
        require(selfUid > 0) { "selfUid 必须 > 0: $selfUid" }
        require(vipStart in 1..255 && vipEnd in vipStart..255) { "vIP 范围非法: $vipStart..$vipEnd" }
        require(vipSubnet.matches(Regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.0/24"))) {
            "vipSubnet 需为 /24 网段（实现按末段递增生成主机地址）: $vipSubnet"
        }
        // 自身 UID 防御性剔除（自身永远排除，不可被选入/排除）
        val effective = scopeUids?.filter { it > 0 && it != selfUid }?.sorted() ?: emptyList()
        mode = when {
            scopeUids == null -> ScopeMode.ALL_APPS
            scopeInclude -> ScopeMode.SELECTED
            else -> ScopeMode.EXCLUDED
        }
        if (mode == ScopeMode.EXCLUDED && effective.size > MAX_EXCLUDED_UIDS) {
            throw IllegalArgumentException("EXCLUDED scope 最多 $MAX_EXCLUDED_UIDS 个 UID，实际 ${effective.size} 个")
        }
        uids = effective
        // 全 TLS 捕获必须同时满足：显式 SELECTED、属于普通 scope、真实 IP 重定向已启用。
        // 这样 ALL/EXCLUDED 不会因一个设置键意外扩大到全设备 HTTPS。
        captureUids = if (mode == ScopeMode.SELECTED && enableRealIpRedirect) {
            fullTlsCaptureUids.asSequence()
                .filter { it > 0 && it != selfUid && it in uids }
                .distinct()
                .sorted()
                .toList()
        } else {
            emptyList()
        }
        // IPv6 全捕获必须额外经过完整 IPv6 netfilter/监听能力门控。不能仅因用户授权
        // full TLS 就生成 ip6tables REDIRECT，否则缺少 [::1] 监听时会制造 IPv6 黑洞。
        captureUidsV6 = if (enableIpv6Redirect) captureUids else emptyList()
        val validDestinations = if (enableRealIpRedirect) {
            directDestinations.asSequence()
                .filter(RouteSnapshotCodec::isRoutableCidr)
                .mapNotNull { cidr ->
                    IpAddresses.parseIpAddress(cidr.substringBefore('/'))?.size?.let { cidr to it }
                }
                .distinct()
                .sortedBy { it.first }
                .toList()
        } else emptyList()
        val limit = if (useIpSet) MAX_IPSET_DESTINATIONS else MAX_INLINE_DESTINATIONS
        directCidrsV4 = validDestinations.asSequence()
            .filter { it.second == 4 }
            .map { it.first }
            .take(limit)
            .toList()
        directCidrsV6 = if (enableIpv6Redirect) {
            validDestinations.asSequence()
                .filter { it.second == 16 }
                .map { it.first }
                .take(limit)
                .toList()
        } else emptyList()
        // 第三方 NAT64 必须保持显式、最小 scope。ALL/EXCLUDED、关闭真实 IP 接管、没有
        // 可用 IPv4 目标或完整 IPv6 透明接管已可用时，都不得安装额外策略路由。
        nat64FallbackUids = if (
            enableIpv6UidPolicyFallback && mode == ScopeMode.SELECTED &&
            enableRealIpRedirect && directCidrsV4.isNotEmpty()
        ) {
            uids.take(MAX_IPV6_POLICY_UIDS)
        } else {
            emptyList()
        }
        nat64FallbackCidrsV6 = if (nat64FallbackUids.isNotEmpty()) {
            nat64Ipv6FallbackDestinations.asSequence()
                .filter { it.endsWith("/128") && RouteSnapshotCodec.isRoutableCidr(it) }
                .filter { cidr ->
                    IpAddresses.parseIpAddress(cidr.substringBefore('/'))?.size == 16
                }
                .distinct()
                .sorted()
                .take(MAX_IPV6_POLICY_DESTINATIONS)
                .toList()
        } else {
            emptyList()
        }
    }

    // ---------- 纯换算 ----------

    /** 主机号 n（vipStart..vipEnd）→ 形如 "10.0.0.10" 的地址串。 */
    private fun vipAddr(n: Int): String = "$vipPrefix$n"

    /** 10.0.0.0/24 → "10.0.0."（仅支持末段主机递增的网段）。 */
    private val vipPrefix: String = vipSubnet.substringBefore("/").substringBeforeLast('.') + "."

    // ---------- owner 条件 ----------

    private fun ownerExcludeSelf(): String = "-m owner ! --uid-owner $selfUid"

    /** 单条规则级 owner 条件（EXCLUDED 时叠加排除；SELECTED/ALL_APPS 由调用方按模式生成）。 */
    private fun ownerCond(): String = when (mode) {
        ScopeMode.ALL_APPS -> ownerExcludeSelf()
        ScopeMode.SELECTED -> ownerExcludeSelf() // 实际不用：jump 规则下分子链
        ScopeMode.EXCLUDED -> ownerExcludeSelf() + uids.joinToString("") { " -m owner ! --uid-owner $it" }
    }

    // ---------- 规则生成 ----------

    /** 一条 vIP TCP REDIRECT（不带 -A 前缀的通用部分）。 */
    private fun tcpVipRule(chain: String, ownerCond: String, n: Int): String =
        "-A $chain ${ownerPrefix(ownerCond)}-d ${vipAddr(n)}/32 -p tcp --dport 443 -j REDIRECT --to-ports ${tcpBasePort + n}"

    private fun tcpDirectRule(chain: String, ownerCond: String, destination: String? = null): String {
        val destinationMatch = if (destination != null) "-d $destination" else "-m set --match-set $IPSET_ACTIVE dst"
        return "-A $chain ${ownerPrefix(ownerCond)}$destinationMatch -p tcp --dport 443 -j REDIRECT --to-ports $directPort"
    }

    private fun tcpDirectRuleV6(chain: String, ownerCond: String, destination: String? = null): String {
        val destinationMatch = if (destination != null) "-d $destination" else "-m set --match-set $IPSET_ACTIVE_V6 dst"
        return "-A $chain ${ownerPrefix(ownerCond)}$destinationMatch -p tcp --dport 443 -j REDIRECT --to-ports $directPort"
    }

    /** Electron-like 宿主兜底：共享目标链未命中后，把该 UID 的其余 TCP/443 送入透明监听器。 */
    private fun tcpAllRule(chain: String, ownerCond: String): String =
        "-A $chain ${ownerPrefix(ownerCond)}-p tcp --dport 443 -j REDIRECT --to-ports $directPort"

    private fun ownerPrefix(ownerCond: String): String =
        ownerCond.trim().takeIf(String::isNotEmpty)?.plus(" ").orEmpty()

    /** SELECTED 的跳转条件（自身排除 + uid 匹配）。 */
    private fun selectJumpCond(uid: Int): String = "${ownerExcludeSelf()} -m owner --uid-owner $uid"

    /** nat 表规则体（不含 *nat/COMMIT）。刷新时沿用既有 OUTPUT jump，避免重复追加。 */
    private fun natRules(includeOutputJumps: Boolean = true): List<String> {
        val rules = mutableListOf<String>()
        if (includeOutputJumps) {
            rules += "-A OUTPUT -j $CHAIN_DNS"
            rules += "-A OUTPUT -j $CHAIN_TCP"
        }
        when (mode) {
            ScopeMode.ALL_APPS -> {
                rules += dnsRules(CHAIN_DNS, ownerCond())
                rules += tcpRules(CHAIN_TCP, ownerCond())
            }
            ScopeMode.SELECTED -> {
                for (uid in uids) {
                    rules += "-A $CHAIN_DNS ${selectJumpCond(uid)} -j $CHAIN_DNS_SELECTED"
                    rules += "-A $CHAIN_TCP ${selectJumpCond(uid)} -j $CHAIN_TCP_SELECTED"
                    if (uid in captureUids) {
                        // GHD_TCP_SEL 先处理 vIP/已知候选；返回父链后才执行全 TLS 兜底。
                        rules += tcpAllRule(CHAIN_TCP, selectJumpCond(uid))
                    }
                }
                if (uids.isNotEmpty()) {
                    rules += dnsRules(CHAIN_DNS_SELECTED, "")
                    rules += tcpRules(CHAIN_TCP_SELECTED, "")
                }
            }
            ScopeMode.EXCLUDED -> {
                val cond = ownerCond()
                rules += dnsRules(CHAIN_DNS, cond)
                rules += tcpRules(CHAIN_TCP, cond)
            }
        }
        return rules
    }

    private fun dnsRules(chain: String, ownerCond: String): List<String> = listOf(
        "-A $chain ${ownerPrefix(ownerCond)}-p udp --dport 53 -j REDIRECT --to-ports $dnsPort",
        "-A $chain ${ownerPrefix(ownerCond)}-p tcp --dport 53 -j REDIRECT --to-ports $dnsTcpPort",
    )

    private fun tcpVipRules(chain: String, ownerCond: String): List<String> =
        (vipStart..vipEnd).map { tcpVipRule(chain, ownerCond, it) }

    private fun tcpRules(chain: String, ownerCond: String): List<String> = buildList {
        addAll(tcpVipRules(chain, ownerCond))
        if (directCidrsV4.isEmpty()) return@buildList
        if (usesIpv4IpSet()) add(tcpDirectRule(chain, ownerCond))
        else directCidrsV4.forEach { add(tcpDirectRule(chain, ownerCond, it)) }
    }

    /** filter 表规则体（UDP 黑洞）；刷新时沿用既有 OUTPUT jump。 */
    private fun filterRules(includeOutputJumps: Boolean = true): List<String> {
        val rules = mutableListOf<String>()
        if (includeOutputJumps) rules += "-A OUTPUT -j $CHAIN_UDP_DROP"
        when (mode) {
            ScopeMode.ALL_APPS -> rules += udpRules(CHAIN_UDP_DROP, ownerCond())
            ScopeMode.SELECTED -> for (uid in uids) {
                rules += "-A $CHAIN_UDP_DROP ${selectJumpCond(uid)} -j $CHAIN_UDP_SELECTED"
                if (uid in captureUids) {
                    // 内置 Chromium/Cronet 可能先走 QUIC；仅对显式宿主阻断 IPv4 UDP/443，促使 TCP 回退。
                    rules += udpAllRule(CHAIN_UDP_DROP, selectJumpCond(uid))
                }
            }
            ScopeMode.EXCLUDED -> rules += udpRules(CHAIN_UDP_DROP, ownerCond())
        }
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            rules += udpRules(CHAIN_UDP_SELECTED, "")
        }
        return rules
    }

    private fun udpDropRule(chain: String, ownerCond: String): String =
        udpRule(chain, ownerCond, vipSubnet)

    private fun udpRule(chain: String, ownerCond: String, destination: String? = null): String {
        val destinationMatch = if (destination != null) "-d $destination" else "-m set --match-set $IPSET_ACTIVE dst"
        val action = if (rejectUdp443) "REJECT --reject-with icmp-port-unreachable" else "DROP"
        return "-A $chain ${ownerPrefix(ownerCond)}$destinationMatch -p udp --dport 443 -j $action"
    }

    private fun udpAllRule(chain: String, ownerCond: String): String {
        val action = if (rejectUdp443) "REJECT --reject-with icmp-port-unreachable" else "DROP"
        return "-A $chain ${ownerPrefix(ownerCond)}-p udp --dport 443 -j $action"
    }

    private fun udpRules(chain: String, ownerCond: String): List<String> = buildList {
        add(udpDropRule(chain, ownerCond))
        if (directCidrsV4.isEmpty()) return@buildList
        if (usesIpv4IpSet()) add(udpRule(chain, ownerCond))
        else directCidrsV4.forEach { add(udpRule(chain, ownerCond, it)) }
    }

    private fun tcpRulesV6(chain: String, ownerCond: String): List<String> = buildList {
        if (usesIpv6IpSet()) add(tcpDirectRuleV6(chain, ownerCond))
        else directCidrsV6.forEach { add(tcpDirectRuleV6(chain, ownerCond, it)) }
    }

    private fun udpRuleV6(chain: String, ownerCond: String, destination: String? = null): String {
        val destinationMatch = if (destination != null) "-d $destination" else "-m set --match-set $IPSET_ACTIVE_V6 dst"
        val action = if (rejectIpv6Udp443) {
            "REJECT --reject-with icmp6-port-unreachable"
        } else {
            "DROP"
        }
        return "-A $chain ${ownerPrefix(ownerCond)}$destinationMatch -p udp --dport 443 -j $action"
    }

    private fun udpRulesV6(chain: String, ownerCond: String): List<String> = buildList {
        if (usesIpv6IpSet()) add(udpRuleV6(chain, ownerCond))
        else directCidrsV6.forEach { add(udpRuleV6(chain, ownerCond, it)) }
    }

    private fun udpAllRuleV6(chain: String, ownerCond: String): String {
        val action = if (rejectIpv6Udp443) {
            "REJECT --reject-with icmp6-port-unreachable"
        } else {
            "DROP"
        }
        return "-A $chain ${ownerPrefix(ownerCond)}-p udp --dport 443 -j $action"
    }

    private fun natRulesV6(includeOutputJumps: Boolean = true): List<String> = buildList {
        if (includeOutputJumps) add("-A OUTPUT -j $CHAIN_TCP_V6")
        when (mode) {
            ScopeMode.ALL_APPS -> addAll(tcpRulesV6(CHAIN_TCP_V6, ownerCond()))
            ScopeMode.SELECTED -> for (uid in uids) {
                add("-A $CHAIN_TCP_V6 ${selectJumpCond(uid)} -j $CHAIN_TCP_V6_SELECTED")
                if (uid in captureUidsV6) {
                    // 已知 IPv6 目标先在共享子链处理；返回后才执行该 UID 的全 TLS 兜底。
                    add(tcpAllRule(CHAIN_TCP_V6, selectJumpCond(uid)))
                }
            }
            ScopeMode.EXCLUDED -> addAll(tcpRulesV6(CHAIN_TCP_V6, ownerCond()))
        }
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            addAll(tcpRulesV6(CHAIN_TCP_V6_SELECTED, ""))
        }
    }

    private fun filterRulesV6(includeOutputJumps: Boolean = true): List<String> = buildList {
        if (includeOutputJumps) add("-A OUTPUT -j $CHAIN_UDP_V6")
        when (mode) {
            ScopeMode.ALL_APPS -> addAll(udpRulesV6(CHAIN_UDP_V6, ownerCond()))
            ScopeMode.SELECTED -> for (uid in uids) {
                add("-A $CHAIN_UDP_V6 ${selectJumpCond(uid)} -j $CHAIN_UDP_V6_SELECTED")
                if (uid in captureUidsV6) {
                    // 对显式宿主阻断其余 IPv6 QUIC，促使 Chromium/Cronet 回退到 TCP。
                    add(udpAllRuleV6(CHAIN_UDP_V6, selectJumpCond(uid)))
                }
            }
            ScopeMode.EXCLUDED -> addAll(udpRulesV6(CHAIN_UDP_V6, ownerCond()))
        }
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            addAll(udpRulesV6(CHAIN_UDP_V6_SELECTED, ""))
        }
    }

    /** 自有 chain 定义行（`-N` 在 restore 中 = `:CHAIN - [0:0]`）。 */
    private fun chainDefs(): List<String> {
        val defs = mutableListOf(":$CHAIN_DNS - [0:0]", ":$CHAIN_TCP - [0:0]")
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            defs += ":$CHAIN_DNS_SELECTED - [0:0]"
            defs += ":$CHAIN_TCP_SELECTED - [0:0]"
        }
        return defs
    }

    // ---------- 对外 API ----------

    /**
     * 安装脚本：`*nat` / `*filter` 两表只声明自有 chain，再追加 OUTPUT jump 与具体规则。
     * `--noflush` 增量脚本不得声明 `:OUTPUT ACCEPT`，否则会修改设备现有内建链策略。
     */
    fun buildInstallScript(): String = buildIpv4Script(includeOutputJumps = true)

    /**
     * ACTIVE 代次原位刷新脚本。`--noflush` 下重新声明用户链会在表 COMMIT 时原子清空并
     * 重建该链；既有 OUTPUT jump 始终保留，因此不会产生链缺失或重复 jump 窗口。
     */
    fun buildRefreshScript(): String = buildIpv4Script(includeOutputJumps = false)

    private fun buildIpv4Script(includeOutputJumps: Boolean): String {
        val sb = StringBuilder()
        sb.appendLine("*nat")
        chainDefs().forEach { sb.appendLine(it) }
        natRules(includeOutputJumps).forEach { sb.appendLine(it) }
        sb.appendLine("COMMIT")
        sb.appendLine("*filter")
        sb.appendLine(":$CHAIN_UDP_DROP - [0:0]")
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            sb.appendLine(":$CHAIN_UDP_SELECTED - [0:0]")
        }
        filterRules(includeOutputJumps).forEach { sb.appendLine(it) }
        sb.appendLine("COMMIT")
        // legacy iptables-restore 要求最后一个 COMMIT 也以换行结束；trimEnd() 会让部分
        // Android 工具箱在 EOF 处报 `Bad argument COMMIT`。
        return sb.toString()
    }

    /** 独立交给 ip6tables-restore；空串表示本代没有可安装的 IPv6 目标。 */
    fun buildIpv6InstallScript(): String =
        if (!usesIpv6RealIpRedirect()) "" else buildIpv6Script(includeOutputJumps = true)

    /**
     * IPv6 代次转换：
     * - disabled -> enabled：首次安装并挂 OUTPUT jump；
     * - enabled -> enabled：保留 jump，原位替换链内容；
     * - enabled -> disabled：同一 restore 表事务内移除 jump 并清空旧链。
     */
    fun buildIpv6RefreshScript(previous: FirewallRules): String = when {
        !previous.usesIpv6RealIpRedirect() && !usesIpv6RealIpRedirect() -> ""
        !previous.usesIpv6RealIpRedirect() -> buildIpv6InstallScript()
        usesIpv6RealIpRedirect() -> buildIpv6Script(includeOutputJumps = false)
        else -> previous.buildIpv6DisableScript()
    }

    private fun buildIpv6Script(includeOutputJumps: Boolean): String {
        val sb = StringBuilder()
        sb.appendLine("*nat")
        sb.appendLine(":$CHAIN_TCP_V6 - [0:0]")
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            sb.appendLine(":$CHAIN_TCP_V6_SELECTED - [0:0]")
        }
        natRulesV6(includeOutputJumps).forEach { sb.appendLine(it) }
        sb.appendLine("COMMIT")
        sb.appendLine("*filter")
        sb.appendLine(":$CHAIN_UDP_V6 - [0:0]")
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            sb.appendLine(":$CHAIN_UDP_V6_SELECTED - [0:0]")
        }
        filterRulesV6(includeOutputJumps).forEach { sb.appendLine(it) }
        sb.appendLine("COMMIT")
        return sb.toString()
    }

    private fun buildIpv6DisableScript(): String {
        val (nat, filter) = ownedIpv6ChainNames()
        val sb = StringBuilder()
        sb.appendLine("*nat")
        nat.forEach { sb.appendLine(":$it - [0:0]") }
        sb.appendLine("-D OUTPUT -j $CHAIN_TCP_V6")
        sb.appendLine("COMMIT")
        sb.appendLine("*filter")
        filter.forEach { sb.appendLine(":$it - [0:0]") }
        sb.appendLine("-D OUTPUT -j $CHAIN_UDP_V6")
        sb.appendLine("COMMIT")
        return sb.toString()
    }

    fun usesRealIpRedirect(): Boolean =
        captureUids.isNotEmpty() || directCidrsV4.isNotEmpty() || directCidrsV6.isNotEmpty()

    fun usesIpv6RealIpRedirect(): Boolean =
        directCidrsV6.isNotEmpty() || captureUidsV6.isNotEmpty()

    fun usesNat64Ipv6Fallback(): Boolean =
        nat64FallbackUids.isNotEmpty() && nat64FallbackCidrsV6.isNotEmpty()

    fun usesIpSet(): Boolean = usesIpv4IpSet() || usesIpv6IpSet()

    private fun usesIpv4IpSet(): Boolean = useIpSet && directCidrsV4.isNotEmpty()

    private fun usesIpv6IpSet(): Boolean = useIpSet && directCidrsV6.isNotEmpty()

    fun directDestinationCount(): Int = directCidrsV4.size

    fun directIpv6DestinationCount(): Int = directCidrsV6.size

    fun nat64Ipv6FallbackDestinationCount(): Int = nat64FallbackCidrsV6.size

    fun fullTlsCaptureUidCount(): Int = captureUids.size

    /** ipset 探测出现假阳性时保留同一 scope/代次，切换到有上限的逐 CIDR 规则。 */
    fun withoutIpSet(): FirewallRules = FirewallRules(
        selfUid = selfUid,
        dnsPort = dnsPort,
        dnsTcpPort = dnsTcpPort,
        tcpBasePort = tcpBasePort,
        vipSubnet = vipSubnet,
        vipStart = vipStart,
        vipEnd = vipEnd,
        scopeUids = scopeUids,
        scopeInclude = scopeInclude,
        fullTlsCaptureUids = fullTlsCaptureUids,
        directDestinations = directDestinations,
        enableRealIpRedirect = enableRealIpRedirect,
        enableIpv6Redirect = enableIpv6Redirect,
        directPort = directPort,
        useIpSet = false,
        rejectUdp443 = rejectUdp443,
        rejectIpv6Udp443 = rejectIpv6Udp443,
        nat64Ipv6FallbackDestinations = nat64Ipv6FallbackDestinations,
        enableIpv6UidPolicyFallback = enableIpv6UidPolicyFallback,
        generation = generation,
    )

    /**
     * 安装顺序必须先建不可达路由，再发布 UID 规则；这样任一步失败都不会把 UID 指向
     * 空表。每个 UID 只占一条 rule，目标数只影响独立表内的 /128 路由，规模 O(U + R)。
     */
    fun buildNat64Ipv6FallbackInstallCommands(): List<String> {
        if (!usesNat64Ipv6Fallback()) return emptyList()
        return buildList {
            nat64FallbackCidrsV6.forEach { destination ->
                add("ip -6 route add unreachable $destination table $nat64PolicyTable")
            }
            nat64FallbackUids.forEachIndexed { index, uid ->
                add(
                    "ip -6 rule add priority ${nat64PolicyPriority(index)} " +
                        "uidrange $uid-$uid lookup $nat64PolicyTable",
                )
            }
        }
    }

    /**
     * 只删除本模块固定优先级窗口内、同时指向本 app 专属表的 rule，再 flush 该表；避免
     * `del table` 误删其他组件碰巧复用同一表号的规则。guardian 使用同一序列，应用死亡后
     * 约 15 秒恢复原生 IPv6（fail-open）。
     */
    fun buildNat64Ipv6FallbackCleanupCommands(): List<String> = buildList {
        repeat(MAX_IPV6_POLICY_UIDS) { index ->
            add(
                "ip -6 rule del priority ${nat64PolicyPriority(index)} " +
                    "table $nat64PolicyTable",
            )
        }
        add("ip -6 route flush table $nat64PolicyTable")
    }

    private fun nat64PolicyPriority(index: Int): Int {
        require(index in 0 until MAX_IPV6_POLICY_UIDS)
        return IPV6_POLICY_PRIORITY_BASE + index
    }

    /** 安装前构造同类型临时集合并 swap；chain 始终只引用固定的 active 名称。 */
    fun buildIpSetInstallCommands(): List<String> {
        return buildList {
            if (usesIpv4IpSet()) addAll(ipSetInstallCommands(IPSET_ACTIVE, IPSET_NEXT, "inet", directCidrsV4))
            if (usesIpv6IpSet()) addAll(ipSetInstallCommands(IPSET_ACTIVE_V6, IPSET_NEXT_V6, "inet6", directCidrsV6))
        }
    }

    private fun ipSetInstallCommands(
        active: String,
        next: String,
        family: String,
        cidrs: List<String>,
    ): List<String> = buildList {
        add("ipset create $active hash:net family $family timeout $IPSET_LEASE_SECONDS -exist")
        add("ipset create $next hash:net family $family timeout $IPSET_LEASE_SECONDS -exist")
        add("ipset flush $next")
        cidrs.forEach { add("ipset add $next $it timeout $IPSET_LEASE_SECONDS -exist") }
        add("ipset swap $next $active")
        add("ipset destroy $next")
    }

    /** 服务每 5 秒调用；若服务死亡，元素约 20 秒后自然过期，规则链变成 fail-open。 */
    fun buildIpSetLeaseRefreshCommands(): List<String> =
        buildList {
            if (usesIpv4IpSet()) {
                directCidrsV4.forEach { add("ipset add $IPSET_ACTIVE $it timeout $IPSET_LEASE_SECONDS -exist") }
            }
            if (usesIpv6IpSet()) {
                directCidrsV6.forEach { add("ipset add $IPSET_ACTIVE_V6 $it timeout $IPSET_LEASE_SECONDS -exist") }
            }
        }

    fun buildIpSetCleanupCommands(): List<String> = listOf(
        "ipset destroy $IPSET_NEXT",
        "ipset destroy $IPSET_ACTIVE",
        "ipset destroy $IPSET_NEXT_V6",
        "ipset destroy $IPSET_ACTIVE_V6",
    )

    /**
     * 原位刷新提交后，只清理新代次不再使用的孤儿子链/IPv6 链与 ipset。
     * 主 IPv4 链始终被复用，不会出现在结果中；命令均可 best-effort 幂等执行。
     */
    fun buildPostRefreshCleanupCommands(next: FirewallRules): List<String> = buildList {
        val (oldNat, oldFilter) = ownedChainNames()
        val (nextNat, nextFilter) = next.ownedChainNames()
        appendObsoleteChainCleanup(
            binary = "iptables",
            obsoleteNat = oldNat.filterNot(nextNat::contains),
            obsoleteFilter = oldFilter.filterNot(nextFilter::contains),
        )

        val (oldNatV6, oldFilterV6) = ownedIpv6ChainNames()
        val (nextNatV6, nextFilterV6) = next.ownedIpv6ChainNames()
        val obsoleteNatV6 = if (usesIpv6RealIpRedirect()) {
            oldNatV6.filterNot { next.usesIpv6RealIpRedirect() && it in nextNatV6 }
        } else {
            emptyList()
        }
        val obsoleteFilterV6 = if (usesIpv6RealIpRedirect()) {
            oldFilterV6.filterNot { next.usesIpv6RealIpRedirect() && it in nextFilterV6 }
        } else {
            emptyList()
        }
        if (CHAIN_TCP_V6 in obsoleteNatV6) add("ip6tables -t nat -D OUTPUT -j $CHAIN_TCP_V6")
        if (CHAIN_UDP_V6 in obsoleteFilterV6) add("ip6tables -t filter -D OUTPUT -j $CHAIN_UDP_V6")
        appendObsoleteChainCleanup("ip6tables", obsoleteNatV6, obsoleteFilterV6)

        if (usesIpv4IpSet() && !next.usesIpv4IpSet()) {
            add("ipset destroy $IPSET_NEXT")
            add("ipset destroy $IPSET_ACTIVE")
        }
        if (usesIpv6IpSet() && !next.usesIpv6IpSet()) {
            add("ipset destroy $IPSET_NEXT_V6")
            add("ipset destroy $IPSET_ACTIVE_V6")
        }
    }

    private fun MutableList<String>.appendObsoleteChainCleanup(
        binary: String,
        obsoleteNat: List<String>,
        obsoleteFilter: List<String>,
    ) {
        obsoleteNat.forEach { add("$binary -t nat -F $it") }
        obsoleteFilter.forEach { add("$binary -t filter -F $it") }
        obsoleteNat.forEach { add("$binary -t nat -X $it") }
        obsoleteFilter.forEach { add("$binary -t filter -X $it") }
    }

    /**
     * 清理命令序列（普通 iptables 命令，幂等）：删 OUTPUT jump → flush 自己 chain → 删自己 chain。
     * 不存在的规则/chain 报错可忽略（逐条失败不影响后续；sh 无 set -e）。
     */
    fun buildCleanupCommands(): List<String> {
        val (nat, filter) = ownedChainNames()
        val cmds = mutableListOf<String>()
        // 1) 删 OUTPUT jump（仅主链有 jump；子链被父链引用，删引用靠 flush 父链）
        nat.filter { it == CHAIN_DNS || it == CHAIN_TCP }.forEach { cmds += "iptables -t nat -D OUTPUT -j $it" }
        filter.filter { it == CHAIN_UDP_DROP }.forEach { cmds += "iptables -t filter -D OUTPUT -j $it" }
        // 2) flush 自己 chain（含子链——flush 父链即解除对子链的引用）
        nat.forEach { cmds += "iptables -t nat -F $it" }
        filter.forEach { cmds += "iptables -t filter -F $it" }
        // 3) 删自己 chain
        nat.forEach { cmds += "iptables -t nat -X $it" }
        filter.forEach { cmds += "iptables -t filter -X $it" }
        if (usesIpv6RealIpRedirect()) {
            val (natV6, filterV6) = ownedIpv6ChainNames()
            natV6.filter { it == CHAIN_TCP_V6 }.forEach { cmds += "ip6tables -t nat -D OUTPUT -j $it" }
            filterV6.filter { it == CHAIN_UDP_V6 }.forEach { cmds += "ip6tables -t filter -D OUTPUT -j $it" }
            natV6.forEach { cmds += "ip6tables -t nat -F $it" }
            filterV6.forEach { cmds += "ip6tables -t filter -F $it" }
            natV6.forEach { cmds += "ip6tables -t nat -X $it" }
            filterV6.forEach { cmds += "ip6tables -t filter -X $it" }
        }
        cmds += buildNat64Ipv6FallbackCleanupCommands()
        return cmds
    }

    /** 本规则集拥有的 chain 名（nat, filter），cleanup 与残留清扫共用。 */
    fun ownedChainNames(): Pair<List<String>, List<String>> {
        val nat = mutableListOf(CHAIN_DNS, CHAIN_TCP)
        val filter = mutableListOf(CHAIN_UDP_DROP)
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            nat += CHAIN_DNS_SELECTED
            nat += CHAIN_TCP_SELECTED
            filter += CHAIN_UDP_SELECTED
        }
        return nat to filter
    }

    /** 本规则集拥有的 IPv6 chain 名（nat, filter）。 */
    fun ownedIpv6ChainNames(): Pair<List<String>, List<String>> {
        val nat = mutableListOf(CHAIN_TCP_V6)
        val filter = mutableListOf(CHAIN_UDP_V6)
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            nat += CHAIN_TCP_V6_SELECTED
            filter += CHAIN_UDP_V6_SELECTED
        }
        return nat to filter
    }

    /**
     * 校验特征行：iptables-save / `iptables -S` 输出中应原样出现的规则行
     * （校验方对每行做子串匹配；行与安装脚本中的规则行完全一致）。
     */
    fun expectedMarkers(): List<String> {
        val markers = mutableListOf<String>()
        markers += "-A OUTPUT -j $CHAIN_DNS"
        markers += "-A OUTPUT -j $CHAIN_TCP"
        markers += "-A OUTPUT -j $CHAIN_UDP_DROP"
        when (mode) {
            ScopeMode.ALL_APPS -> {
                markers += tcpVipRule(CHAIN_TCP, ownerCond(), vipStart)
                markers += tcpVipRule(CHAIN_TCP, ownerCond(), vipEnd)
                markers += dnsRules(CHAIN_DNS, ownerCond())
                markers += udpDropRule(CHAIN_UDP_DROP, ownerCond())
                addDirectMarkers(markers, CHAIN_TCP, CHAIN_UDP_DROP, ownerCond())
            }
            ScopeMode.SELECTED -> {
                if (uids.isNotEmpty()) {
                    val uid = uids.first()
                    markers += "-A $CHAIN_TCP ${selectJumpCond(uid)} -j $CHAIN_TCP_SELECTED"
                    markers += tcpVipRule(CHAIN_TCP_SELECTED, "", vipStart)
                    markers += tcpVipRule(CHAIN_TCP_SELECTED, "", vipEnd)
                    markers += dnsRules(CHAIN_DNS_SELECTED, "")
                    markers += udpDropRule(CHAIN_UDP_SELECTED, "")
                    addDirectMarkers(markers, CHAIN_TCP_SELECTED, CHAIN_UDP_SELECTED, "")
                    captureUids.firstOrNull()?.let { captureUid ->
                        markers += tcpAllRule(CHAIN_TCP, selectJumpCond(captureUid))
                        markers += udpAllRule(CHAIN_UDP_DROP, selectJumpCond(captureUid))
                    }
                }
            }
            ScopeMode.EXCLUDED -> {
                val cond = ownerCond()
                markers += tcpVipRule(CHAIN_TCP, cond, vipStart)
                markers += tcpVipRule(CHAIN_TCP, cond, vipEnd)
                markers += dnsRules(CHAIN_DNS, cond)
                markers += udpDropRule(CHAIN_UDP_DROP, cond)
                addDirectMarkers(markers, CHAIN_TCP, CHAIN_UDP_DROP, cond)
            }
        }
        addIpv6Markers(markers)
        addNat64Ipv6FallbackMarkers(markers)
        return markers
    }

    private fun addNat64Ipv6FallbackMarkers(markers: MutableList<String>) {
        if (!usesNat64Ipv6Fallback()) return
        nat64FallbackUids.firstOrNull()?.let { uid ->
            markers += "uidrange $uid-$uid lookup $nat64PolicyTable"
        }
        nat64FallbackUids.lastOrNull()?.takeIf { it != nat64FallbackUids.firstOrNull() }?.let { uid ->
            markers += "uidrange $uid-$uid lookup $nat64PolicyTable"
        }
        markers += "unreachable ${nat64FallbackCidrsV6.first().substringBefore('/')}"
        nat64FallbackCidrsV6.lastOrNull()
            ?.takeIf { it != nat64FallbackCidrsV6.first() }
            ?.let { markers += "unreachable ${it.substringBefore('/')}" }
    }

    private fun addIpv6Markers(markers: MutableList<String>) {
        if (!usesIpv6RealIpRedirect()) return
        markers += "-A OUTPUT -j $CHAIN_TCP_V6"
        markers += "-A OUTPUT -j $CHAIN_UDP_V6"
        when (mode) {
            ScopeMode.ALL_APPS -> {
                if (directCidrsV6.isNotEmpty()) {
                    addDirectMarkersV6(markers, CHAIN_TCP_V6, CHAIN_UDP_V6, ownerCond())
                }
            }
            ScopeMode.SELECTED -> {
                if (uids.isEmpty()) return
                val uid = uids.first()
                markers += "-A $CHAIN_TCP_V6 ${selectJumpCond(uid)} -j $CHAIN_TCP_V6_SELECTED"
                markers += "-A $CHAIN_UDP_V6 ${selectJumpCond(uid)} -j $CHAIN_UDP_V6_SELECTED"
                if (directCidrsV6.isNotEmpty()) {
                    addDirectMarkersV6(markers, CHAIN_TCP_V6_SELECTED, CHAIN_UDP_V6_SELECTED, "")
                }
                captureUidsV6.firstOrNull()?.let { captureUid ->
                    markers += tcpAllRule(CHAIN_TCP_V6, selectJumpCond(captureUid))
                    markers += udpAllRuleV6(CHAIN_UDP_V6, selectJumpCond(captureUid))
                }
            }
            ScopeMode.EXCLUDED -> {
                if (directCidrsV6.isNotEmpty()) {
                    addDirectMarkersV6(markers, CHAIN_TCP_V6, CHAIN_UDP_V6, ownerCond())
                }
            }
        }
    }

    /**
     * 校验只读取 OUTPUT 与本代实际使用的 GHD_* 链，避免多 UID 规则让完整
     * `iptables-save` 输出达到数百 KiB 后被命令捕获上限截断。
     */
    fun verificationCommands(): List<String> = buildList {
        add("iptables -t nat -S OUTPUT")
        add("iptables -t filter -S OUTPUT")
        add("iptables -t nat -S $CHAIN_DNS")
        add("iptables -t nat -S $CHAIN_TCP")
        add("iptables -t filter -S $CHAIN_UDP_DROP")
        if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
            add("iptables -t nat -S $CHAIN_DNS_SELECTED")
            add("iptables -t nat -S $CHAIN_TCP_SELECTED")
            add("iptables -t filter -S $CHAIN_UDP_SELECTED")
        }
        if (usesIpv6RealIpRedirect()) {
            add("ip6tables -t nat -S OUTPUT")
            add("ip6tables -t filter -S OUTPUT")
            add("ip6tables -t nat -S $CHAIN_TCP_V6")
            add("ip6tables -t filter -S $CHAIN_UDP_V6")
            if (mode == ScopeMode.SELECTED && uids.isNotEmpty()) {
                add("ip6tables -t nat -S $CHAIN_TCP_V6_SELECTED")
                add("ip6tables -t filter -S $CHAIN_UDP_V6_SELECTED")
            }
        }
        if (usesNat64Ipv6Fallback()) {
            add("ip -6 rule show")
            add("ip -6 route show table $nat64PolicyTable")
        }
    }

    private fun addDirectMarkers(
        markers: MutableList<String>,
        tcpChain: String,
        udpChain: String,
        ownerCond: String,
    ) {
        if (directCidrsV4.isEmpty()) return
        if (usesIpv4IpSet()) {
            markers += tcpDirectRule(tcpChain, ownerCond)
            markers += udpRule(udpChain, ownerCond)
        } else {
            markers += tcpDirectRule(tcpChain, ownerCond, directCidrsV4.first())
            markers += tcpDirectRule(tcpChain, ownerCond, directCidrsV4.last())
            markers += udpRule(udpChain, ownerCond, directCidrsV4.first())
        }
    }

    private fun addDirectMarkersV6(
        markers: MutableList<String>,
        tcpChain: String,
        udpChain: String,
        ownerCond: String,
    ) {
        if (usesIpv6IpSet()) {
            markers += tcpDirectRuleV6(tcpChain, ownerCond)
            markers += udpRuleV6(udpChain, ownerCond)
        } else {
            markers += tcpDirectRuleV6(tcpChain, ownerCond, directCidrsV6.first())
            markers += tcpDirectRuleV6(tcpChain, ownerCond, directCidrsV6.last())
            markers += udpRuleV6(udpChain, ownerCond, directCidrsV6.first())
        }
    }

    companion object {
        const val MAX_EXCLUDED_UIDS = 8
        const val CHAIN_DNS = "GHD_DNS"
        const val CHAIN_TCP = "GHD_TCP"
        const val CHAIN_UDP_DROP = "GHD_UDP_DROP"
        const val CHAIN_TCP_V6 = "GHD_6_TCP"
        const val CHAIN_UDP_V6 = "GHD_6_UDP"
        const val CHAIN_DNS_SELECTED = "GHD_DNS_SEL"
        const val CHAIN_TCP_SELECTED = "GHD_TCP_SEL"
        const val CHAIN_UDP_SELECTED = "GHD_UDP_SEL"
        const val CHAIN_TCP_V6_SELECTED = "GHD_6_TCP_SEL"
        const val CHAIN_UDP_V6_SELECTED = "GHD_6_UDP_SEL"
        const val IPSET_ACTIVE = "GHD_DST"
        const val IPSET_NEXT = "GHD_DST_NEXT"
        const val IPSET_ACTIVE_V6 = "GHD_DST6"
        const val IPSET_NEXT_V6 = "GHD_DST6_NEXT"
        const val IPSET_LEASE_SECONDS = 20
        const val MAX_INLINE_DESTINATIONS = 128
        const val MAX_IPSET_DESTINATIONS = 512
        const val MAX_IPV6_POLICY_UIDS = 32
        const val MAX_IPV6_POLICY_DESTINATIONS = 128
        private const val IPV6_POLICY_TABLE_BASE = 52_000
        private const val IPV6_POLICY_TABLE_SPAN = 1_000
        private const val IPV6_POLICY_PRIORITY_BASE = 10_500
    }
}

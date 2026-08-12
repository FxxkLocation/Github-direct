package org.xiyu.githubdirect.root

/**
 * FirewallRules —— iptables-restore 安装脚本 / 清理命令 / 校验特征行的**纯字符串生成**（不执行）。
 *
 * 规则语义（设计 §20/§23 与端口编码 REDIRECT 决策）：
 * - nat 表自有 chain：`GHD_DNS`（DNS UDP 5354 + TCP 5355 重定向）、`GHD_TCP`（245 条 vIP TCP 重定向）；
 *   filter 表自有 chain：`GHD_UDP_DROP`（vIP UDP 黑洞，QUIC 客户端 TCP 回退）。
 * - 只管理自有 chain：卸载 = 删 OUTPUT jump → flush 自己 chain → 删自己 chain（先删引用再删除）。
 * - 自身 UID 排除：所有规则带 `-m owner ! --uid-owner <selfUid>`，DoH/relay/探活自身流量不进规则。
 * - 安装用 iptables-restore `--noflush`（原子、不碰他人规则；chain 由 `:GHD_* - [0:0]` 定义，不存在则创建）。
 *
 * App scope 语义：
 * - ALL_APPS（scopeUids=null）：owner 条件 = `! --uid-owner self`，245 条规则直挂在 GHD_TCP。
 * - SELECTED（include=true）：每 UID 一子链 `GHD_TCP_UID_<uid>`（245 条规则无 owner 匹配），
 *   GHD_TCP 内 jump 规则 `-m owner ! --uid-owner self -m owner --uid-owner U -j GHD_TCP_UID_U`
 *   （iptables 无 IN 集合匹配，每 UID 一条 jump；多 -m owner 语义 AND）。
 * - EXCLUDED（include=false）：单链 245 条规则，owner 条件 = `! self` + 每个排除 UID 一条
 *   `! --uid-owner U` 叠加（owner 模块多次匹配可叠加，语义 AND）；上限 8 个，超出抛异常。
 *
 * DNS 与 UDP 黑洞同样应用 scope 语义（SELECTED 用子链 GHD_DNS_UID_U / GHD_UDP_DROP_UID_U）。
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
) {

    private enum class ScopeMode { ALL_APPS, SELECTED, EXCLUDED }

    private val mode: ScopeMode
    private val uids: List<Int>

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
        "-A $chain $ownerCond -d ${vipAddr(n)}/32 -p tcp --dport 443 -j REDIRECT --to-ports ${tcpBasePort + n}"

    /** SELECTED 的跳转条件（自身排除 + uid 匹配）。 */
    private fun selectJumpCond(uid: Int): String = "${ownerExcludeSelf()} -m owner --uid-owner $uid"

    /** nat 表规则体（不含 *nat/COMMIT）。 */
    private fun natRules(): List<String> {
        val rules = mutableListOf<String>()
        rules += "-A OUTPUT -j $CHAIN_DNS"
        rules += "-A OUTPUT -j $CHAIN_TCP"
        when (mode) {
            ScopeMode.ALL_APPS -> {
                rules += dnsRules(CHAIN_DNS, ownerCond())
                rules += tcpVipRules(CHAIN_TCP, ownerCond())
            }
            ScopeMode.SELECTED -> {
                for (uid in uids) {
                    val dnsChain = uidChain(CHAIN_DNS, uid)
                    val tcpChain = uidChain(CHAIN_TCP, uid)
                    rules += "-A $CHAIN_DNS ${selectJumpCond(uid)} -j $dnsChain"
                    rules += "-A $CHAIN_TCP ${selectJumpCond(uid)} -j $tcpChain"
                    rules += dnsRules(dnsChain, "")
                    rules += tcpVipRules(tcpChain, "")
                }
            }
            ScopeMode.EXCLUDED -> {
                val cond = ownerCond()
                rules += dnsRules(CHAIN_DNS, cond)
                rules += tcpVipRules(CHAIN_TCP, cond)
            }
        }
        return rules
    }

    private fun dnsRules(chain: String, ownerCond: String): List<String> = listOf(
        "-A $chain $ownerCond -p udp --dport 53 -j REDIRECT --to-ports $dnsPort",
        "-A $chain $ownerCond -p tcp --dport 53 -j REDIRECT --to-ports $dnsTcpPort",
    )

    private fun tcpVipRules(chain: String, ownerCond: String): List<String> =
        (vipStart..vipEnd).map { tcpVipRule(chain, ownerCond, it) }

    /** filter 表规则体（UDP 黑洞）。 */
    private fun filterRules(): List<String> {
        val rules = mutableListOf<String>()
        rules += "-A OUTPUT -j $CHAIN_UDP_DROP"
        when (mode) {
            ScopeMode.ALL_APPS -> rules += udpDropRule(CHAIN_UDP_DROP, ownerCond())
            ScopeMode.SELECTED -> for (uid in uids) {
                val chain = uidChain(CHAIN_UDP_DROP, uid)
                rules += "-A $CHAIN_UDP_DROP ${selectJumpCond(uid)} -j $chain"
                rules += udpDropRule(chain, "")
            }
            ScopeMode.EXCLUDED -> rules += udpDropRule(CHAIN_UDP_DROP, ownerCond())
        }
        return rules
    }

    private fun udpDropRule(chain: String, ownerCond: String): String =
        "-A $chain $ownerCond -d $vipSubnet -p udp --dport 443 -j DROP"

    /** 自有 chain 定义行（`-N` 在 restore 中 = `:CHAIN - [0:0]`）。 */
    private fun chainDefs(): List<String> {
        val defs = mutableListOf(":$CHAIN_DNS - [0:0]", ":$CHAIN_TCP - [0:0]")
        if (mode == ScopeMode.SELECTED) {
            for (uid in uids) {
                defs += ":${uidChain(CHAIN_DNS, uid)} - [0:0]"
                defs += ":${uidChain(CHAIN_TCP, uid)} - [0:0]"
            }
        }
        return defs
    }

    // ---------- 对外 API ----------

    /**
     * 安装脚本：`*nat` / `*filter` 两表，各含 `:OUTPUT ACCEPT` + 自有 chain 定义 +
     * OUTPUT jump + 具体规则 + COMMIT。由安装方以 `iptables-restore --noflush` 原子安装。
     */
    fun buildInstallScript(): String {
        val sb = StringBuilder()
        sb.appendLine("*nat")
        sb.appendLine(":OUTPUT ACCEPT [0:0]")
        chainDefs().forEach { sb.appendLine(it) }
        natRules().forEach { sb.appendLine(it) }
        sb.appendLine("COMMIT")
        sb.appendLine("*filter")
        sb.appendLine(":OUTPUT ACCEPT [0:0]")
        sb.appendLine(":$CHAIN_UDP_DROP - [0:0]")
        if (mode == ScopeMode.SELECTED) {
            uids.forEach { sb.appendLine(":${uidChain(CHAIN_UDP_DROP, it)} - [0:0]") }
        }
        filterRules().forEach { sb.appendLine(it) }
        sb.appendLine("COMMIT")
        return sb.toString().trimEnd()
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
        return cmds
    }

    /** 本规则集拥有的 chain 名（nat, filter），cleanup 与残留清扫共用。 */
    fun ownedChainNames(): Pair<List<String>, List<String>> {
        val nat = mutableListOf(CHAIN_DNS, CHAIN_TCP)
        val filter = mutableListOf(CHAIN_UDP_DROP)
        if (mode == ScopeMode.SELECTED) {
            for (uid in uids) {
                nat += uidChain(CHAIN_DNS, uid)
                nat += uidChain(CHAIN_TCP, uid)
                filter += uidChain(CHAIN_UDP_DROP, uid)
            }
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
            }
            ScopeMode.SELECTED -> {
                if (uids.isEmpty()) return markers // 空 SELECTED：仅 OUTPUT jump 标记
                val uid = uids.first()
                val dnsChain = uidChain(CHAIN_DNS, uid)
                val tcpChain = uidChain(CHAIN_TCP, uid)
                val dropChain = uidChain(CHAIN_UDP_DROP, uid)
                markers += "-A $CHAIN_TCP ${selectJumpCond(uid)} -j $tcpChain"
                markers += tcpVipRule(tcpChain, "", vipStart)
                markers += tcpVipRule(tcpChain, "", vipEnd)
                markers += dnsRules(dnsChain, "")
                markers += udpDropRule(dropChain, "")
            }
            ScopeMode.EXCLUDED -> {
                val cond = ownerCond()
                markers += tcpVipRule(CHAIN_TCP, cond, vipStart)
                markers += tcpVipRule(CHAIN_TCP, cond, vipEnd)
                markers += dnsRules(CHAIN_DNS, cond)
                markers += udpDropRule(CHAIN_UDP_DROP, cond)
            }
        }
        return markers
    }

    companion object {
        const val MAX_EXCLUDED_UIDS = 8
        const val CHAIN_DNS = "GHD_DNS"
        const val CHAIN_TCP = "GHD_TCP"
        const val CHAIN_UDP_DROP = "GHD_UDP_DROP"

        fun uidChain(base: String, uid: Int): String = "${base}_UID_$uid"
    }
}

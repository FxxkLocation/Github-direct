package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * FirewallRules 纯字符串生成测试（重点：三种 scope 的安装脚本结构、owner 匹配拼写、
 * REDIRECT 端口映射、filter 表 UDP 黑洞、清理命令幂等序列、EXCLUDED 上限）。
 */
class FirewallRulesTest {

    private val SELF = 10123

    private fun allApps(): FirewallRules = FirewallRules(selfUid = SELF)

    // ---------- ALL_APPS：安装脚本结构 ----------

    @Test
    fun `ALL_APPS 安装脚本含 nat 与 filter 两表及 COMMIT`() {
        val script = allApps().buildInstallScript()
        assertTrue("应含 *nat", script.contains("*nat"))
        assertTrue("应含 *filter", script.contains("*filter"))
        assertEquals("两个 COMMIT（nat + filter）", 2, script.lines().count { it == "COMMIT" })
        assertFalse("增量 restore 不得改写设备 OUTPUT policy", script.contains(":OUTPUT "))
        assertTrue(script.contains(":GHD_DNS - [0:0]"))
        assertTrue(script.contains(":GHD_TCP - [0:0]"))
        assertTrue(script.contains(":GHD_UDP_DROP - [0:0]"))
    }

    @Test
    fun `ALL_APPS OUTPUT jump 到三个自有 chain`() {
        val script = allApps().buildInstallScript()
        assertTrue(script.contains("-A OUTPUT -j GHD_DNS"))
        assertTrue(script.contains("-A OUTPUT -j GHD_TCP"))
        assertTrue(script.contains("-A OUTPUT -j GHD_UDP_DROP"))
    }

    @Test
    fun `owner 匹配拼写为感叹号空格双横线 uid-owner`() {
        val script = allApps().buildInstallScript()
        assertTrue("应含 -m owner ! --uid-owner", script.contains("-m owner ! --uid-owner $SELF"))
        // REDIRECT 规则不应把 self 当作正向 uid 匹配（唯一匹配形式是反向排除）
        assertFalse(script.contains("-m owner --uid-owner $SELF"))
    }

    @Test
    fun `ALL_APPS 245 条 TCP REDIRECT 且端口随 vIP 递增`() {
        val script = allApps().buildInstallScript()
        val redirects = script.lines().filter { it.startsWith("-A GHD_TCP ") && it.contains("-j REDIRECT") }
        assertEquals(245, redirects.size)
        assertTrue("首个 vIP 10 → 7010", script.contains("-d 10.0.0.10/32 -p tcp --dport 443 -j REDIRECT --to-ports 7010"))
        assertTrue("vIP 100 → 7100", script.contains("-d 10.0.0.100/32 -p tcp --dport 443 -j REDIRECT --to-ports 7100"))
        assertTrue("末个 vIP 254 → 7254", script.contains("-d 10.0.0.254/32 -p tcp --dport 443 -j REDIRECT --to-ports 7254"))
        // 全部带自身 UID 排除
        assertTrue(redirects.all { it.contains("! --uid-owner $SELF") })
    }

    @Test
    fun `DNS 规则重定向到 5354 与 5355`() {
        val script = allApps().buildInstallScript()
        assertTrue(script.contains("-A GHD_DNS -m owner ! --uid-owner $SELF -p udp --dport 53 -j REDIRECT --to-ports 5354"))
        assertTrue(script.contains("-A GHD_DNS -m owner ! --uid-owner $SELF -p tcp --dport 53 -j REDIRECT --to-ports 5355"))
    }

    @Test
    fun `UDP 黑洞在 filter 表且带 vIP 网段匹配`() {
        val script = allApps().buildInstallScript()
        val dropLine = "-A GHD_UDP_DROP -m owner ! --uid-owner $SELF -d 10.0.0.0/24 -p udp --dport 443 -j DROP"
        assertTrue(script.contains(dropLine))
        val filterIdx = script.indexOf("*filter")
        val dropIdx = script.indexOf(dropLine)
        assertTrue("UDP DROP 应在 filter 段", filterIdx > 0 && dropIdx > filterIdx)
        // filter 段必须定义 GHD_UDP_DROP chain（restore 中 -A 引用前需 :CHAIN 行）
        assertTrue(script.contains(":${FirewallRules.CHAIN_UDP_DROP} - [0:0]"))
    }

    // ---------- SELECTED：每 UID 入口 + 共享载荷链 ----------

    private fun selected(vararg uids: Int): FirewallRules =
        FirewallRules(selfUid = SELF, scopeUids = uids.toSet(), scopeInclude = true)

    @Test
    fun `SELECTED 每 UID 一条入口且载荷链只生成一次`() {
        val script = selected(1001, 2002).buildInstallScript()
        assertFalse("空 owner 条件不得产生双空格，避免 iptables -S 校验误判", script.lines().any { "  " in it })
        assertEquals(1, script.lines().count { it == ":GHD_TCP_SEL - [0:0]" })
        assertEquals(1, script.lines().count { it == ":GHD_DNS_SEL - [0:0]" })
        assertEquals(1, script.lines().count { it == ":GHD_UDP_SEL - [0:0]" })
        assertFalse("不再按 UID 创建载荷链", script.contains("_UID_"))
        // jump 规则：自身排除 + uid 正向匹配，两个 UID 指向同一共享链。
        assertTrue(script.contains("-A GHD_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -j GHD_TCP_SEL"))
        assertTrue(script.contains("-A GHD_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 2002 -j GHD_TCP_SEL"))
        // 共享载荷链内 245 条规则不带 owner；owner 已由父链入口完成匹配。
        val payloadRules = script.lines().filter { it.startsWith("-A GHD_TCP_SEL ") }
        assertEquals(245, payloadRules.size)
        assertTrue(payloadRules.all { !it.contains("--uid-owner") })
        assertTrue(payloadRules.first().contains("--to-ports 7010"))
    }

    @Test
    fun `SELECTED 空集合 = 拦截零应用（仅保留 OUTPUT jump，无 REDIRECT 规则）`() {
        val script = selected().buildInstallScript()
        assertTrue(script.contains("-A OUTPUT -j GHD_TCP"))
        assertFalse(script.contains("-j REDIRECT"))
        assertFalse(script.contains("GHD_TCP_SEL"))
    }

    @Test
    fun `SELECTED 自动剔除自身 UID`() {
        val script = selected(SELF, 1001).buildInstallScript()
        assertFalse("自身 UID 不应成为正向入口", script.contains("-m owner --uid-owner $SELF"))
        assertTrue(script.contains("-m owner --uid-owner 1001 -j GHD_TCP_SEL"))
    }

    @Test
    fun `SELECTED 规则规模为 UID 加载荷而非两者乘积`() {
        val oneUid = selected(20_000).buildInstallScript()
        val hundredUids = selected(*(20_000 until 20_100).toList().toIntArray()).buildInstallScript()
        val lines = hundredUids.lines()

        assertEquals(100, lines.count { it.startsWith("-A GHD_TCP ") && it.endsWith("-j GHD_TCP_SEL") })
        assertEquals(245, lines.count { it.startsWith("-A GHD_TCP_SEL ") && it.contains("-j REDIRECT") })
        assertEquals("每新增 UID 仅增加 DNS/TCP/UDP 三条入口", 99 * 3, lines.size - oneUid.lines().size)
        assertFalse(hundredUids.contains("_UID_"))
    }

    @Test
    fun `Electron-like宿主仅在共享目标链之后捕获全部IPv4 TLS并迫使QUIC回退`() {
        val rules = FirewallRules(
            selfUid = SELF,
            scopeUids = setOf(1001, 2002),
            scopeInclude = true,
            fullTlsCaptureUids = setOf(1001, 9999), // 9999 不在普通 scope，必须被剔除
            enableRealIpRedirect = true,
            rejectUdp443 = true,
        )
        val script = rules.buildInstallScript()
        val targetJump = "-A GHD_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -j GHD_TCP_SEL"
        val catchAll = "-A GHD_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -p tcp --dport 443 -j REDIRECT --to-ports 7443"
        val quicFallback = "-A GHD_UDP_DROP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable"

        assertTrue(rules.usesRealIpRedirect())
        assertEquals(1, rules.fullTlsCaptureUidCount())
        assertTrue(script.indexOf(targetJump) in 0 until script.indexOf(catchAll))
        assertTrue(script.contains(quicFallback))
        assertFalse(script.contains("--uid-owner 2002 -p tcp --dport 443 -j REDIRECT --to-ports 7443"))
        assertFalse(script.contains("--uid-owner 9999"))
        assertEquals(245, script.lines().count { it.startsWith("-A GHD_TCP_SEL ") && it.contains("-j REDIRECT") })
        assertTrue(rules.expectedMarkers().all(script::contains))
        assertEquals("IPv6 不做无边界全捕获，保留原生双栈直连", "", rules.buildIpv6InstallScript())
    }

    @Test
    fun `关闭真实IP重定向时忽略Electron-like全TLS授权`() {
        val rules = FirewallRules(
            selfUid = SELF,
            scopeUids = setOf(1001),
            scopeInclude = true,
            fullTlsCaptureUids = setOf(1001),
            enableRealIpRedirect = false,
        )
        assertEquals(0, rules.fullTlsCaptureUidCount())
        assertFalse(rules.usesRealIpRedirect())
        assertFalse(rules.buildInstallScript().contains("--to-ports 7443"))
    }

    @Test
    fun `IPv6能力可用时Electron-like全TLS与QUIC回退保持双栈对称`() {
        val rules = FirewallRules(
            selfUid = SELF,
            scopeUids = setOf(1001, 2002),
            scopeInclude = true,
            fullTlsCaptureUids = setOf(1001, 9999),
            enableRealIpRedirect = true,
            enableIpv6Redirect = true,
            rejectIpv6Udp443 = true,
        )
        val ipv4 = rules.buildInstallScript()
        val ipv6 = rules.buildIpv6InstallScript()
        val targetJump =
            "-A GHD_6_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -j GHD_6_TCP_SEL"
        val catchAll =
            "-A GHD_6_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -p tcp --dport 443 -j REDIRECT --to-ports 7443"
        val quicFallback =
            "-A GHD_6_UDP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable"

        assertTrue(rules.usesIpv6RealIpRedirect())
        assertEquals(0, rules.directIpv6DestinationCount())
        assertTrue(ipv6.indexOf(targetJump) in 0 until ipv6.indexOf(catchAll))
        assertTrue(ipv6.contains(quicFallback))
        assertFalse(ipv6.contains("--uid-owner 2002 -p tcp --dport 443 -j REDIRECT --to-ports 7443"))
        assertFalse(ipv6.contains("--uid-owner 9999"))
        assertTrue(rules.expectedMarkers().all { (ipv4 + "\n" + ipv6).contains(it) })
        assertTrue(rules.verificationCommands().contains("ip6tables -t nat -S GHD_6_TCP"))
        assertTrue(rules.buildCleanupCommands().contains("ip6tables -t nat -D OUTPUT -j GHD_6_TCP"))
    }

    // ---------- EXCLUDED：叠加排除 ----------

    private fun excluded(vararg uids: Int): FirewallRules =
        FirewallRules(selfUid = SELF, scopeUids = uids.toSet(), scopeInclude = false)

    @Test
    fun `EXCLUDED 单链 245 条且多 owner 排除可叠加`() {
        val script = excluded(1001, 2002).buildInstallScript()
        val redirects = script.lines().filter { it.startsWith("-A GHD_TCP ") && it.contains("-j REDIRECT") }
        assertEquals(245, redirects.size)
        val sample = redirects.first()
        assertTrue(sample.contains("! --uid-owner $SELF"))
        assertTrue(sample.contains("! --uid-owner 1001"))
        assertTrue(sample.contains("! --uid-owner 2002"))
        assertFalse("EXCLUDED 不应有 SELECTED 载荷链", script.contains("GHD_TCP_SEL"))
        // DNS 规则同样叠加排除
        assertTrue(script.contains("-A GHD_DNS -m owner ! --uid-owner $SELF -m owner ! --uid-owner 1001 -m owner ! --uid-owner 2002 -p udp --dport 53"))
        // UDP 黑洞同样叠加排除
        assertTrue(script.contains("-A GHD_UDP_DROP -m owner ! --uid-owner $SELF -m owner ! --uid-owner 1001 -m owner ! --uid-owner 2002 -d 10.0.0.0/24"))
    }

    @Test
    fun `EXCLUDED 超过 8 个 UID 抛异常`() {
        try {
            excluded(1, 2, 3, 4, 5, 6, 7, 8, 9)
            fail("应抛 IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // 预期
        }
        // 8 个是上限，允许
        excluded(1, 2, 3, 4, 5, 6, 7, 8).buildInstallScript()
    }

    // ---------- 清理命令 ----------

    @Test
    fun `清理命令序列 删jump 再 flush 再 删chain`() {
        val cmds = allApps().buildCleanupCommands()
        val text = cmds.joinToString("\n")
        assertTrue(text.contains("iptables -t nat -D OUTPUT -j GHD_DNS"))
        assertTrue(text.contains("iptables -t nat -D OUTPUT -j GHD_TCP"))
        assertTrue(text.contains("iptables -t filter -D OUTPUT -j GHD_UDP_DROP"))
        assertTrue(text.contains("iptables -t nat -F GHD_DNS"))
        assertTrue(text.contains("iptables -t nat -F GHD_TCP"))
        assertTrue(text.contains("iptables -t filter -F GHD_UDP_DROP"))
        assertTrue(text.contains("iptables -t nat -X GHD_DNS"))
        assertTrue(text.contains("iptables -t nat -X GHD_TCP"))
        assertTrue(text.contains("iptables -t filter -X GHD_UDP_DROP"))
        // 顺序：所有 -D 在 -F 前，所有 -F 在 -X 前（先删引用再删除）
        val firstX = cmds.indexOfFirst { it.contains(" -X ") }
        val lastF = cmds.indexOfLast { it.contains(" -F ") }
        val firstF = cmds.indexOfFirst { it.contains(" -F ") }
        val lastD = cmds.indexOfLast { it.contains(" -D ") }
        assertTrue(firstF > lastD)
        assertTrue(firstX > lastF)
    }

    @Test
    fun `SELECTED 清理命令含共享载荷链 flush 与 delete`() {
        val cmds = selected(1001).buildCleanupCommands()
        val text = cmds.joinToString("\n")
        assertTrue(text.contains("iptables -t nat -F GHD_TCP_SEL"))
        assertTrue(text.contains("iptables -t nat -X GHD_TCP_SEL"))
        assertTrue(text.contains("iptables -t nat -F GHD_DNS_SEL"))
        assertTrue(text.contains("iptables -t filter -F GHD_UDP_SEL"))
        assertTrue(text.contains("iptables -t filter -X GHD_UDP_SEL"))
        // 共享载荷链没有直接 OUTPUT jump（jump 只对主链）。
        assertFalse(text.contains("-D OUTPUT -j GHD_TCP_SEL"))
    }

    // ---------- 校验特征行 ----------

    @Test
    fun `expectedMarkers 全部为安装脚本中的原样行（verify 可用性不变式）`() {
        for (rules in listOf(allApps(), selected(1001, 2002), excluded(1001, 2002))) {
            val script = rules.buildInstallScript()
            val markers = rules.expectedMarkers()
            assertTrue("markers 应能匹配安装脚本（${markers.size} 条）", markers.all { script.contains(it) })
        }
    }

    @Test
    fun `expectedMarkers 覆盖 jump DNS 首尾 REDIRECT 与黑洞行`() {
        val markers = allApps().expectedMarkers()
        val text = markers.joinToString("\n")
        assertTrue(text.contains("-A OUTPUT -j GHD_DNS"))
        assertTrue(text.contains("-A OUTPUT -j GHD_TCP"))
        assertTrue(text.contains("-A OUTPUT -j GHD_UDP_DROP"))
        assertTrue(text.contains("--to-ports 7010"))
        assertTrue(text.contains("--to-ports 7254"))
        assertTrue(text.contains("--to-ports 5354"))
        assertTrue(text.contains("--to-ports 5355"))
        assertTrue(text.contains("-j DROP"))
    }

    @Test
    fun `校验命令只查询OUTPUT与实际使用的自有链`() {
        val rules = selected(1001, 2002)
        val commands = rules.verificationCommands()
        val text = commands.joinToString("\n")
        assertTrue(text.contains("iptables -t nat -S OUTPUT"))
        assertTrue(text.contains("iptables -t filter -S OUTPUT"))
        assertTrue(text.contains("iptables -t nat -S GHD_TCP_SEL"))
        assertTrue(text.contains("iptables -t filter -S GHD_UDP_SEL"))
        assertFalse(text.contains("_UID_"))
        assertFalse(text.contains("iptables-save"))
    }

    @Test
    fun `真实GitHub目标内联重定向且QUIC优先REJECT`() {
        val rules = FirewallRules(
            selfUid = SELF,
            directDestinations = setOf("140.82.112.0/20", "199.59.148.9/32", "2606:50c0::/32", "bad"),
            enableRealIpRedirect = true,
            rejectUdp443 = true,
            generation = 42,
        )
        val script = rules.buildInstallScript()
        assertTrue(rules.usesRealIpRedirect())
        assertFalse(rules.usesIpSet())
        assertEquals(2, rules.directDestinationCount())
        assertEquals(42, rules.generation)
        assertTrue(script.contains("-d 140.82.112.0/20 -p tcp --dport 443 -j REDIRECT --to-ports 7443"))
        assertTrue(script.contains("-d 199.59.148.9/32 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable"))
        assertFalse("IPv6 不得误塞进 iptables v4 脚本", script.contains("2606:50c0"))
    }

    @Test
    fun `IPv6真实目标使用独立restore并保持scope与QUIC语义`() {
        val rules = FirewallRules(
            selfUid = SELF,
            scopeUids = setOf(1001),
            scopeInclude = true,
            directDestinations = setOf("140.82.112.0/20", "2606:50c0::/32", "2a0a:a440::/29"),
            enableRealIpRedirect = true,
            enableIpv6Redirect = true,
            rejectIpv6Udp443 = true,
        )

        val ipv4 = rules.buildInstallScript()
        val ipv6 = rules.buildIpv6InstallScript()
        assertEquals(2, rules.directIpv6DestinationCount())
        assertTrue(rules.usesIpv6RealIpRedirect())
        assertFalse("IPv6 CIDR 不得进入 iptables-restore", ipv4.contains("2606:50c0"))
        assertTrue(ipv6.contains(":GHD_6_TCP - [0:0]"))
        assertTrue(ipv6.contains(":GHD_6_TCP_SEL - [0:0]"))
        assertTrue(
            ipv6.contains(
                "-A GHD_6_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -j GHD_6_TCP_SEL",
            ),
        )
        assertTrue(ipv6.contains("-d 2606:50c0::/32 -p tcp --dport 443 -j REDIRECT --to-ports 7443"))
        assertTrue(ipv6.contains("-j REJECT --reject-with icmp6-port-unreachable"))
        assertTrue(rules.expectedMarkers().all { (ipv4 + "\n" + ipv6).contains(it) })
        assertTrue(rules.verificationCommands().any { it == "ip6tables -t nat -S GHD_6_TCP" })
        assertTrue(rules.buildCleanupCommands().any { it == "ip6tables -t nat -D OUTPUT -j GHD_6_TCP" })
    }

    @Test
    fun `NAT64在无ip6tables设备上以所选UID和动态AAAA做策略回落`() {
        val rules = FirewallRules(
            selfUid = SELF,
            scopeUids = setOf(10311, 10312),
            scopeInclude = true,
            directDestinations = setOf("104.18.41.241/32", "172.64.146.15/32"),
            enableRealIpRedirect = true,
            nat64Ipv6FallbackDestinations = setOf(
                "2606:4700:4400::6812:29f1/128",
                "2a06:98c1:310c::ac40:920f/128",
                "2607:f8b0:4007:80e::2004/64", // 非精确地址不得进入回落表
            ),
            enableIpv6UidPolicyFallback = true,
        )

        assertTrue(rules.usesNat64Ipv6Fallback())
        assertEquals(2, rules.nat64Ipv6FallbackDestinationCount())
        assertEquals("", rules.buildIpv6InstallScript())
        val install = rules.buildNat64Ipv6FallbackInstallCommands()
        val text = install.joinToString("\n")
        assertTrue(text.contains("ip -6 route add unreachable 2606:4700:4400::6812:29f1/128 table 52123"))
        assertTrue(text.contains("ip -6 route add unreachable 2a06:98c1:310c::ac40:920f/128 table 52123"))
        assertTrue(text.contains("priority 10500 uidrange 10311-10311 lookup 52123"))
        assertTrue(text.contains("priority 10501 uidrange 10312-10312 lookup 52123"))
        assertTrue(install.indexOfFirst { "route add" in it } < install.indexOfFirst { "rule add" in it })
        assertFalse(text.contains("2607:f8b0"))
        assertTrue(rules.verificationCommands().contains("ip -6 route show table 52123"))
        assertTrue(rules.expectedMarkers().contains("uidrange 10311-10311 lookup 52123"))
        assertTrue(rules.expectedMarkers().contains("unreachable 2606:4700:4400::6812:29f1"))
        assertEquals(
            FirewallRules.MAX_IPV6_POLICY_UIDS,
            rules.buildNat64Ipv6FallbackCleanupCommands().count {
                it.startsWith("ip -6 rule del priority ") && it.endsWith(" table 52123")
            },
        )
        assertTrue(rules.buildCleanupCommands().contains("ip -6 route flush table 52123"))
    }

    @Test
    fun `NAT64策略回落拒绝ALL和EXCLUDED作用域`() {
        fun rules(scope: Set<Int>?, include: Boolean) = FirewallRules(
            selfUid = SELF,
            scopeUids = scope,
            scopeInclude = include,
            directDestinations = setOf("104.18.41.241/32"),
            enableRealIpRedirect = true,
            nat64Ipv6FallbackDestinations = setOf("2606:4700:4400::6812:29f1/128"),
            enableIpv6UidPolicyFallback = true,
        )

        assertFalse(rules(null, true).usesNat64Ipv6Fallback())
        assertFalse(rules(setOf(10311), false).usesNat64Ipv6Fallback())
    }

    @Test
    fun `ipset模式使用固定集合原子swap与20秒租约`() {
        val rules = FirewallRules(
            selfUid = SELF,
            directDestinations = setOf("140.82.112.0/20", "199.59.148.9/32"),
            enableRealIpRedirect = true,
            useIpSet = true,
        )
        assertTrue(rules.usesIpSet())
        val script = rules.buildInstallScript()
        assertTrue(script.contains("-m set --match-set GHD_DST dst -p tcp --dport 443"))
        val install = rules.buildIpSetInstallCommands().joinToString("\n")
        assertTrue(install.contains("hash:net family inet timeout 20"))
        assertTrue(install.contains("ipset swap GHD_DST_NEXT GHD_DST"))
        assertEquals(2, rules.buildIpSetLeaseRefreshCommands().size)

        val fallback = rules.withoutIpSet()
        assertFalse(fallback.usesIpSet())
        assertTrue(fallback.buildInstallScript().contains("-d 140.82.112.0/20"))
    }

    @Test
    fun `IPv6 ipset使用inet6独立集合并参与租约刷新`() {
        val rules = FirewallRules(
            selfUid = SELF,
            directDestinations = setOf("2606:50c0::/32"),
            enableRealIpRedirect = true,
            enableIpv6Redirect = true,
            useIpSet = true,
        )

        assertTrue(rules.usesIpSet())
        assertTrue(rules.buildIpv6InstallScript().contains("--match-set GHD_DST6 dst"))
        val install = rules.buildIpSetInstallCommands().joinToString("\n")
        assertTrue(install.contains("GHD_DST6 hash:net family inet6 timeout 20"))
        assertTrue(install.contains("ipset swap GHD_DST6_NEXT GHD_DST6"))
        assertEquals(
            listOf("ipset add GHD_DST6 2606:50c0::/32 timeout 20 -exist"),
            rules.buildIpSetLeaseRefreshCommands(),
        )
        val fallback = rules.withoutIpSet()
        assertFalse(fallback.usesIpSet())
        assertTrue(fallback.buildIpv6InstallScript().contains("-d 2606:50c0::/32"))
    }

    @Test
    fun `无ipset时真实目标有128条硬上限`() {
        val destinations = (0 until 200).map { "11.0.${it / 256}.${it % 256}/32" }.toSet()
        val rules = FirewallRules(
            selfUid = SELF,
            directDestinations = destinations,
            enableRealIpRedirect = true,
        )
        assertEquals(FirewallRules.MAX_INLINE_DESTINATIONS, rules.directDestinationCount())
    }

    @Test
    fun `restore 脚本最后一个 COMMIT 保留换行以兼容 Android legacy parser`() {
        assertTrue(allApps().buildInstallScript().endsWith("COMMIT\n"))
        val ipv6 = FirewallRules(
            selfUid = SELF,
            directDestinations = setOf("2606:50c0::/32"),
            enableRealIpRedirect = true,
            enableIpv6Redirect = true,
        ).buildIpv6InstallScript()
        assertTrue(ipv6.endsWith("COMMIT\n"))
    }

    @Test
    fun `原位刷新重建自有链但不重复或摘除既有OUTPUT jump`() {
        val script = selected(1001, 2002).buildRefreshScript()

        assertTrue(script.contains(":GHD_DNS - [0:0]"))
        assertTrue(script.contains(":GHD_TCP_SEL - [0:0]"))
        assertTrue(script.contains("-A GHD_TCP_SEL "))
        assertFalse(script.contains("-A OUTPUT -j GHD_"))
        assertFalse(script.contains("-D OUTPUT -j GHD_"))
        assertFalse(script.contains(":OUTPUT "))
        assertTrue(script.endsWith("COMMIT\n"))
    }

    @Test
    fun `IPv6刷新按启用状态安装原位替换或原子摘除`() {
        val disabled = FirewallRules(selfUid = SELF)
        val oldEnabled = FirewallRules(
            selfUid = SELF,
            scopeUids = setOf(1001),
            directDestinations = setOf("2606:50c0::/32"),
            enableRealIpRedirect = true,
            enableIpv6Redirect = true,
        )
        val nextEnabled = FirewallRules(
            selfUid = SELF,
            directDestinations = setOf("2606:50c0::/32"),
            enableRealIpRedirect = true,
            enableIpv6Redirect = true,
        )

        val enable = nextEnabled.buildIpv6RefreshScript(disabled)
        assertTrue(enable.contains("-A OUTPUT -j GHD_6_TCP"))
        assertTrue(enable.contains("-A OUTPUT -j GHD_6_UDP"))

        val replace = nextEnabled.buildIpv6RefreshScript(oldEnabled)
        assertFalse(replace.contains("-A OUTPUT -j GHD_6_"))
        assertFalse(replace.contains("-D OUTPUT -j GHD_6_"))
        assertTrue(replace.contains("-A GHD_6_TCP "))

        val disable = disabled.buildIpv6RefreshScript(oldEnabled)
        assertTrue(disable.contains(":GHD_6_TCP - [0:0]"))
        assertTrue(disable.contains(":GHD_6_TCP_SEL - [0:0]"))
        assertTrue(disable.contains("-D OUTPUT -j GHD_6_TCP"))
        assertTrue(disable.contains("-D OUTPUT -j GHD_6_UDP"))
        assertFalse(disable.contains("-A OUTPUT -j GHD_6_"))
    }

    @Test
    fun `刷新后只清理新代次不再引用的子链IPv6链和集合`() {
        val previous = FirewallRules(
            selfUid = SELF,
            scopeUids = setOf(1001),
            directDestinations = setOf("140.82.112.0/20", "2606:50c0::/32"),
            enableRealIpRedirect = true,
            enableIpv6Redirect = true,
            useIpSet = true,
        )
        val next = FirewallRules(
            selfUid = SELF,
            directDestinations = setOf("140.82.112.0/20"),
            enableRealIpRedirect = true,
            useIpSet = false,
        )

        val cleanup = previous.buildPostRefreshCleanupCommands(next)
        assertTrue(cleanup.contains("iptables -t nat -X GHD_TCP_SEL"))
        assertTrue(cleanup.contains("iptables -t filter -X GHD_UDP_SEL"))
        assertTrue(cleanup.contains("ip6tables -t nat -D OUTPUT -j GHD_6_TCP"))
        assertTrue(cleanup.contains("ip6tables -t nat -X GHD_6_TCP"))
        assertTrue(cleanup.contains("ipset destroy GHD_DST"))
        assertTrue(cleanup.contains("ipset destroy GHD_DST6"))
        assertFalse(cleanup.contains("iptables -t nat -X GHD_TCP"))
    }

    // ---------- 参数校验 ----------

    @Test
    fun `非法参数拒绝`() {
        try {
            FirewallRules(selfUid = 0)
            fail("selfUid=0 应拒绝")
        } catch (e: IllegalArgumentException) {
        }
        try {
            FirewallRules(selfUid = SELF, vipStart = 5, vipEnd = 3)
            fail("vipStart>vipEnd 应拒绝")
        } catch (e: IllegalArgumentException) {
        }
        try {
            FirewallRules(selfUid = SELF, vipSubnet = "10.0.0.0/16")
            fail("非 /24 网段应拒绝")
        } catch (e: IllegalArgumentException) {
        }
    }
}

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
        assertTrue(script.contains(":OUTPUT ACCEPT [0:0]"))
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

    // ---------- SELECTED：per-UID 子链 ----------

    private fun selected(vararg uids: Int): FirewallRules =
        FirewallRules(selfUid = SELF, scopeUids = uids.toSet(), scopeInclude = true)

    @Test
    fun `SELECTED 每 UID 一子链且子链内无 owner 匹配`() {
        val script = selected(1001, 2002).buildInstallScript()
        assertTrue(script.contains(":GHD_TCP_UID_1001 - [0:0]"))
        assertTrue(script.contains(":GHD_TCP_UID_2002 - [0:0]"))
        assertTrue(script.contains(":GHD_DNS_UID_1001 - [0:0]"))
        // jump 规则：自身排除 + uid 正向匹配
        assertTrue(script.contains("-A GHD_TCP -m owner ! --uid-owner $SELF -m owner --uid-owner 1001 -j GHD_TCP_UID_1001"))
        // 子链内 245 条规则不带 owner 匹配
        val subRules = script.lines().filter { it.startsWith("-A GHD_TCP_UID_1001 ") }
        assertEquals(245, subRules.size)
        assertTrue(subRules.all { !it.contains("--uid-owner") })
        assertTrue(subRules.first().contains("--to-ports 7010"))
    }

    @Test
    fun `SELECTED 空集合 = 拦截零应用（仅保留 OUTPUT jump，无 REDIRECT 规则）`() {
        val script = selected().buildInstallScript()
        assertTrue(script.contains("-A OUTPUT -j GHD_TCP"))
        assertFalse(script.contains("-j REDIRECT"))
        assertFalse(script.contains("GHD_TCP_UID_"))
    }

    @Test
    fun `SELECTED 自动剔除自身 UID`() {
        val script = selected(SELF, 1001).buildInstallScript()
        assertFalse("自身 UID 不应出现在子链", script.contains("GHD_TCP_UID_$SELF"))
        assertTrue(script.contains("GHD_TCP_UID_1001"))
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
        assertFalse("EXCLUDED 不应有子链", script.contains("GHD_TCP_UID_"))
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
    fun `SELECTED 清理命令含子链 flush 与 delete`() {
        val cmds = selected(1001).buildCleanupCommands()
        val text = cmds.joinToString("\n")
        assertTrue(text.contains("iptables -t nat -F GHD_TCP_UID_1001"))
        assertTrue(text.contains("iptables -t nat -X GHD_TCP_UID_1001"))
        assertTrue(text.contains("iptables -t nat -F GHD_DNS_UID_1001"))
        assertTrue(text.contains("iptables -t filter -F GHD_UDP_DROP_UID_1001"))
        assertTrue(text.contains("iptables -t filter -X GHD_UDP_DROP_UID_1001"))
        // 子链没有直接 OUTPUT jump（jump 只对主链）
        assertFalse(text.contains("-D OUTPUT -j GHD_TCP_UID_1001"))
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

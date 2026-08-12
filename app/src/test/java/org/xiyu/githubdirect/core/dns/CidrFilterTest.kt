package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CidrFilterTest {

    private fun v4(a: Int, b: Int, c: Int, d: Int): ByteArray =
        byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())

    @Test
    fun `v4网段匹配`() {
        val filter = CidrFilter.parse(
            listOf("140.82.112.0/20", "20.205.243.0/24"),
            emptyList(),
        )
        assertTrue(filter.allowsIpv4(v4(140, 82, 112, 3)))    // 140.82.112.0/20 内
        assertTrue(filter.allowsIpv4(v4(140, 82, 127, 255)))  // 上边界
        assertFalse(filter.allowsIpv4(v4(140, 82, 128, 0)))   // 上边界外
        assertTrue(filter.allowsIpv4(v4(20, 205, 243, 100)))  // 20.205.243.0/24 内
        assertFalse(filter.allowsIpv4(v4(20, 205, 244, 100))) // 网段外
        assertFalse(filter.allowsIpv4(v4(8, 8, 8, 8)))
    }

    @Test
    fun `v6前缀匹配`() {
        val filter = CidrFilter.parse(emptyList(), listOf("2606:50c0::/32"))
        assertTrue(filter.allowsIpv6(IpAddresses.parseIpv6("2606:50c0:0:0:0:0:0:1")!!))
        assertTrue(filter.allowsIpv6(IpAddresses.parseIpv6("2606:50c0:ffff::")!!))
        assertFalse(filter.allowsIpv6(IpAddresses.parseIpv6("2606:50c1::")!!))
        assertFalse(filter.allowsIpv6(IpAddresses.parseIpv6("2606:50bf::")!!))
    }

    @Test
    fun `非32位v6前缀`() {
        val filter = CidrFilter.parse(emptyList(), listOf("2001:db8:abcd::/48"))
        assertTrue(filter.allowsIpv6(IpAddresses.parseIpv6("2001:db8:abcd:1::")!!))
        assertFalse(filter.allowsIpv6(IpAddresses.parseIpv6("2001:db8:abce::")!!))
    }

    @Test
    fun `空过滤器isEmpty且不匹配任何地址`() {
        val filter = CidrFilter.parse(emptyList(), emptyList())
        assertTrue(filter.isEmpty)
        assertFalse(filter.allowsIpv4(v4(1, 2, 3, 4)))
        assertFalse(filter.allowsIpv6(IpAddresses.parseIpv6("::1")!!))
    }

    @Test
    fun `非法CIDR条目被跳过`() {
        val filter = CidrFilter.parse(
            listOf("not-a-cidr", "140.82.112.0/99", "140.82.112.0"),
            listOf("zzz", "2606:50c0::/33"),
        )
        assertTrue(filter.allowsIpv4(v4(140, 82, 112, 0))) // 无掩码视为 /32
        assertFalse(filter.allowsIpv4(v4(140, 82, 112, 3)))
        assertTrue(filter.allowsIpv6(IpAddresses.parseIpv6("2606:50c0::1")!!))
    }

    @Test
    fun `解析器校验`() {
        val p = CidrFilter.parseV4Cidr("192.30.252.0/22")
        assertEquals(0xC01EFC00L, p!!.first) // 192.30.252.0 归一化
        assertEquals(22, p.second)
        assertNull(CidrFilter.parseV4Cidr("1.2.3"))
        assertNull(CidrFilter.parseV4Cidr("1.2.3.4/33"))
        assertNull(CidrFilter.parseV6Cidr("2606:50c0::/129"))
    }
}

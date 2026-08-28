package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpAddressesTest {

    @Test
    fun `ipv4解析`() {
        assertArrayEquals(byteArrayOf(140.toByte(), 82.toByte(), 112.toByte(), 3.toByte()),
            IpAddresses.parseIpv4("140.82.112.3"))
        assertNull(IpAddresses.parseIpv4("1.2.3"))
        assertNull(IpAddresses.parseIpv4("1.2.3.4.5"))
        assertNull(IpAddresses.parseIpv4("1.2.3.256"))
        assertNull(IpAddresses.parseIpv4(""))
        assertNull(IpAddresses.parseIpv4(null))
    }

    @Test
    fun `ipv6全展开解析`() {
        assertArrayEquals(
            byteArrayOf(0x26, 0x06, 0x50, 0xc0.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
            IpAddresses.parseIpv6("2606:50c0::1"))
        assertArrayEquals(
            byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
            IpAddresses.parseIpv6("2001:db8::1"))
        assertNull(IpAddresses.parseIpv6("2001:db8"))
        assertNull(IpAddresses.parseIpv6("gggg::1"))
        assertNull(IpAddresses.parseIpv6("1:2:3:4:5:6:7:8:9"))
    }

    @Test
    fun `内嵌ipv4解析`() {
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1),
            IpAddresses.parseIpv6("::127.0.0.1"))
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff.toByte(), 0xff.toByte(), 10, 0, 0, 1),
            IpAddresses.parseIpv6("::ffff:10.0.0.1"))
    }

    @Test
    fun `parseIpAddress分派v4和v6`() {
        assertEquals(4, IpAddresses.parseIpAddress("1.2.3.4")!!.size)
        assertEquals(16, IpAddresses.parseIpAddress("::1")!!.size)
        assertNull(IpAddresses.parseIpAddress("bad"))
    }

    @Test
    fun `字符串转换roundtrip`() {
        assertEquals("140.82.112.3", IpAddresses.ipv4ToString(IpAddresses.parseIpv4("140.82.112.3")!!))
        assertEquals("2606:50c0:0:0:0:0:0:1",
            IpAddresses.ipv6ToString(IpAddresses.parseIpv6("2606:50c0::1")!!))
        assertEquals("2001:db8:0:0:0:0:0:1",
            IpAddresses.ipv6ToString(IpAddresses.parseIpv6("2001:db8::1")!!))
    }

    @Test
    fun `污染与私网地址判定`() {
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("127.0.0.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("0.0.0.0")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("10.0.0.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("100.64.0.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("192.168.1.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("192.0.0.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("192.0.2.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("198.18.0.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("198.51.100.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("203.0.113.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("240.0.0.1")!!))
        assertFalse(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("140.82.112.3")!!))
        assertFalse(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("192.0.66.2")!!))
        assertFalse(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv4("8.8.8.8")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv6("::1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv6("::127.0.0.1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv6("2001:db8::1")!!))
        assertTrue(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv6("2001:20::1")!!))
        assertFalse(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv6("2001:1000::1")!!))
        assertFalse(IpAddresses.isBogonOrPoisoned(IpAddresses.parseIpv6("2606:50c0::1")!!))
    }

    @Test
    fun `int与数组互转`() {
        val a = IpAddresses.parseIpv4("10.0.0.53")!!
        val intVal = IpAddresses.ipToInt(a)
        assertArrayEquals(a, IpAddresses.intToIpv4(intVal))
        assertEquals(0x0A000035, intVal)
    }
}

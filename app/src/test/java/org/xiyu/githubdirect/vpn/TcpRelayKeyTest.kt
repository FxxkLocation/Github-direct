package org.xiyu.githubdirect.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * §49 回归：会话 key 必须含 IP 四元组。
 * 原实现仅 srcPort:dstPort，两个不同客户端源 IP（或不同 vIP）同端口对会碰撞、串数据。
 */
class TcpRelayKeyTest {

    private fun ip(a: Int, b: Int, c: Int, d: Int) = byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())

    @Test
    fun `同端口对不同源IP产生不同key`() {
        val k1 = TcpRelay.sessionKey(ip(1, 2, 3, 4), 12345, ip(10, 0, 0, 10), 443)
        val k2 = TcpRelay.sessionKey(ip(5, 6, 7, 8), 12345, ip(10, 0, 0, 10), 443)
        assertNotEquals(k1, k2)
    }

    @Test
    fun `同端口对不同目标IP产生不同key`() {
        val k1 = TcpRelay.sessionKey(ip(1, 2, 3, 4), 12345, ip(10, 0, 0, 10), 443)
        val k2 = TcpRelay.sessionKey(ip(1, 2, 3, 4), 12345, ip(10, 0, 0, 11), 443)
        assertNotEquals(k1, k2)
    }

    @Test
    fun `同一连接key稳定且格式为ip端口ip端口`() {
        val k1 = TcpRelay.sessionKey(ip(1, 2, 3, 4), 12345, ip(10, 0, 0, 10), 443)
        val k2 = TcpRelay.sessionKey(ip(1, 2, 3, 4), 12345, ip(10, 0, 0, 10), 443)
        assertEquals(k1, k2)
        assertEquals("1.2.3.4:12345:10.0.0.10:443", k1)
    }

    @Test
    fun `同IP对不同端口产生不同key`() {
        assertNotEquals(
            TcpRelay.sessionKey(ip(1, 2, 3, 4), 12345, ip(10, 0, 0, 10), 443),
            TcpRelay.sessionKey(ip(1, 2, 3, 4), 54321, ip(10, 0, 0, 10), 443),
        )
    }

    @Test
    fun `四元组中任一IP差异均产生不同key`() {
        val base = TcpRelay.sessionKey(ip(1, 2, 3, 4), 1111, ip(10, 0, 0, 1), 53)
        // 目标端口 53（DNS 中继：RouteTarget 指向明文 DNS IP）也参与 key
        assertNotEquals(base, TcpRelay.sessionKey(ip(1, 2, 3, 4), 1111, ip(10, 0, 0, 1), 54))
        assertNotEquals(base, TcpRelay.sessionKey(ip(1, 2, 3, 5), 1111, ip(10, 0, 0, 1), 53))
    }
}

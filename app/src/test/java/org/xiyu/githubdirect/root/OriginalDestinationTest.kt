package org.xiyu.githubdirect.root

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OriginalDestinationTest {
    @Test
    fun `解码IPv4原目的地址`() {
        val decoded = OriginalDestination.decode(
            byteArrayOf(4, 0x01, 0xbb.toByte(), 20, 205.toByte(), 243.toByte(), 166.toByte()),
        )!!
        assertEquals("20.205.243.166", decoded.address.hostAddress)
        assertEquals(443, decoded.port)
    }

    @Test
    fun `解码IPv6原目的地址`() {
        val address = byteArrayOf(
            0x26, 0x06, 0x50, 0xc0.toByte(), 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        )
        val decoded = OriginalDestination.decode(
            byteArrayOf(6, 0x01, 0xbb.toByte()) + address,
        )!!
        assertArrayEquals(address, decoded.address.address)
        assertEquals(443, decoded.port)
    }

    @Test
    fun `拒绝非法family和端口`() {
        assertNull(OriginalDestination.decode(byteArrayOf(9, 0, 80, 1, 2, 3, 4)))
        assertNull(OriginalDestination.decode(byteArrayOf(4, 0, 0, 1, 2, 3, 4)))
    }
}

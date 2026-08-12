package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RelayIpTableTest {

    @Test
    fun `update与lookup`() {
        val table = RelayIpTable()
        assertNull(table.lookup("github.com"))

        table.update(mapOf("github.com" to listOf("140.82.112.3", "140.82.113.4")))
        assertEquals(listOf("140.82.112.3", "140.82.113.4"), table.lookup("github.com"))
        assertNull(table.lookup("api.github.com"))
        assertEquals(1, table.size())
    }

    @Test
    fun `firstIpv4取第一个v4`() {
        val table = RelayIpTable()
        table.update(mapOf(
            "github.com" to listOf("140.82.112.3"),
            "v6only.com" to listOf("2606:50c0::1"),
        ))
        assertEquals("140.82.112.3", table.firstIpv4("github.com"))
        assertNull(table.firstIpv4("v6only.com")) // 只有 v6
        assertNull(table.firstIpv4("unknown.com"))
    }

    @Test
    fun `整体替换无并发残留`() {
        val table = RelayIpTable()
        table.update(mapOf("a.com" to listOf("1.1.1.1")))
        table.update(mapOf("b.com" to listOf("2.2.2.2")))
        // 整体替换：旧键消失
        assertNull(table.lookup("a.com"))
        assertEquals(listOf("2.2.2.2"), table.lookup("b.com"))
        assertEquals(mapOf("b.com" to listOf("2.2.2.2")), table.snapshot())
    }
}

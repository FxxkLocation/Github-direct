package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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
    fun `通配键按最长标签后缀匹配且精确键优先`() {
        val table = RelayIpTable()
        table.update(
            mapOf(
                "*.github.io" to listOf("185.199.108.153"),
                "*.pages.github.io" to listOf("185.199.109.153"),
                "special.pages.github.io" to listOf("185.199.110.153"),
            ),
        )
        assertEquals(listOf("185.199.108.153"), table.lookup("owner.github.io"))
        assertEquals(listOf("185.199.109.153"), table.lookup("docs.pages.github.io"))
        assertEquals(listOf("185.199.110.153"), table.lookup("special.pages.github.io"))
        assertNull(table.lookup("github.io"))
        assertNull(table.lookup("evilgithub.io"))
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

    @Test
    fun `严格解析短TTL结果仅覆盖精确域并与稳定候选合并`() {
        val table = RelayIpTable()
        table.update(
            mapOf(
                "*.googlevideo.com" to listOf("142.250.1.1"),
                "r1.googlevideo.com" to listOf("142.250.1.2"),
            ),
        )
        table.observeResolution(
            "R1.GoogleVideo.COM.",
            listOf("142.250.1.3", "2001:4860:4802:32::a"),
            ttlMs = 60_000,
            now = 10_000,
        )

        assertEquals(
            listOf("142.250.1.3", "2001:4860:4802:32:0:0:0:a", "142.250.1.2"),
            table.lookup("r1.googlevideo.com", now = 20_000),
        )
        assertEquals(
            listOf("142.250.1.1"),
            table.lookup("r2.googlevideo.com", now = 20_000),
        )
        assertEquals(listOf("142.250.1.2"), table.lookup("r1.googlevideo.com", now = 80_000))
    }

    @Test
    fun `短TTL结果拒绝私网污染并限制缓存规模`() {
        val table = RelayIpTable()
        table.observeResolution("bad.example", listOf("127.0.0.1", "10.0.0.1"), now = 1)
        assertNull(table.lookup("bad.example", now = 2))

        repeat(140) { index ->
            table.observeResolution(
                "h$index.example",
                listOf("142.250.${index / 200}.${(index % 200) + 1}"),
                ttlMs = 60_000L + index,
                now = 10_000,
            )
        }
        assertTrue(table.ephemeralSize() <= 128)
    }
}

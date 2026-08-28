package org.xiyu.githubdirect.core.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class GoogleIpRangesTest {

    @Test
    fun `goog json只接受公网规范前缀并按双栈归属匹配`() {
        val ranges = GoogleIpRangesParser.parse(
            """{
              "syncToken":"123",
              "creationTime":"2026-08-28T01:06:18Z",
              "prefixes":[
                {"ipv4Prefix":"142.250.0.0/15"},
                {"ipv6Prefix":"2607:f8b0::/32"},
                {"ipv4Prefix":"10.0.0.0/8"},
                {"ipv4Prefix":"142.250.1.1/15"},
                {"ipv4Prefix":"0.0.0.0/0"},
                {"ipv4Prefix":"142.250.0.0/15","ipv6Prefix":"2607:f8b0::/32"}
              ]
            }""",
        )
        assertNotNull(ranges)
        ranges!!
        assertEquals(setOf("142.250.0.0/15"), ranges.ipv4Cidrs)
        assertEquals(setOf("2607:f8b0::/32"), ranges.ipv6Cidrs)
        assertTrue(ranges.contains("142.251.12.119"))
        assertTrue(ranges.contains("2607:f8b0:4005:805::200e"))
        assertFalse(ranges.contains("104.244.42.197"))
        assertFalse(ranges.contains("120.253.255.107"))
    }

    @Test
    fun `空或损坏的官方地址文档保护性拒绝`() {
        assertNull(GoogleIpRangesParser.parse(null))
        assertNull(GoogleIpRangesParser.parse("{}"))
        assertNull(GoogleIpRangesParser.parse("{not-json"))
        assertNull(GoogleIpRangesParser.parse("""{"prefixes":[{"ipv4Prefix":"127.0.0.0/8"}]}"""))
    }

    @Test
    fun `内置保守快照覆盖当前经典Google前端而排除污染样本`() {
        val file = File("src/main/assets/routes/google_frontend_prefixes.json")
        assertTrue("bundled Google ownership snapshot missing", file.isFile)
        val ranges = GoogleIpRangesParser.parse(file.readText(Charsets.UTF_8))
            ?: error("bundled Google ownership snapshot is invalid")
        assertTrue(ranges.contains("142.250.4.119"))
        assertTrue(ranges.contains("142.251.12.119"))
        assertTrue(ranges.contains("2404:6800:4005:80a::200e"))
        assertFalse(ranges.contains("104.244.42.197"))
        assertFalse(ranges.contains("199.59.148.9"))
    }
}

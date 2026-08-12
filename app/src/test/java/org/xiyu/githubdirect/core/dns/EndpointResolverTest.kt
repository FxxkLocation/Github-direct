package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.test.FakeBinder

class EndpointResolverTest {

    /** 按 URL 中的服务器名返回不同响应。 */
    private fun multiServer(handlers: Map<String, (String) -> String?>): (String) -> String? {
        return { url ->
            var result: String? = null
            for ((marker, handler) in handlers) {
                if (url.contains(marker)) {
                    result = handler(url)
                    break
                }
            }
            result
        }
    }

    private val v4Json = """{"Status":0,"Answer":[{"type":1,"data":"140.82.112.3"}]}"""

    @Test
    fun `第一台服务器成功即返回`() {
        val resolver = EndpointResolver(
            FakeBinder { v4Json },
            servers = listOf("http://s1", "http://s2"),
        )
        val r = resolver.resolve("github.com", null)
        assertNotNull(r)
        assertEquals(1, r!!.v4.size)
        assertEquals("140.82.112.3", IpAddresses.ipv4ToString(r.v4[0]))
    }

    @Test
    fun `服务器失败自动回退下一台`() {
        var s1Calls = 0
        val resolver = EndpointResolver(
            FakeBinder { url ->
                if (url.contains("s1")) {
                    s1Calls++
                    null // s1 网络失败
                } else {
                    v4Json
                }
            },
            servers = listOf("http://s1", "http://s2"),
        )
        val r = resolver.resolve("github.com", null)
        assertNotNull(r)
        assertEquals(1, r!!.v4.size)
        assertTrue(s1Calls > 0)
    }

    @Test
    fun `全部服务器失败返回null`() {
        val resolver = EndpointResolver(
            FakeBinder { null },
            servers = listOf("http://s1", "http://s2"),
        )
        assertNull(resolver.resolve("github.com", null))
        assertNull(resolver.resolveType("github.com", 1, null))
    }

    @Test
    fun `CIDR过滤掉污染IP`() {
        val cidr = CidrFilter.parse(listOf("140.82.112.0/24"), emptyList())
        val resolver = EndpointResolver(
            FakeBinder { url ->
                if (url.contains("s2")) {
                    v4Json // s2 返回合法 GitHub IP
                } else {
                    """{"Status":0,"Answer":[{"type":1,"data":"8.8.8.8"}]}""" // s1 被污染
                }
            },
            servers = listOf("http://s1", "http://s2"),
        )
        val r = resolver.resolve("github.com", cidr)
        assertNotNull(r)
        assertEquals(1, r!!.v4.size)
        assertEquals("140.82.112.3", IpAddresses.ipv4ToString(r.v4[0]))
    }

    @Test
    fun `有响应但全被过滤返回空列表`() {
        val cidr = CidrFilter.parse(listOf("140.82.112.0/24"), emptyList())
        val resolver = EndpointResolver(
            FakeBinder { """{"Status":0,"Answer":[{"type":1,"data":"8.8.8.8"}]}""" },
            servers = listOf("http://s1"),
        )
        val list = resolver.resolveType("github.com", 1, cidr)
        assertNotNull("有响应 → 非 null", list)
        assertEquals(0, list!!.size) // 空 = 有响应但全部被过滤
    }

    @Test
    fun `resolveType只返回对应类型`() {
        val resolver = EndpointResolver(
            FakeBinder { url ->
                if (url.contains("type=AAAA")) {
                    """{"Status":0,"Answer":[{"type":28,"data":"2606:50c0::1"}]}"""
                } else {
                    v4Json
                }
            },
            servers = listOf("http://s1"),
        )
        val a = resolver.resolveType("github.com", 1, null)!!
        val aaaa = resolver.resolveType("github.com", 28, null)!!
        assertEquals(1, a.size)
        assertEquals(1, aaaa.size)
        assertEquals(16, aaaa[0].size)
    }

    @Test
    fun `DoH状态非0视为失败`() {
        val resolver = EndpointResolver(
            FakeBinder { """{"Status":3,"Answer":[]}""" },
            servers = listOf("http://s1"),
        )
        assertNull(resolver.resolveType("github.com", 1, null))
    }
}

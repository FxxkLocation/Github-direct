package org.xiyu.githubdirect.core.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsNamesTest {

    @Test
    fun `正常域名小写化`() {
        assertEquals("github.com", DnsNames.normalize("GitHub.COM"))
        assertEquals("github.com", DnsNames.normalize("github.com"))
    }

    @Test
    fun `去尾点`() {
        assertEquals("github.com", DnsNames.normalize("github.com."))
        assertEquals("github.com", DnsNames.normalize("github.com.."))
    }

    @Test
    fun `trim空白`() {
        assertEquals("github.com", DnsNames.normalize("  github.com  "))
    }

    @Test
    fun `空输入返回null`() {
        assertNull(DnsNames.normalize(null))
        assertNull(DnsNames.normalize(""))
        assertNull(DnsNames.normalize("   "))
        assertNull(DnsNames.normalize("."))
    }

    @Test
    fun `IDN转punycode`() {
        assertEquals("xn--fiqs8s", DnsNames.normalize("中国"))
    }

    @Test
    fun `非法标签返回null`() {
        assertNull(DnsNames.normalize("bad_domain.com")) // 下划线
        assertNull(DnsNames.normalize("-leading.com"))   // 前导连字符
        assertNull(DnsNames.normalize("trailing-.com"))  // 尾随连字符
        assertNull(DnsNames.normalize("a..b.com"))       // 空标签
    }

    @Test
    fun `超长域名返回null`() {
        val long = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) +
                "." + "d".repeat(63) + "." + "e".repeat(10)
        assertNull(DnsNames.normalize(long))
    }

    @Test
    fun `63字节标签合法`() {
        assertEquals("a".repeat(63), DnsNames.normalize("a".repeat(63)))
    }
}

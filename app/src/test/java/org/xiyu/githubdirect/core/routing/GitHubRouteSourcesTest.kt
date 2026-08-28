package org.xiyu.githubdirect.core.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDateTime
import java.time.ZoneOffset

class GitHubRouteSourcesTest {

    @Test
    fun `GitHub SNI白名单严格按标签边界匹配`() {
        assertTrue(GitHubDomainPolicy.isTrustedSni("alive.github.com"))
        assertTrue(GitHubDomainPolicy.isTrustedSni("release-assets.githubusercontent.com"))
        assertTrue(GitHubDomainPolicy.isTrustedSni("github.githubassets.com"))
        assertTrue(GitHubDomainPolicy.isTrustedSni("owner.github.io"))
        assertTrue(GitHubDomainPolicy.isTrustedSni("github.blog"))
        assertFalse(GitHubDomainPolicy.isTrustedSni("evilgithub.com"))
        assertFalse(GitHubDomainPolicy.isTrustedSni("github.com.example.org"))
        assertFalse(GitHubDomainPolicy.isTrustedSni("github-cloud.s3.amazonaws.com"))
    }

    @Test
    fun `Meta仅保留合法字段并区分字面候选`() {
        val meta = GitHubMetaParser.parse(
            """{
              "web":["140.82.112.0/20","20.205.243.166/32","127.0.0.0/8","bad"],
              "api":["2606:50c0::/32","2606:50c0:8000::153/128"]
            }""",
        )!!
        assertEquals(setOf("20.205.243.166"), meta.literalAddresses("web"))
        assertTrue(meta.contains("140.82.116.4"))
        assertTrue(meta.contains("2606:50c0:8000::153"))
        assertFalse(meta.contains("199.59.148.9"))
    }

    @Test
    fun `社区hosts必须新鲜且只接受GitHub域`() {
        val now = LocalDateTime.of(2026, 8, 24, 12, 0)
            .toInstant(ZoneOffset.ofHours(8)).toEpochMilli()
        val text = """
            # Update Time: 2026-08-24 08:00:00
            20.205.243.166 github.com
            199.59.148.9 api.github.com
            127.0.0.1 raw.githubusercontent.com
            192.0.66.2 github.blog
            185.199.108.153 github.io
            1.1.1.2 evilgithub.com
            1.1.1.1 example.com
        """.trimIndent()
        val parsed = CommunityHostsParser.parse(text, now, 7 * 24 * 60 * 60 * 1000L)!!
        assertEquals(listOf("20.205.243.166"), parsed.hosts["github.com"])
        assertEquals(listOf("199.59.148.9"), parsed.hosts["api.github.com"])
        assertEquals(listOf("192.0.66.2"), parsed.hosts["github.blog"])
        assertEquals(listOf("185.199.108.153"), parsed.hosts["github.io"])
        assertNull(parsed.hosts["raw.githubusercontent.com"])
        assertNull(parsed.hosts["evilgithub.com"])
        assertNull(parsed.hosts["example.com"])
        assertNull(CommunityHostsParser.parse(text, now + 8 * 24 * 60 * 60 * 1000L, 7 * 24 * 60 * 60 * 1000L))
    }
}

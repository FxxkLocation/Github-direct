package org.xiyu.githubdirect.core.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteSnapshotTest {

    @Test
    fun `编解码保持候选与拦截目标`() {
        val now = 1_000L
        val snapshot = RouteSnapshot(
            generation = 7,
            createdAt = now,
            expiresAt = 0,
            plans = mapOf(
                "github.com" to EndpointPlan(
                    domain = "github.com",
                    endpointGroup = "web",
                    candidates = listOf(
                        EndpointCandidate(
                            "github.com", "20.205.243.166", CandidateSource.WIRE_DOH,
                            now, 0, 25, RouteCapability.DIRECT_TLS,
                            noSniCapable = true,
                        ),
                        EndpointCandidate(
                            "github.com", "199.59.148.9", CandidateSource.LOCAL_DNS,
                            now, now + 60_000, 0, RouteCapability.UNUSABLE, interceptOnly = true,
                            lastError = "SocketTimeoutException:\r\n read timed out",
                            failureStage = CandidateFailureStage.TCP_CONNECT,
                        ),
                    ),
                ),
            ),
            metaCidrs = setOf("140.82.112.0/20"),
        )
        val decoded = RouteSnapshotCodec.decode(RouteSnapshotCodec.encode(snapshot))!!
        assertEquals(7, decoded.generation)
        assertEquals(listOf("20.205.243.166"), decoded.candidatesFor("github.com", now).map { it.address })
        assertTrue(decoded.candidatesFor("github.com", now).single().noSniCapable)
        assertTrue(decoded.candidatesFor("github.com", now).single().noSniProbed)
        assertTrue("140.82.112.0/20" in decoded.interceptDestinations(now))
        assertTrue("199.59.148.9/32" in decoded.interceptDestinations(now))
        assertFalse(decoded.candidatesFor("github.com", now).any { it.address == "199.59.148.9" })
        assertEquals(
            "SocketTimeoutException: read timed out",
            decoded.plans.getValue("github.com").candidates
                .single { it.address == "199.59.148.9" }
                .lastError,
        )
        assertEquals(
            CandidateFailureStage.TCP_CONNECT,
            decoded.plans.getValue("github.com").candidates
                .single { it.address == "199.59.148.9" }
                .failureStage,
        )
    }

    @Test
    fun `缺省no-SNI字段按历史能力推导且不误判直连候选`() {
        val decoded = RouteSnapshotCodec.decode(
            """{
              "version":2,
              "plans":[{"domain":"example.com","endpointGroup":"web","candidates":[
                {"address":"8.8.8.8","source":"WIRE_DOH","capability":"DIRECT_TLS"},
                {"address":"8.8.4.4","source":"WIRE_DOH","capability":"NO_SNI_TLS"}
              ]}]
            }""",
        )!!

        val candidates = decoded.plans.getValue("example.com").candidates.associateBy { it.address }
        assertFalse(candidates.getValue("8.8.8.8").noSniCapable)
        assertFalse(candidates.getValue("8.8.8.8").noSniProbed)
        assertTrue(candidates.getValue("8.8.4.4").noSniCapable)
        assertTrue(candidates.getValue("8.8.4.4").noSniProbed)
    }

    @Test
    fun `最长后缀计划匹配且非法快照拒绝`() {
        val plan = EndpointPlan("githubusercontent.com", "usercontent", true, emptyList())
        val snapshot = RouteSnapshot(1, 0, 0, mapOf(plan.domain to plan), emptySet())
        assertEquals(plan, snapshot.planFor("raw.githubusercontent.com"))
        assertNull(snapshot.planFor("example.com"))
        assertNull(RouteSnapshotCodec.decode("{\"version\":99}"))
        assertTrue(RouteSnapshotCodec.isValidCidr("2606:50c0::/32"))
        assertFalse(RouteSnapshotCodec.isValidCidr("140.82.0.1/99"))
        assertTrue(RouteSnapshotCodec.isRoutableCidr("140.82.112.0/20"))
        assertTrue(RouteSnapshotCodec.isRoutableCidr("2606:50c0::/32"))
        assertFalse(RouteSnapshotCodec.isRoutableCidr("10.0.0.0/8"))
        assertFalse(RouteSnapshotCodec.isRoutableCidr("192.0.2.0/24"))
        assertFalse(RouteSnapshotCodec.isRoutableCidr("1.0.0.0/8"))
        assertFalse(RouteSnapshotCodec.isRoutableCidr("140.82.112.1/20"))
    }

    @Test
    fun `持久化快照和拦截目标拒绝私网保留地址`() {
        val decoded = RouteSnapshotCodec.decode(
            """{
              "version":2,
              "metaCidrs":["127.0.0.0/8","140.82.112.0/20"],
              "plans":[{"domain":"github.com","endpointGroup":"web","candidates":[
                {"address":"127.0.0.1","source":"LOCAL_DNS","capability":"DIRECT_TLS"},
                {"address":"20.205.243.166","source":"WIRE_DOH","capability":"DIRECT_TLS"}
              ]}]
            }""",
        )!!
        assertEquals(listOf("20.205.243.166"), decoded.plans.getValue("github.com").candidates.map { it.address })
        assertEquals(setOf("140.82.112.0/20"), decoded.metaCidrs)

        val direct = RouteSnapshot(
            1, 0, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web", candidates = listOf(
                        EndpointCandidate(
                            "github.com", "10.0.0.1", CandidateSource.LOCAL_DNS,
                            0, 0, 1, RouteCapability.DIRECT_TLS,
                        ),
                    ),
                ),
            ),
            setOf("192.168.0.0/16"),
        )
        assertTrue(direct.interceptDestinations().isEmpty())
    }

    @Test
    fun `严格验证后按能力和延迟选择候选`() {
        val candidates = listOf(
            EndpointCandidate("github.com", "140.82.112.1", CandidateSource.BUNDLED, 0, 0, 90, RouteCapability.DIRECT_TLS),
            EndpointCandidate("github.com", "140.82.112.2", CandidateSource.BUNDLED, 0, 0, 80, RouteCapability.DIRECT_TLS),
            EndpointCandidate("github.com", "140.82.112.3", CandidateSource.BUNDLED, 0, 0, 70, RouteCapability.DIRECT_TLS),
            EndpointCandidate("github.com", "140.82.112.4", CandidateSource.LOCAL_DNS, 0, 0, 10, RouteCapability.DIRECT_TLS),
        )
        val snapshot = RouteSnapshot(
            1, 0, 0,
            mapOf("github.com" to EndpointPlan("github.com", "web", candidates = candidates)),
            emptySet(),
        )
        assertEquals(
            listOf("140.82.112.4", "140.82.112.3", "140.82.112.2"),
            snapshot.candidatesFor("github.com", 1).map { it.address },
        )
    }

    @Test
    fun `relayHosts为includeSubdomains计划发布显式通配键`() {
        val candidate = EndpointCandidate(
            "github.io", "185.199.108.153", CandidateSource.BUNDLED,
            0, 0, 10, RouteCapability.DIRECT_TLS,
        )
        val snapshot = RouteSnapshot(
            1, 0, 0,
            mapOf(
                "github.io" to EndpointPlan(
                    "github.io", "pages", includeSubdomains = true, candidates = listOf(candidate),
                ),
            ),
            emptySet(),
        )
        assertEquals(listOf("185.199.108.153"), snapshot.relayHosts()["github.io"])
        assertEquals(listOf("185.199.108.153"), snapshot.relayHosts()["*.github.io"])
    }

    @Test
    fun `控制面前置SNI候选不进入透明代理目的集合`() {
        val candidate = EndpointCandidate(
            "g.cn", "142.250.4.160", CandidateSource.WIRE_DOH,
            0, 0, 10, RouteCapability.DIRECT_TLS,
        )
        val snapshot = RouteSnapshot(
            1, 0, 0,
            mapOf(
                "g.cn" to EndpointPlan(
                    "g.cn",
                    "front-sni:g.cn",
                    candidates = listOf(candidate),
                ),
            ),
            emptySet(),
        )

        assertEquals(listOf("142.250.4.160"), snapshot.candidatesFor("g.cn").map { it.address })
        assertTrue(snapshot.relayHosts().isEmpty())
        assertTrue(snapshot.interceptDestinations().isEmpty())
        assertTrue(snapshot.candidateDestinationsForDomains(setOf("g.cn")).isEmpty())
        assertTrue(
            snapshot.candidateDestinationsForDomainBoundaries(
                exactDomains = setOf("g.cn"),
                suffixDomains = emptySet(),
            ).isEmpty(),
        )
    }

    @Test
    fun `按授权域名提取动态候选且不混入其他平台或Meta网段`() {
        val now = 10_000L
        fun candidate(domain: String, address: String, expiresAt: Long = 0L) = EndpointCandidate(
            domain, address, CandidateSource.WIRE_DOH,
            fetchedAt = now, expiresAt = expiresAt, latencyMs = 20,
            capability = RouteCapability.DIRECT_TLS,
        )
        val snapshot = RouteSnapshot(
            generation = 9,
            createdAt = now,
            expiresAt = 0,
            plans = mapOf(
                "auth.openai.com" to EndpointPlan(
                    "auth.openai.com",
                    "openai-auth",
                    candidates = listOf(
                        candidate("auth.openai.com", "172.64.146.15"),
                        candidate("auth.openai.com", "2606:4700:4400::6812:29f1"),
                        candidate("auth.openai.com", "2a06:98c1:310c::ac40:920f"),
                        candidate("auth.openai.com", "2606:4700::dead", now),
                    ),
                ),
                "www.google.com" to EndpointPlan(
                    "www.google.com",
                    "google-web",
                    candidates = listOf(candidate("www.google.com", "2607:f8b0:4007:80e::2004")),
                ),
            ),
            metaCidrs = setOf("2606:4700::/32"),
        )

        assertEquals(
            setOf(
                "172.64.146.15/32",
                "2606:4700:4400::6812:29f1/128",
                "2a06:98c1:310c::ac40:920f/128",
            ),
            snapshot.candidateDestinationsForDomains(setOf("openai.com"), now),
        )
        assertTrue(snapshot.candidateDestinationsForDomains(setOf("penai.com"), now).isEmpty())
    }
}

package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.IpAddresses
import org.xiyu.githubdirect.core.routing.CandidateSource
import org.xiyu.githubdirect.core.routing.EndpointCandidate
import org.xiyu.githubdirect.core.routing.EndpointPlan
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.core.routing.RouteSnapshotCodec
import org.xiyu.githubdirect.core.routing.GoogleIpRangesParser
import org.xiyu.githubdirect.core.rules.HostsProviderSpec
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class GithubHostsProviderPolicyTest {

    @Test
    fun `未重新观测的拦截候选不续期且到期即淘汰`() {
        val now = 5_000L
        val stale = EndpointCandidate(
            domain = "www.youtube.com",
            address = "104.244.42.197",
            source = CandidateSource.WIRE_DOH,
            fetchedAt = 1_000L,
            expiresAt = now + 1,
            latencyMs = 0,
            capability = RouteCapability.UNUSABLE,
            interceptOnly = true,
        )

        assertSame(stale, GithubHostsProvider.unobservedCandidateBeforeExpiry(stale, now))
        assertNull(GithubHostsProvider.unobservedCandidateBeforeExpiry(stale, now + 1))
    }

    @Test
    fun `本机与观察器DNS永远不能提升为上游`() {
        assertFalse(GithubHostsProvider.sourceCanBecomeUpstream(CandidateSource.LOCAL_DNS))
        assertFalse(GithubHostsProvider.sourceCanBecomeUpstream(CandidateSource.DNS_OBSERVER))
        assertTrue(GithubHostsProvider.sourceCanBecomeUpstream(CandidateSource.WIRE_DOH))
        assertTrue(GithubHostsProvider.sourceCanBecomeUpstream(CandidateSource.CANDIDATE_POOL))
        assertTrue(GithubHostsProvider.sourceCanBecomeUpstream(CandidateSource.COMMUNITY))
    }

    @Test
    fun `Google新候选必须通过官方归属而其他平台与已验证历史不受影响`() {
        val ranges = GoogleIpRangesParser.parse(
            """{"prefixes":[{"ipv4Prefix":"142.250.0.0/15"}]}""",
        )!!
        val official = IpAddresses.parseIpAddress("142.251.12.119")!!
        val polluted = IpAddresses.parseIpAddress("104.244.42.197")!!

        assertTrue(GithubHostsProvider.candidateOwnershipAllowsUpstream(
            "google-edge", official, ranges, previouslyVerified = false,
        ))
        assertFalse(GithubHostsProvider.candidateOwnershipAllowsUpstream(
            "google-edge", polluted, ranges, previouslyVerified = false,
        ))
        assertFalse(GithubHostsProvider.candidateOwnershipAllowsUpstream(
            "google-edge", official, googleRanges = null, previouslyVerified = false,
        ))
        assertTrue(GithubHostsProvider.candidateOwnershipAllowsUpstream(
            "google-edge", polluted, googleRanges = null, previouslyVerified = true,
        ))
        assertTrue(GithubHostsProvider.candidateOwnershipAllowsUpstream(
            candidatePool = null,
            address = polluted,
            googleRanges = null,
            previouslyVerified = false,
        ))
    }

    @Test
    fun `自适应清单覆盖GitHub App与首期下载链`() {
        val targets = GithubHostsProvider.targetDomains()
        listOf(
            "github.com",
            "api.github.com",
            "alive.github.com",
            "central.github.com",
            "collector.github.com",
            "github.githubassets.com",
            "raw.githubusercontent.com",
            "release-assets.githubusercontent.com",
        ).forEach { domain ->
            assertTrue("missing adaptive target: $domain", domain in targets)
        }
    }

    @Test
    fun `内置安全快照覆盖全部自适应目标且不含污染上游`() {
        val file = File("src/main/assets/routes/github_snapshot.json")
        assertTrue("bundled route snapshot missing: ${file.absolutePath}", file.isFile)
        val snapshot = RouteSnapshotCodec.decode(file.readText(Charsets.UTF_8))
            ?: error("bundled route snapshot is invalid")
        val missing = GithubHostsProvider.targetDomains() - snapshot.plans.keys
        assertTrue("bundled route plans missing: $missing", missing.isEmpty())
        for (domain in GithubHostsProvider.targetDomains()) {
            val upstreams = snapshot.plans.getValue(domain).candidates.filterNot { it.interceptOnly }
            assertTrue("bundled route has no safe upstream: $domain", upstreams.isNotEmpty())
            assertFalse("polluted address promoted for $domain", upstreams.any {
                it.address == "199.59.148.9" || it.address == "199.59.149.235"
            })
        }
    }

    @Test
    fun `整轮刷新失败按1 5 30分钟退避`() {
        assertEquals(TimeUnit.MINUTES.toMillis(1), GithubHostsProvider.refreshFailureBackoffMs(1))
        assertEquals(TimeUnit.MINUTES.toMillis(5), GithubHostsProvider.refreshFailureBackoffMs(2))
        assertEquals(TimeUnit.MINUTES.toMillis(30), GithubHostsProvider.refreshFailureBackoffMs(3))
        assertEquals(TimeUnit.MINUTES.toMillis(30), GithubHostsProvider.refreshFailureBackoffMs(99))
    }

    @Test
    fun `仅复用旧快照不算刷新成功而任一实时可信结果可结束退避`() {
        assertFalse(GithubHostsProvider.refreshHasLiveSource(false, false, false, false))
        assertTrue(GithubHostsProvider.refreshHasLiveSource(true, false, false, false))
        assertTrue(GithubHostsProvider.refreshHasLiveSource(false, true, false, false))
        assertTrue(GithubHostsProvider.refreshHasLiveSource(false, false, true, false))
        assertTrue(GithubHostsProvider.refreshHasLiveSource(false, false, false, true))
    }

    @Test
    fun `探测域名顺序按游标轮转避免尾部饥饿`() {
        assertEquals(listOf(0, 1, 2, 3, 4), GithubHostsProvider.rotatingIndexes(5, 0).toList())
        assertEquals(listOf(3, 4, 0, 1, 2), GithubHostsProvider.rotatingIndexes(5, 3).toList())
        assertEquals(listOf(4, 0, 1, 2, 3), GithubHostsProvider.rotatingIndexes(5, -1).toList())
        assertTrue(GithubHostsProvider.rotatingIndexes(0, 32).isEmpty())
    }

    @Test
    fun `严格Wire不可达会产生明确降级原因`() {
        assertEquals(
            "官方地址源、严格 Wire DoH 与可验证 TLS 候选均不可达；正在沿用最后安全快照",
            GithubHostsProvider.sourceDegradation(false, false, false, false),
        )
        assertTrue(
            GithubHostsProvider.sourceDegradation(true, false, false, false)
                .contains("严格 Wire DoH 不可达"),
        )
        assertEquals("", GithubHostsProvider.sourceDegradation(false, false, true, false))
    }

    @Test
    fun `延迟使用alpha四分之一的EWMA`() {
        assertEquals(40, GithubHostsProvider.latencyEwmaMs(0, 40))
        assertEquals(85, GithubHostsProvider.latencyEwmaMs(100, 40))
        assertEquals(100, GithubHostsProvider.latencyEwmaMs(100, 0))
    }

    @Test
    fun `候选硬上限为待探测池种子保留位置`() {
        val now = 1_000_000L
        val domain = "googlevideo.com"
        fun candidate(
            address: String,
            source: CandidateSource,
            capability: RouteCapability,
        ) = EndpointCandidate(
            domain = domain,
            address = address,
            source = source,
            fetchedAt = now,
            expiresAt = now + 60_000,
            latencyMs = if (capability == RouteCapability.UNUSABLE) 0 else 20,
            capability = capability,
            interceptOnly = capability == RouteCapability.UNUSABLE,
        )

        val usable = (1..3).map { index ->
            candidate("120.253.244.$index", CandidateSource.CANDIDATE_POOL, RouteCapability.DIRECT_TLS)
        }
        val wireObserved = (1..32).map { index ->
            candidate("142.250.0.$index", CandidateSource.WIRE_DOH, RouteCapability.UNUSABLE)
        }
        val reserved = candidate(
            "120.253.255.33",
            CandidateSource.CANDIDATE_POOL,
            RouteCapability.UNUSABLE,
        )

        val limited = GithubHostsProvider.rankAndLimitCandidates(
            usable + wireObserved + reserved,
            setOf(reserved.address),
            now,
            limit = 32,
        )

        assertEquals(32, limited.size)
        assertTrue(limited.containsAll(usable))
        assertTrue(reserved in limited)
    }

    @Test
    fun `快照发布屏障串行化规则激活与provider刷新`() {
        val provider = GithubHostsProvider(HostsProviderSpec("test", 6, 443))
        val firstEntered = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val secondEntered = CountDownLatch(1)
        val first = thread(isDaemon = true, name = "barrier-first") {
            provider.withRefreshBarrier {
                firstEntered.countDown()
                releaseFirst.await(2, TimeUnit.SECONDS)
            }
        }
        assertTrue(firstEntered.await(1, TimeUnit.SECONDS))
        val second = thread(isDaemon = true, name = "barrier-second") {
            provider.withRefreshBarrier { secondEntered.countDown() }
        }
        try {
            assertFalse(secondEntered.await(100, TimeUnit.MILLISECONDS))
        } finally {
            releaseFirst.countDown()
        }
        assertTrue(secondEntered.await(1, TimeUnit.SECONDS))
        first.join(1_000)
        second.join(1_000)
    }

    @Test
    fun `REPROBE 绕过新鲜度和退避而普通刷新遵守退避`() {
        val now = 1_000_000L
        val fresh = EndpointCandidate(
            "github.com", "140.82.112.4", CandidateSource.WIRE_DOH,
            now, 0, 20, RouteCapability.DIRECT_TLS,
            failures = 1,
            backoffUntil = now + 60_000,
            networkKey = "wifi",
        )
        assertFalse(GithubHostsProvider.candidateProbeDue(fresh, now, "wifi", forceProbe = false))
        assertFalse(
            GithubHostsProvider.candidateProbeDue(
                fresh,
                now,
                "wifi",
                forceProbe = false,
                requireNoSniProbe = true,
            ),
        )
        val historicalUnprobed = fresh.copy(failures = 0, backoffUntil = 0)
        assertTrue(
            GithubHostsProvider.candidateProbeDue(
                historicalUnprobed,
                now,
                "wifi",
                forceProbe = false,
                requireNoSniProbe = true,
            ),
        )
        assertFalse(
            GithubHostsProvider.candidateProbeDue(
                historicalUnprobed.copy(noSniProbed = true),
                now,
                "wifi",
                forceProbe = false,
                requireNoSniProbe = true,
            ),
        )
        assertTrue(GithubHostsProvider.candidateProbeDue(fresh, now, "wifi", forceProbe = true))
        assertTrue(GithubHostsProvider.candidateProbeDue(fresh, now, "cellular", forceProbe = false))
        assertTrue(GithubHostsProvider.candidateProbeDue(null, now, "wifi", forceProbe = false))
    }

    @Test
    fun `网络切换保留已验证候选但清空旧健康分`() {
        val now = 1_000_000L
        val previous = EndpointCandidate(
            "github.com", "140.82.112.4", CandidateSource.WIRE_DOH,
            now - 10_000, now + 60_000, 42, RouteCapability.FRAGMENTED_TLS,
            failures = 2,
            backoffUntil = now + 30_000,
            networkKey = "wifi",
        )
        val carried = GithubHostsProvider.carryVerifiedCandidateAcrossNetwork(
            previous, now, "cellular",
        )!!
        assertEquals(RouteCapability.FRAGMENTED_TLS, carried.capability)
        assertEquals("wifi", carried.networkKey)
        assertEquals(0L, carried.latencyMs)
        assertEquals(0, carried.failures)
        assertEquals(0L, carried.backoffUntil)
        assertTrue(carried.usable(now))
        assertTrue(GithubHostsProvider.candidateProbeDue(carried, now, "cellular", false))

        assertEquals(null, GithubHostsProvider.carryVerifiedCandidateAcrossNetwork(
            previous.copy(interceptOnly = true), now, "cellular",
        ))
        assertEquals(null, GithubHostsProvider.carryVerifiedCandidateAcrossNetwork(
            previous.copy(expiresAt = now), now, "cellular",
        ))
    }

    @Test
    fun `升级时内置快照补齐新域并在旧候选全失效时兜底`() {
        val now = 1_000_000L
        fun candidate(domain: String, address: String, expiresAt: Long, interceptOnly: Boolean = false) =
            EndpointCandidate(
                domain, address,
                if (interceptOnly) CandidateSource.LOCAL_DNS else CandidateSource.BUNDLED,
                now - 100, expiresAt, 10,
                if (interceptOnly) RouteCapability.UNUSABLE else RouteCapability.FRAGMENTED_TLS,
                interceptOnly = interceptOnly,
            )
        val persisted = RouteSnapshot(
            9, now - 1_000, now - 1,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web", candidates = listOf(
                        candidate("github.com", "140.82.112.4", now - 1),
                        candidate("github.com", "199.59.148.9", now + 60_000, interceptOnly = true),
                    ),
                ),
            ),
            setOf("140.82.112.0/20"),
        )
        val bundled = RouteSnapshot(
            1, 0, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web", candidates = listOf(
                        candidate("github.com", "140.82.113.4", 0),
                    ),
                ),
                "alive.github.com" to EndpointPlan(
                    "alive.github.com", "web", candidates = listOf(
                        candidate("alive.github.com", "140.82.113.26", 0),
                    ),
                ),
            ),
            setOf("185.199.108.0/22"),
        )

        val merged = GithubHostsProvider.mergeBundledFallback(persisted, bundled, now)
        assertEquals(9, merged.generation)
        assertTrue("alive.github.com" in merged.plans)
        assertEquals("140.82.113.4", merged.candidatesFor("github.com", now).first().address)
        assertTrue(merged.plans.getValue("github.com").candidates.any { it.address == "199.59.148.9" })
        assertEquals(setOf("140.82.112.0/20", "185.199.108.0/22"), merged.metaCidrs)
    }

    @Test
    fun `空的generation0持久化快照不能压过内置启动快照`() {
        val bundled = RouteSnapshot(
            1, 0, 0,
            mapOf(
                "github.com" to EndpointPlan(
                    "github.com", "web", candidates = listOf(
                        EndpointCandidate(
                            "github.com", "140.82.112.4", CandidateSource.BUNDLED,
                            0, 0, 10, RouteCapability.FRAGMENTED_TLS,
                        ),
                    ),
                ),
            ),
            setOf("140.82.112.0/20"),
        )
        val merged = GithubHostsProvider.mergeBundledFallback(RouteSnapshot.EMPTY.copy(), bundled, 1)
        assertEquals(1L, merged.generation)
        assertTrue(merged.plans.containsKey("github.com"))
        assertEquals(listOf("140.82.112.4"), merged.candidatesFor("github.com", 1).map { it.address })
    }
}

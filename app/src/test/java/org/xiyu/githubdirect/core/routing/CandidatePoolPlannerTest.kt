package org.xiyu.githubdirect.core.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CandidatePoolPlannerTest {

    private val now = 1_000_000L

    private fun target(
        domain: String,
        pool: String? = "shared",
        endpointGroup: String = "shared-backend",
    ) = AdaptiveRouteTarget(
        serviceId = "test",
        domain = domain,
        endpointGroup = endpointGroup,
        includeSubdomains = false,
        candidatePool = pool,
    )

    private fun candidate(
        domain: String,
        address: String,
        source: CandidateSource = CandidateSource.WIRE_DOH,
        capability: RouteCapability = RouteCapability.DIRECT_TLS,
        expiresAt: Long = now + 60_000,
        interceptOnly: Boolean = false,
    ) = EndpointCandidate(
        domain = domain,
        address = address,
        source = source,
        fetchedAt = now - 100,
        expiresAt = expiresAt,
        latencyMs = 20,
        capability = capability,
        interceptOnly = interceptOnly,
    )

    private fun snapshot(vararg plans: EndpointPlan) = RouteSnapshot(
        generation = 1,
        createdAt = now,
        expiresAt = now + 60_000,
        plans = plans.associateBy(EndpointPlan::domain),
        metaCidrs = emptySet(),
    )

    @Test
    fun `同池只向缺少上游的目标共享已验证公网IP`() {
        val source = target("www.gstatic.com")
        val missing = target("www.youtube.com")
        val otherPool = target("discord.com", "discord-edge")
        val routes = snapshot(
            EndpointPlan(
                source.domain,
                source.endpointGroup,
                candidates = listOf(
                    candidate(source.domain, "120.253.255.162"),
                    candidate(source.domain, "120.253.255.98", CandidateSource.LOCAL_DNS),
                    candidate(source.domain, "127.0.0.1"),
                ),
            ),
            EndpointPlan(missing.domain, missing.endpointGroup, candidates = emptyList()),
            EndpointPlan(otherPool.domain, otherPool.endpointGroup, candidates = emptyList()),
        )

        val shared = CandidatePoolPlanner.sharedSeeds(
            listOf(source, missing, otherPool),
            routes,
            now,
        )

        assertEquals(listOf("120.253.255.162"), shared[missing.domain])
        assertFalse(source.domain in shared)
        assertFalse(otherPool.domain in shared)
    }

    @Test
    fun `同候选池但不同应用后端绝不共享IP`() {
        val source = target("redirector.googlevideo.com", endpointGroup = "youtube-stream")
        val web = target("www.youtube.com", endpointGroup = "youtube-web")
        val routes = snapshot(
            EndpointPlan(
                source.domain,
                source.endpointGroup,
                candidates = listOf(candidate(source.domain, "120.253.255.33")),
            ),
            EndpointPlan(web.domain, web.endpointGroup, candidates = emptyList()),
        )

        val shared = CandidatePoolPlanner.sharedSeeds(listOf(source, web), routes, now)

        assertTrue(shared.isEmpty())
        assertTrue(CandidatePoolPlanner.activeMemberDomains(listOf(source, web)).isEmpty())
    }

    @Test
    fun `失败过期和观察型候选不能进入池`() {
        val source = target("source.example")
        val missing = target("target.example")
        val routes = snapshot(
            EndpointPlan(
                source.domain,
                source.endpointGroup,
                candidates = listOf(
                    candidate(source.domain, "8.8.8.8", capability = RouteCapability.UNUSABLE),
                    candidate(source.domain, "8.8.4.4", expiresAt = now),
                    candidate(source.domain, "1.1.1.1", source = CandidateSource.DNS_OBSERVER),
                    candidate(source.domain, "9.9.9.9", interceptOnly = true),
                ),
            ),
        )

        assertTrue(CandidatePoolPlanner.sharedSeeds(listOf(source, missing), routes, now).isEmpty())
    }

    @Test
    fun `目标补齐到活动候选上限且池有硬上限`() {
        val source = target("source.example")
        val missing = target("missing.example")
        val healthy = target("healthy.example")
        val many = (1..20).map { index ->
            candidate(source.domain, "8.8.8.$index")
        }
        val routes = snapshot(
            EndpointPlan(source.domain, source.endpointGroup, candidates = many),
            EndpointPlan(
                healthy.domain,
                healthy.endpointGroup,
                candidates = listOf(candidate(healthy.domain, "1.0.0.1")),
            ),
        )

        val shared = CandidatePoolPlanner.sharedSeeds(listOf(source, missing, healthy), routes, now)

        assertEquals(
            CandidatePoolPlanner.TARGET_USABLE_CANDIDATES,
            shared.getValue(missing.domain).size,
        )
        assertEquals(
            CandidatePoolPlanner.TARGET_USABLE_CANDIDATES - 1,
            shared.getValue(healthy.domain).size,
        )
        assertFalse("1.0.0.1" in shared.getValue(healthy.domain))
    }

    @Test
    fun `已有三个直连候选但无no-SNI时继续轮换未尝试地址`() {
        val source = target("source.example")
        val target = target("target.example")
        val sourceCandidates = (1..8).map { index ->
            candidate(source.domain, "8.8.8.$index")
        }
        val tried = sourceCandidates.take(3).map {
            it.copy(domain = target.domain, noSniProbed = true)
        }
        val routes = snapshot(
            EndpointPlan(source.domain, source.endpointGroup, candidates = sourceCandidates),
            EndpointPlan(target.domain, target.endpointGroup, candidates = tried),
        )

        val shared = CandidatePoolPlanner.sharedSeeds(listOf(source, target), routes, now)

        assertEquals(CandidatePoolPlanner.NO_SNI_SEARCH_PER_ROUND, shared.getValue(target.domain).size)
        assertTrue(shared.getValue(target.domain).none { address -> tried.any { it.address == address } })
    }

    @Test
    fun `受全局预算影响尚未探测的池地址下一轮仍可进入队列`() {
        val source = target("source.example")
        val target = target("target.example")
        val address = "8.8.8.8"
        val routes = snapshot(
            EndpointPlan(
                source.domain,
                source.endpointGroup,
                candidates = listOf(candidate(source.domain, address)),
            ),
            EndpointPlan(
                target.domain,
                target.endpointGroup,
                candidates = listOf(
                    candidate(
                        target.domain,
                        address,
                        capability = RouteCapability.UNUSABLE,
                        interceptOnly = true,
                    ),
                ),
            ),
        )

        val shared = CandidatePoolPlanner.sharedSeeds(listOf(source, target), routes, now)

        assertEquals(listOf(address), shared[target.domain])
    }

    @Test
    fun `目标已有严格验证no-SNI能力后停止额外搜索`() {
        val source = target("source.example")
        val target = target("target.example")
        val sourceCandidates = (1..8).map { index ->
            candidate(source.domain, "8.8.8.$index")
        }
        val targetCandidates = sourceCandidates.take(3).mapIndexed { index, item ->
            item.copy(domain = target.domain, noSniCapable = index == 0)
        }
        val routes = snapshot(
            EndpointPlan(source.domain, source.endpointGroup, candidates = sourceCandidates),
            EndpointPlan(target.domain, target.endpointGroup, candidates = targetCandidates),
        )

        val shared = CandidatePoolPlanner.sharedSeeds(listOf(source, target), routes, now)

        assertFalse(target.domain in shared)
    }
}

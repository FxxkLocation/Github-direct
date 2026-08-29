package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.routing.CandidateSource
import org.xiyu.githubdirect.core.routing.EndpointCandidate
import org.xiyu.githubdirect.core.routing.EndpointPlan
import org.xiyu.githubdirect.core.routing.RouteCapability
import org.xiyu.githubdirect.core.routing.RouteSnapshot
import org.xiyu.githubdirect.core.data.Nat64FallbackActivation

class SniGateRoutesTest {
    @Test
    fun `verified NAT64 observation is reused only for the same activation inside TTL`() {
        val activation = Nat64FallbackActivation(
            prefix = "2a01:4f8:c2c:123f:64:5:0:0/96",
            operator = "Example NAT64",
            expectedAsn = "AS24940",
            expectedRegion = "US",
        )
        val observation = Nat64EgressObservation(
            verified = true,
            publicIp = "203.0.113.8",
            observedAt = 1_000L,
        )

        assertEquals(
            observation,
            reusableNat64Observation(activation, activation, observation, 1_999L, 1_000L),
        )
        assertEquals(
            null,
            reusableNat64Observation(activation, activation, observation, 2_001L, 1_000L),
        )
        assertEquals(
            null,
            reusableNat64Observation(
                activation,
                activation.copy(expectedRegion = "DE"),
                observation,
                1_500L,
                1_000L,
            ),
        )
        assertEquals(
            null,
            reusableNat64Observation(
                activation,
                activation,
                observation.copy(verified = false),
                1_500L,
                1_000L,
            ),
        )
        assertEquals(
            null,
            reusableNat64Observation(activation, activation, observation, 999L, 1_000L),
        )
    }

    @Test
    fun `stale sni-gate PID only kills the exact module binary prefix`() {
        val script = sniGateStopScript()
        assertTrue(
            script.contains(
                "case \"\$cmd\" in ${SniGateRuntime.ROOT_RUNTIME_DIR}/sni-gate-*",
            ),
        )
        assertFalse(script.contains("in *sni-gate*"))
    }

    @Test
    fun `runtime reuses unchanged routes and verifies only changed or due failures`() {
        val route = TlsTerminationRoute(
            domain = "discord.gg",
            includeSubdomains = true,
            method = TlsTerminationMethod.ECH,
        )
        val api = route.copy(domain = "api.openai.com", includeSubdomains = false)
        val requested = TlsTerminationPlan(
            7,
            listOf(route, api),
        )
        val verifiedSubset = TlsTerminationPlan(7, listOf(route))
        val fullyVerified = requested.copy()

        val deferred = sniGateVerificationDecision(
            requested,
            requested.copy(generation = 8),
            verifiedSubset,
            true,
            now = 1_500L,
            retryAtByRoute = mapOf(api to 2_000L),
        )
        assertEquals(listOf(route), deferred.reusedRoutes)
        assertEquals(emptyList<TlsTerminationRoute>(), deferred.routesToVerify)

        val due = sniGateVerificationDecision(
            requested,
            requested.copy(generation = 8),
            verifiedSubset,
            true,
            now = 2_000L,
            retryAtByRoute = mapOf(api to 2_000L),
        )
        assertEquals(listOf(route), due.reusedRoutes)
        assertEquals(listOf(api), due.routesToVerify)

        val changed = route.copy(domain = "youtube.com")
        val changedDecision = sniGateVerificationDecision(
            requested,
            TlsTerminationPlan(8, listOf(route, changed)),
            verifiedSubset,
            true,
            now = 1_500L,
            retryAtByRoute = mapOf(api to 2_000L),
        )
        assertEquals(listOf(route), changedDecision.reusedRoutes)
        assertEquals(listOf(changed), changedDecision.routesToVerify)

        val allReused = sniGateVerificationDecision(
            requested,
            requested.copy(generation = 8),
            fullyVerified,
            true,
        )
        assertEquals(requested.routes, allReused.reusedRoutes)
        assertEquals(emptyList<TlsTerminationRoute>(), allReused.routesToVerify)

        val forced = sniGateVerificationDecision(
            requested,
            requested.copy(generation = 8),
            fullyVerified,
            true,
            forceVerification = true,
        )
        assertEquals(emptyList<TlsTerminationRoute>(), forced.reusedRoutes)
        assertEquals(requested.routes, forced.routesToVerify)

        val localDown = sniGateVerificationDecision(
            requested,
            requested,
            verifiedSubset,
            false,
        )
        assertEquals(emptyList<TlsTerminationRoute>(), localDown.reusedRoutes)
        assertEquals(requested.routes, localDown.routesToVerify)
    }

    @Test
    fun `verification retry deadline addition saturates instead of overflowing`() {
        assertEquals(3_000L, saturatingAdd(1_000L, 2_000L))
        assertEquals(Long.MAX_VALUE, saturatingAdd(Long.MAX_VALUE - 5L, 10L))
    }

    @Test
    fun `planner prefers proven no-SNI route and does not add an overlapping ECH route`() {
        val now = 1_000L
        val candidate = EndpointCandidate(
            domain = "example.com",
            address = "203.0.113.8",
            source = CandidateSource.WIRE_DOH,
            fetchedAt = now,
            expiresAt = now + 60_000,
            latencyMs = 20,
            capability = RouteCapability.NO_SNI_TLS,
        )
        val snapshot = RouteSnapshot(
            generation = 7,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(
                "example.com" to EndpointPlan(
                    "example.com",
                    "web",
                    includeSubdomains = true,
                    candidates = listOf(candidate),
                ),
            ),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(snapshot, now)
        assertEquals(TlsTerminationMethod.NO_SNI, plan.routeFor("example.com")?.method)
        assertEquals("203.0.113.8", plan.routeFor("example.com")?.upstreamAddress)
        assertEquals(1, plan.routes.size)
        assertEquals(null, plan.routeFor("a.example.com"))
    }

    @Test
    fun `planner derives target-native ECH probes from enabled rules without a hardcoded CDN`() {
        val now = 1_000L
        fun endpoint(domain: String) = EndpointPlan(
            domain = domain,
            endpointGroup = domain,
            candidates = emptyList(),
        )
        val snapshot = RouteSnapshot(
            generation = 9,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(
                "api.openai.com" to endpoint("api.openai.com"),
                "discord.com" to endpoint("discord.com"),
                "www.google.com" to endpoint("www.google.com"),
                "github.com" to endpoint("github.com"),
            ),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(
            snapshot,
            now,
            enabledRelayDomains = setOf("api.openai.com", "discord.com", "www.google.com"),
        )

        assertEquals(
            setOf("api.openai.com", "discord.com", "www.google.com"),
            plan.routes.map { it.domain }.toSet(),
        )
        assertTrue(plan.routes.all { it.method == TlsTerminationMethod.ECH })
        assertTrue(plan.routes.all { it.upstreamHost == null })
        assertTrue(plan.routes.all { it.echConfigDomain == null })
        assertEquals(null, plan.routeFor("github.com"))
    }

    @Test
    fun `planner binds declared ECH config to the current strictly probed candidate`() {
        val now = 1_000L
        val root = "chatgpt.com"
        val candidates = listOf(
            EndpointCandidate(
                domain = root,
                address = "172.64.155.209",
                source = CandidateSource.WIRE_DOH,
                fetchedAt = now,
                expiresAt = now + 60_000,
                latencyMs = 0,
                capability = RouteCapability.UNUSABLE,
            ),
            EndpointCandidate(
                domain = root,
                address = "104.18.32.47",
                source = CandidateSource.WIRE_DOH,
                fetchedAt = now,
                expiresAt = now + 60_000,
                latencyMs = 915,
                capability = RouteCapability.FRAGMENTED_TLS,
            ),
        )
        val snapshot = RouteSnapshot(
            generation = 13,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(root to EndpointPlan(root, "chatgpt", candidates = candidates)),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(
            snapshot = snapshot,
            now = now,
            enabledRelayDomains = setOf(root),
            enabledRelaySuffixes = setOf(root),
            enabledEchConfigDomains = mapOf(
                root to "cloudflare-ech.com",
                "untrusted.example" to "attacker.example",
            ),
        )

        val route = plan.routeFor("auth.chatgpt.com") ?: error("dynamic suffix route missing")
        assertEquals(TlsTerminationMethod.ECH, route.method)
        assertEquals("104.18.32.47", route.upstreamAddress)
        assertEquals("cloudflare-ech.com", route.echConfigDomain)
        assertEquals(null, plan.routeFor("chatgpt.com.attacker.example"))

        val rendered = SniGateConfigRenderer.render(
            plan,
            SniGateConfigPaths("/private/ca.crt", "/private/ca.key", "/private/certs"),
        )
        assertTrue(rendered.contains("match_sni = [\".chatgpt.com\"]"))
        assertTrue(rendered.contains("upstream = \"104.18.32.47:443\""))
        assertTrue(rendered.contains("ech_domain = \"cloudflare-ech.com\""))
        assertFalse(rendered.contains("172.64.155.209"))
        assertFalse(rendered.contains("attacker.example"))
    }

    @Test
    fun `ECH preflight may rehabilitate trusted DoH candidates rejected only by visible SNI`() {
        val now = 2_000L
        val root = "chatgpt.com"
        fun rejected(address: String, source: CandidateSource, expiresAt: Long = now + 60_000) =
            EndpointCandidate(
                domain = root,
                address = address,
                source = source,
                fetchedAt = now,
                expiresAt = expiresAt,
                latencyMs = 0,
                capability = RouteCapability.UNUSABLE,
                failures = 4,
                backoffUntil = now + 30_000,
                interceptOnly = true,
                lastError = "visible SNI reset",
            )
        val snapshot = RouteSnapshot(
            generation = 14,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(
                root to EndpointPlan(
                    root,
                    "chatgpt",
                    candidates = listOf(
                        rejected("31.13.75.5", CandidateSource.LOCAL_DNS),
                        rejected("103.252.115.221", CandidateSource.DNS_OBSERVER),
                        rejected("104.18.32.47", CandidateSource.WIRE_DOH),
                        rejected("172.64.155.209", CandidateSource.WIRE_DOH),
                        rejected("104.18.31.1", CandidateSource.WIRE_DOH, expiresAt = now),
                    ),
                ),
            ),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(
            snapshot = snapshot,
            now = now,
            enabledRelayDomains = setOf(root),
            enabledEchConfigDomains = mapOf(root to "cloudflare-ech.com"),
        )

        val route = plan.routeFor(root) ?: error("trusted ECH preflight route missing")
        assertEquals("104.18.32.47", route.upstreamAddress)
        assertEquals("cloudflare-ech.com", route.echConfigDomain)
        assertFalse(route.upstreamAddress in setOf("31.13.75.5", "103.252.115.221"))
    }

    @Test
    fun `NAT64 is rendered only for explicitly eligible ECH roots and forces a trusted IPv4 candidate`() {
        val now = 3_000L
        fun endpoint(domain: String, v4: String, v6: String) = EndpointPlan(
            domain = domain,
            endpointGroup = domain,
            candidates = listOf(
                EndpointCandidate(
                    domain = domain,
                    address = v6,
                    source = CandidateSource.WIRE_DOH,
                    fetchedAt = now,
                    expiresAt = now + 60_000,
                    latencyMs = 10,
                    capability = RouteCapability.DIRECT_TLS,
                ),
                EndpointCandidate(
                    domain = domain,
                    address = v4,
                    source = CandidateSource.WIRE_DOH,
                    fetchedAt = now,
                    expiresAt = now + 60_000,
                    latencyMs = 30,
                    capability = RouteCapability.UNUSABLE,
                    interceptOnly = true,
                ),
            ),
        )
        val snapshot = RouteSnapshot(
            generation = 15,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(
                "chatgpt.com" to endpoint("chatgpt.com", "104.18.32.47", "2606:4700:4408::6812:202f"),
                "discord.com" to endpoint("discord.com", "162.159.128.233", "2606:4700:7::a29f:80e9"),
            ),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(
            snapshot = snapshot,
            now = now,
            enabledRelayDomains = setOf("chatgpt.com", "discord.com"),
            enabledRelaySuffixes = setOf("chatgpt.com", "discord.com"),
            enabledEchConfigDomains = mapOf(
                "chatgpt.com" to "cloudflare-ech.com",
                "discord.com" to "cloudflare-ech.com",
            ),
            nat64FallbackEligibleDomains = setOf("chatgpt.com"),
            nat64Fallback = Nat64FallbackActivation(
                prefix = "2a01:4f8:c2c:123f:64:5:0:0/96",
                operator = "Example NAT64",
                expectedAsn = "AS24940",
                expectedRegion = "Nuremberg, DE",
            ),
        )

        val chatgpt = plan.routeFor("auth.chatgpt.com") ?: error("NAT64 route missing")
        assertEquals("104.18.32.47", chatgpt.upstreamAddress)
        assertEquals("2a01:4f8:c2c:123f:64:5:0:0/96", chatgpt.nat64Prefix)
        assertEquals("Example NAT64", chatgpt.nat64Operator)
        val discord = plan.routeFor("gateway.discord.com") ?: error("strict route missing")
        assertEquals("2606:4700:7::a29f:80e9", discord.upstreamAddress)
        assertEquals(null, discord.nat64Prefix)

        val rendered = SniGateConfigRenderer.render(
            plan,
            SniGateConfigPaths("/private/ca.crt", "/private/ca.key", "/private/certs"),
        )
        assertEquals(1, Regex("nat64_prefix =").findAll(rendered).count())
        assertTrue(rendered.contains("address_family = \"ipv4\""))
        assertTrue(rendered.contains("NON_STRICT_NAT64"))
        assertFalse(rendered.substringBefore("[[listener]]").contains("nat64_prefix"))
    }

    @Test
    fun `planner covers newly observed Discord subdomains through a bounded suffix route`() {
        val now = 1_000L
        val root = "discord.gg"
        val snapshot = RouteSnapshot(
            generation = 10,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(
                root to EndpointPlan(
                    domain = root,
                    endpointGroup = "discord",
                    candidates = emptyList(),
                ),
            ),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(
            snapshot,
            now,
            enabledRelayDomains = setOf(root),
            enabledRelaySuffixes = setOf(root, "untrusted.example"),
        )

        assertEquals(TlsTerminationMethod.ECH, plan.routeFor("remote-auth-gateway.discord.gg")?.method)
        assertTrue(plan.routes.single().includeSubdomains)
        assertEquals(null, plan.routeFor("discord.gg.attacker.example"))
        val rendered = SniGateConfigRenderer.render(
            plan,
            SniGateConfigPaths("/private/ca.crt", "/private/ca.key", "/private/certs"),
        )
        assertTrue(rendered.contains("match_sni = [\".discord.gg\"]"))
        assertFalse(rendered.contains("untrusted.example"))
    }

    @Test
    fun `planner promotes a proven no-SNI apex to its enabled suffix without child hardcoding`() {
        val now = 1_000L
        val root = "discord.gg"
        val candidate = EndpointCandidate(
            domain = root,
            address = "162.159.134.234",
            source = CandidateSource.WIRE_DOH,
            fetchedAt = now,
            expiresAt = now + 60_000,
            latencyMs = 20,
            capability = RouteCapability.NO_SNI_TLS,
        )
        val snapshot = RouteSnapshot(
            generation = 11,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(
                root to EndpointPlan(
                    domain = root,
                    endpointGroup = "discord",
                    candidates = listOf(candidate),
                ),
                "gateway.discord.gg" to EndpointPlan(
                    domain = "gateway.discord.gg",
                    endpointGroup = "discord-gateway",
                    candidates = listOf(candidate.copy(domain = "gateway.discord.gg")),
                ),
            ),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(
            snapshot,
            now,
            enabledRelayDomains = setOf(root, "gateway.discord.gg"),
            enabledRelaySuffixes = setOf(root),
        )

        val dynamic = plan.routeFor("remote-auth-gateway.discord.gg")
        assertEquals(TlsTerminationMethod.NO_SNI, dynamic?.method)
        assertTrue(dynamic?.includeSubdomains == true)
        assertEquals("162.159.134.234", dynamic?.upstreamAddress)
        assertEquals(null, plan.routeFor("discord.gg.attacker.example"))

        val rendered = SniGateConfigRenderer.render(
            plan,
            SniGateConfigPaths("/private/ca.crt", "/private/ca.key", "/private/certs"),
        )
        val exact = rendered.indexOf("match_sni = [\"gateway.discord.gg\"]")
        val suffix = rendered.indexOf("match_sni = [\".discord.gg\"]")
        assertTrue(exact >= 0)
        assertTrue(suffix > exact)
        assertFalse(rendered.contains("remote-auth-gateway.discord.gg"))
    }

    @Test
    fun `planner preserves direct fallback while preferring independently proven no-SNI ability`() {
        val now = 1_000L
        val candidate = EndpointCandidate(
            domain = "youtube.com",
            address = "120.253.244.226",
            source = CandidateSource.CANDIDATE_POOL,
            fetchedAt = now,
            expiresAt = now + 60_000,
            latencyMs = 20,
            capability = RouteCapability.DIRECT_TLS,
            noSniCapable = true,
        )
        val snapshot = RouteSnapshot(
            generation = 12,
            createdAt = now,
            expiresAt = now + 60_000,
            plans = mapOf(
                "youtube.com" to EndpointPlan(
                    "youtube.com",
                    "youtube",
                    candidates = listOf(candidate),
                ),
            ),
            metaCidrs = emptySet(),
        )

        val plan = TlsTerminationPlanner.plan(
            snapshot,
            now,
            enabledRelayDomains = setOf("youtube.com"),
            enabledRelaySuffixes = setOf("youtube.com"),
        )

        val dynamic = plan.routeFor("movies.youtube.com")
        assertEquals(TlsTerminationMethod.NO_SNI, dynamic?.method)
        assertEquals("120.253.244.226", dynamic?.upstreamAddress)
        assertEquals(RouteCapability.DIRECT_TLS, candidate.capability)
    }

    @Test
    fun `suffix verification uses a representative child for no-SNI and apex for ECH`() {
        val suffix = TlsTerminationRoute(
            domain = "discord.gg",
            includeSubdomains = true,
            method = TlsTerminationMethod.NO_SNI,
            upstreamAddress = "162.159.134.234",
        )
        assertEquals(
            listOf("ghd-probe.discord.gg"),
            verificationDomainsFor(suffix),
        )
        assertEquals(
            listOf("discord.gg"),
            verificationDomainsFor(suffix.copy(includeSubdomains = false)),
        )
        assertEquals(
            listOf("discord.gg"),
            verificationDomainsFor(suffix.copy(method = TlsTerminationMethod.ECH)),
        )
    }

    @Test
    fun `renderer is fail-closed and never installs or embeds a CA key`() {
        val plan = TlsTerminationPlan(
            generation = 1,
            routes = listOf(
                TlsTerminationRoute(
                    domain = "example.com",
                    includeSubdomains = false,
                    method = TlsTerminationMethod.NO_SNI,
                    upstreamAddress = "2001:db8::8",
                ),
                TlsTerminationRoute(
                    domain = "api.openai.com",
                    includeSubdomains = false,
                    method = TlsTerminationMethod.ECH,
                ),
            ),
        )
        val text = SniGateConfigRenderer.render(
            plan,
            SniGateConfigPaths("/private/ca.crt", "/private/ca.key", "/private/certs"),
        )

        assertTrue(text.contains("unmatched = \"close\""))
        assertTrue(text.contains("require_ech = true"))
        assertTrue(text.contains("override_sni = \"\""))
        assertTrue(text.contains("upstream = \"[2001:db8::8]:443\""))
        assertTrue(text.contains("match_sni = [\"api.openai.com\"]"))
        assertFalse(text.contains("cloudflare-ech.com"))
        assertFalse(text.substringAfter("name = \"strict-ech-0\"").contains("ech_domain ="))
        assertTrue(text.contains("install_to_system_root = false"))
        assertFalse(text.contains("BEGIN PRIVATE KEY"))
    }
}

package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertNotEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.xiyu.githubdirect.core.routing.RouteCapability
import java.net.Socket

/**
 * 显式联网验收：默认跳过，避免把外部网络可用性带入 CI。
 *
 * PowerShell:
 *   $env:GHD_LIVE_TLS_PROBE='1'
 *   .\gradlew.bat testDebugUnitTest --tests '*TlsEndpointProbeLiveTest'
 */
class TlsEndpointProbeLiveTest {
    @Test
    fun bundledFallbackCandidatesPassSystemTrustAndHostnameVerification() {
        assumeTrue(System.getenv("GHD_LIVE_TLS_PROBE") == "1")
        val binder = object : NetworkBinder {
            override var protect: ((Socket) -> Boolean)? = null
            override fun httpGet(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): String? = null
            override fun bindSocket(socket: Socket) = Unit
        }
        val probe = TlsEndpointProbe(binder, timeoutMs = 5_000)
        val candidates = listOf(
            "alive.github.com" to "140.82.112.26",
            "alive.github.com" to "140.82.113.26",
            "central.github.com" to "140.82.112.22",
            "central.github.com" to "140.82.113.22",
            "collector.github.com" to "140.82.112.21",
            "collector.github.com" to "140.82.113.21",
            "github.blog" to "192.0.66.2",
            "copilot-proxy.githubusercontent.com" to "4.249.131.160",
            "media.githubusercontent.com" to "185.199.109.133",
            "media.githubusercontent.com" to "185.199.110.133",
            "camo.githubusercontent.com" to "185.199.111.133",
            "camo.githubusercontent.com" to "185.199.108.133",
            "github.io" to "185.199.108.153",
            "github.io" to "185.199.109.153",
        )

        for ((domain, address) in candidates) {
            val result = probe.probe(domain, address)
            assertNotEquals("$domain@$address: ${result.error}", RouteCapability.UNUSABLE, result.capability)
        }
    }
}

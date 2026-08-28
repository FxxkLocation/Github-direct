package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.dns.IpAddresses

class Nat64EgressProbeTest {
    @Test
    fun `synthesis uses only the low 32 bits and rejects private IPv4`() {
        val address = synthesizeNat64Address(
            "2602:fc59:20:64::/96",
            "104.26.12.205",
        ) ?: error("synthesis failed")

        assertEquals(
            "2602:fc59:20:64:0:0:681a:ccd",
            IpAddresses.ipv6ToString(address.address),
        )
        assertNull(synthesizeNat64Address("2602:fc59:20:64::/96", "192.168.1.1"))
        assertNull(synthesizeNat64Address("64:ff9b::/96", "104.26.12.205"))
    }

    @Test
    fun `Cloudflare trace requires a public IPv4 region colo and TLS`() {
        val parsed = parseNat64Trace(
            """
            fl=629f11
            ip=203.23.166.37
            colo=ABQ
            loc=US
            tls=TLSv1.3
            """.trimIndent(),
        ) ?: error("trace not parsed")

        assertEquals("203.23.166.37", parsed.publicIp)
        assertEquals("US/ABQ", parsed.region)
        assertEquals("TLSv1.3", parsed.tls)
        assertNull(parseNat64Trace("ip=10.0.0.1\nloc=US\ncolo=ABQ\ntls=TLSv1.3"))
        assertNull(parseNat64Trace("ip=203.23.166.37\nloc=US\ncolo=ABQ"))
    }

    @Test
    fun `RIPEstat parsers normalize origin ASN and holder`() {
        val networkInfo =
            """{"data":{"asns":[19625],"prefix":"203.23.166.0/24"}}"""
        val overview =
            """{"data":{"holder":"ZTVI - Metro Communications Company"}}"""

        assertEquals("AS19625", parseRipeOriginAsn(networkInfo))
        assertEquals("ZTVI - Metro Communications Company", parseRipeAsHolder(overview))
        assertNull(parseRipeOriginAsn("""{"data":{"asns":[]}}"""))
        assertNull(parseRipeAsHolder("""{"data":{"holder":""}}"""))
    }

    @Test
    fun `expected region uses the first explicit two-letter code`() {
        assertEquals("US", expectedNat64RegionCode("US/ABQ-measured-registry-AU"))
        assertEquals("DE", expectedNat64RegionCode("Nuremberg, DE"))
        assertNull(expectedNat64RegionCode("Albuquerque"))
        assertTrue(expectedNat64RegionCode("us-abq") == "US")
    }
}

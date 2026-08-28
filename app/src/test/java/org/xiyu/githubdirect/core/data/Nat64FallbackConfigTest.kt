package org.xiyu.githubdirect.core.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class Nat64FallbackConfigTest {
    @Test
    fun `public NAT64 prefix requires a global unicast slash 96 with zero host bits`() {
        assertEquals(
            "2a01:4f8:c2c:123f:64:5:0:0/96",
            normalizePublicNat64Prefix96(" 2A01:4F8:C2C:123F:64:5::/96 "),
        )
        assertNull(normalizePublicNat64Prefix96("2a01:4f8:c2c:123f:64:5::1/96"))
        assertNull(normalizePublicNat64Prefix96("2a01:4f8:c2c:123f:64:5::/64"))
        assertNull(normalizePublicNat64Prefix96("64:ff9b::/96"))
        assertNull(normalizePublicNat64Prefix96("fd00:64::/96"))
        assertNull(normalizePublicNat64Prefix96("2001:db8:64::/96"))
    }

    @Test
    fun `activation requires complete operator metadata and a separate risk acknowledgement`() {
        val configured = Nat64FallbackConfig(
            enabled = true,
            prefix = "2a01:4f8:c2c:123f:64:5::/96",
            operator = "Example NAT64",
            expectedAsn = "24940",
            expectedRegion = "Nuremberg, DE",
        )
        assertNull(configured.activationOrNull())

        val active = configured.copy(riskAccepted = true).activationOrNull()
        assertNotNull(active)
        assertEquals("AS24940", active?.expectedAsn)
        assertEquals("2a01:4f8:c2c:123f:64:5:0:0/96", active?.prefix)
    }
}

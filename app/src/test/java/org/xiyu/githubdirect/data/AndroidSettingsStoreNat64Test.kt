package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.xiyu.githubdirect.core.data.Nat64FallbackConfig
import org.xiyu.githubdirect.test.InMemorySharedPreferences

class AndroidSettingsStoreNat64Test {
    @Test
    fun `NAT64 defaults off and invalid external enable is atomically downgraded`() {
        val store = AndroidSettingsStore(InMemorySharedPreferences())
        assertFalse(store.nat64FallbackConfig().enabled)

        store.setNat64FallbackConfig(
            Nat64FallbackConfig(enabled = true, prefix = "64:ff9b::/96", riskAccepted = true),
        )
        assertFalse(store.nat64FallbackConfig().enabled)
        assertFalse(store.nat64FallbackConfig().riskAccepted)
    }

    @Test
    fun `complete acknowledged NAT64 config roundtrips in canonical form`() {
        val store = AndroidSettingsStore(InMemorySharedPreferences())
        store.setNat64FallbackConfig(
            Nat64FallbackConfig(
                enabled = true,
                prefix = "2A01:4F8:C2C:123F:64:5::/96",
                operator = " Example NAT64 ",
                expectedAsn = "24940",
                expectedRegion = " Nuremberg, DE ",
                riskAccepted = true,
            ),
        )

        val actual = store.nat64FallbackConfig()
        assertNotNull(actual.activationOrNull())
        assertEquals("2a01:4f8:c2c:123f:64:5:0:0/96", actual.prefix)
        assertEquals("AS24940", actual.expectedAsn)
    }
}

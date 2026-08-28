package org.xiyu.githubdirect.root

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OemFreezeLeaseTest {

    @Test
    fun `仅Oplus系品牌启用厂商冻结租约`() {
        assertTrue(OemFreezeLease.isOplusFamily("OPPO", "oppo"))
        assertTrue(OemFreezeLease.isOplusFamily("OnePlus", "OnePlus"))
        assertTrue(OemFreezeLease.isOplusFamily("realme", "RMX"))
        assertTrue(OemFreezeLease.isOplusFamily("OPLUS", null))

        assertFalse(OemFreezeLease.isOplusFamily("Google", "Pixel"))
        assertFalse(OemFreezeLease.isOplusFamily("Samsung", "Samsung"))
        assertFalse(OemFreezeLease.isOplusFamily(null, null))
    }
}

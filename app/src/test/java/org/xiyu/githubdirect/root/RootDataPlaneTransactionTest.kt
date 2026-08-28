package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootDataPlaneTransactionTest {
    @Test
    fun `TLS rules and snapshot activation stay inside one barrier`() {
        val calls = ArrayList<String>()

        val result = runRootDataPlaneTransaction(
            withBarrier = { action ->
                calls += "barrier-enter"
                action().also { calls += "barrier-exit" }
            },
            syncTlsTermination = { calls += "tls" },
            operation = { calls += "rules"; true },
            isBackendActive = { calls += "active"; true },
            activateSnapshot = { calls += "snapshot"; true },
        )

        assertEquals(
            listOf("barrier-enter", "tls", "rules", "active", "snapshot", "barrier-exit"),
            calls,
        )
        assertTrue(result.operationOk)
        assertTrue(result.backendActive)
        assertTrue(result.snapshotActivated)
    }

    @Test
    fun `failed rules never query activity or publish a Hook snapshot`() {
        var activeChecked = false
        var snapshotPublished = false

        val result = runRootDataPlaneTransaction(
            withBarrier = { it() },
            syncTlsTermination = {},
            operation = { false },
            isBackendActive = { activeChecked = true; true },
            activateSnapshot = { snapshotPublished = true; true },
        )

        assertFalse(result.operationOk)
        assertFalse(result.backendActive)
        assertTrue(result.snapshotActivated)
        assertFalse(activeChecked)
        assertFalse(snapshotPublished)
    }

    @Test
    fun `inactive optional Root assist skips snapshot publication without failing operation`() {
        var snapshotPublished = false

        val result = runRootDataPlaneTransaction(
            withBarrier = { it() },
            syncTlsTermination = {},
            operation = { true },
            isBackendActive = { false },
            activateSnapshot = { snapshotPublished = true; false },
        )

        assertTrue(result.operationOk)
        assertFalse(result.backendActive)
        assertTrue(result.snapshotActivated)
        assertFalse(snapshotPublished)
    }
}

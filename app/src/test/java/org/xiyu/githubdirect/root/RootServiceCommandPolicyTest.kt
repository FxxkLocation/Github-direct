package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootServiceCommandPolicyTest {

    @Test
    fun `五个显式动作与null intent恢复动作分类正确`() {
        assertEquals(RootServiceCommand.START, RootServiceCommandPolicy.classify(RootServiceCommandPolicy.ACTION_START))
        assertEquals(RootServiceCommand.STOP, RootServiceCommandPolicy.classify(RootServiceCommandPolicy.ACTION_STOP))
        assertEquals(RootServiceCommand.REFRESH, RootServiceCommandPolicy.classify(RootServiceCommandPolicy.ACTION_REFRESH))
        assertEquals(RootServiceCommand.REPROBE, RootServiceCommandPolicy.classify(RootServiceCommandPolicy.ACTION_REPROBE))
        assertEquals(RootServiceCommand.RESTORE, RootServiceCommandPolicy.classify(RootServiceCommandPolicy.ACTION_RESTORE))
        assertEquals(RootServiceCommand.RESTORE, RootServiceCommandPolicy.classify(null))
        assertEquals(RootServiceCommand.RESTORE, RootServiceCommandPolicy.classify("unknown"))
    }

    @Test
    fun `STOP总是退出且未启用服务的一次性命令完成后退出`() {
        assertTrue(RootServiceCommandPolicy.shouldStopAfterCompletion(RootServiceCommand.STOP, true))
        assertTrue(RootServiceCommandPolicy.shouldStopAfterCompletion(RootServiceCommand.REFRESH, false))
        assertTrue(RootServiceCommandPolicy.shouldStopAfterCompletion(RootServiceCommand.REPROBE, false))

        assertFalse(RootServiceCommandPolicy.shouldStopAfterCompletion(RootServiceCommand.REFRESH, true))
        assertFalse(RootServiceCommandPolicy.shouldStopAfterCompletion(RootServiceCommand.REPROBE, true))
        assertFalse(RootServiceCommandPolicy.shouldStopAfterCompletion(RootServiceCommand.START, false))
        assertFalse(RootServiceCommandPolicy.shouldStopAfterCompletion(RootServiceCommand.RESTORE, false))
    }
}

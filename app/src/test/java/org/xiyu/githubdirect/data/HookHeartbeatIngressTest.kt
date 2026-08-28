package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class HookHeartbeatIngressTest {
    private val token = "a".repeat(32)
    private val valid = HookHeartbeatIngress.Payload(
        packageName = "com.microsoft.emmx",
        processName = "com.microsoft.emmx:privileged_process0",
        routeGeneration = 7L,
        framework = "LSPosed 2.0.0",
        apiVersion = 101,
        hitCount = 3L,
        token = token,
    )

    @Test
    fun `接受UID所属包并由服务端设置时间`() {
        val heartbeat = HookHeartbeatIngress.accept(
            valid,
            setOf("com.microsoft.emmx"),
            token,
            acceptedAt = 1234L,
        )

        assertNotNull(heartbeat)
        assertEquals(1234L, heartbeat?.timestamp)
        assertEquals(3L, heartbeat?.hitCount)
    }

    @Test
    fun `拒绝伪造包名和非子进程名`() {
        assertNull(HookHeartbeatIngress.accept(valid, setOf("com.example.other"), token, 1L))
        assertNull(
            HookHeartbeatIngress.accept(
                valid.copy(processName = "com.microsoft.emmx.evil"),
                setOf("com.microsoft.emmx"),
                token,
                1L,
            )
        )
    }

    @Test
    fun `拒绝错误令牌和越界字段`() {
        val caller = setOf("com.microsoft.emmx")
        assertNull(HookHeartbeatIngress.accept(valid, caller, "b".repeat(32), 1L))
        assertNull(HookHeartbeatIngress.accept(valid.copy(hitCount = -1L), caller, token, 1L))
        assertNull(HookHeartbeatIngress.accept(valid.copy(framework = "x".repeat(161)), caller, token, 1L))
    }

    @Test
    fun `拒绝无效服务端时间和API版本`() {
        val caller = setOf("com.microsoft.emmx")
        assertNull(HookHeartbeatIngress.accept(valid, caller, token, 0L))
        assertNull(HookHeartbeatIngress.accept(valid.copy(apiVersion = 0), caller, token, 1L))
    }
}

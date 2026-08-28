package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.data.HookHeartbeat
import org.xiyu.githubdirect.test.InMemorySharedPreferences

class RemoteSettingsSyncTest {

    @Test
    fun `只向Hook存储同步服务开关和活动路由`() {
        val local = InMemorySharedPreferences(
            mapOf(
                "service.enabled.github" to true,
                "route.snapshot.json" to "{\"generation\":7}",
                "route.snapshot.generation" to 7L,
                "hook.heartbeat.token" to "b".repeat(32),
                "backend.mode" to "ROOT_TRANSPARENT",
                "scope.packages" to setOf("com.github.android"),
                "hosts.github-hosts.data" to "large-private-payload",
            )
        )
        val remote = InMemorySharedPreferences(
            mapOf(
                "service.enabled.github" to false,
                "service.enabled.stale" to true,
                "backend.mode" to "stale-sensitive-value",
                "hook.heartbeat.token" to "a".repeat(32),
            )
        )

        assertTrue(RemoteSettingsSync.pushHookConfiguration(local, remote))

        assertEquals(true, remote.all["service.enabled.github"])
        assertEquals("{\"generation\":7}", remote.all["route.snapshot.json"])
        assertEquals(7L, remote.all["route.snapshot.generation"])
        assertEquals("b".repeat(32), remote.all["hook.heartbeat.token"])
        assertFalse(remote.contains("service.enabled.stale"))
        assertFalse(remote.contains("backend.mode"))
        assertFalse(remote.contains("scope.packages"))
        assertFalse(remote.contains("hosts.github-hosts.data"))
    }

    @Test
    fun `重置本地配置会清除Hook侧旧值和旧版远程心跳`() {
        val local = InMemorySharedPreferences()
        val remote = InMemorySharedPreferences(
            mapOf(
                "service.enabled.github" to false,
                "route.snapshot.json" to "old",
                "route.snapshot.generation" to 6L,
                "hook.heartbeat.token" to "b".repeat(32),
                "hook.heartbeat.package.com.example.old" to "stale",
            )
        )

        assertTrue(RemoteSettingsSync.pushHookConfiguration(local, remote))

        assertTrue(remote.all.isEmpty())
    }

    @Test
    fun `模块私有存储最多保留32个包心跳`() {
        val token = "e".repeat(32)
        val remote = InMemorySharedPreferences(mapOf("hook.heartbeat.token" to token))
        val store = AndroidSettingsStore(remote)

        repeat(40) { index ->
            store.recordHookHeartbeat(
                HookHeartbeat(
                    packageName = "com.example.app$index",
                    processName = "com.example.app$index",
                    timestamp = index.toLong(),
                    routeGeneration = 1L,
                    framework = "LSPosed",
                    apiVersion = 101,
                    hitCount = 1L,
                    token = token,
                )
            )
        }

        assertEquals(32, remote.all.keys.count { it.startsWith("hook.heartbeat.package.") })
        assertFalse(remote.contains("hook.heartbeat.package.com.example.app0"))
        assertTrue(remote.contains("hook.heartbeat.package.com.example.app39"))
    }

}

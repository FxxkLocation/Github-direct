package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.xiyu.githubdirect.core.rules.BackendMode
import org.xiyu.githubdirect.test.InMemorySettingsStore

/**
 * Scope/Backend 设置的持久化 roundtrip（InMemory 实现，纯 JVM）。
 */
class ScopeSettingsTest {

    @Test
    fun `backend mode 默认 AUTO 且 roundtrip`() {
        val store = InMemorySettingsStore()
        assertEquals(BackendMode.AUTO, store.backendMode())

        store.setBackendMode(BackendMode.ROOT_TRANSPARENT)
        assertEquals(BackendMode.ROOT_TRANSPARENT, store.backendMode())
        store.setBackendMode(BackendMode.VPN)
        assertEquals(BackendMode.VPN, store.backendMode())
        store.setBackendMode(BackendMode.XPOSED_ONLY)
        assertEquals(BackendMode.XPOSED_ONLY, store.backendMode())
        store.setBackendMode(BackendMode.AUTO)
        assertEquals(BackendMode.AUTO, store.backendMode())
    }

    @Test
    fun `app scope mode 默认 ALL_APPS 且 roundtrip`() {
        val store = InMemorySettingsStore()
        assertEquals(AppScopeMode.ALL_APPS, store.appScopeMode())

        store.setAppScopeMode(AppScopeMode.SELECTED_APPS)
        assertEquals(AppScopeMode.SELECTED_APPS, store.appScopeMode())
        store.setAppScopeMode(AppScopeMode.EXCLUDED_APPS)
        assertEquals(AppScopeMode.EXCLUDED_APPS, store.appScopeMode())
    }

    @Test
    fun `scoped packages 默认空集且 roundtrip`() {
        val store = InMemorySettingsStore()
        assertTrue(store.scopedPackages().isEmpty())

        val pkgs = setOf("com.example.a", "org.xiyu.githubdirect", "com.android.chrome")
        store.setScopedPackages(pkgs)
        assertEquals(pkgs, store.scopedPackages())

        // 空集合清空
        store.setScopedPackages(emptySet())
        assertTrue(store.scopedPackages().isEmpty())
    }

    @Test
    fun `返回值防御性拷贝（外部修改不影响存储）`() {
        val store = InMemorySettingsStore()
        store.setScopedPackages(setOf("com.example.a"))
        store.scopedPackages().let { (it as? MutableSet)?.add("hacker") }
        assertEquals(setOf("com.example.a"), store.scopedPackages())
    }
}

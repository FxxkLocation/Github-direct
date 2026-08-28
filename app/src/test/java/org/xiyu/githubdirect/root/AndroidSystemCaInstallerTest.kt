package org.xiyu.githubdirect.root

import org.xiyu.githubdirect.core.rules.AppScopeMode
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidSystemCaInstallerTest {
    @Test
    fun `APEX injector is scoped to this module and carries public certificate only`() {
        val script = AndroidSystemCaInstaller.renderInjectScript("95b3a169.0")

        assertTrue(script.contains("/apex/com.android.conscrypt/cacerts"))
        assertTrue(script.contains("mount -t tmpfs"))
        assertTrue(script.contains("mount --bind"))
        assertTrue(script.contains("system_security_cacerts_file"))
        assertTrue(script.contains("cmp -s"))
        assertFalse(script.contains("ca.key"))
        assertFalse(script.contains("PRIVATE KEY"))
    }

    @Test
    fun `boot scripts enter PID 1 mount namespace and module id is stable`() {
        val postFs = AndroidSystemCaInstaller.renderPostFsDataScript()
        val service = AndroidSystemCaInstaller.renderServiceScript()
        val prop = AndroidSystemCaInstaller.renderModuleProp("a".repeat(64))

        assertTrue(postFs.contains("nsenter -t 1 -m"))
        assertTrue(service.contains("nsenter -t 1 -m"))
        assertTrue(prop.contains("id=github_direct_ca"))
        assertFalse(prop.contains("PRIVATE KEY"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `injector rejects shell metacharacters in certificate filename`() {
        AndroidSystemCaInstaller.renderInjectScript("deadbeef.0;id")
    }

    @Test
    fun `keychain helper result parser accepts only strict exact-match output`() {
        val parsed = AndroidSystemCaInstaller.parseKeyChainResult(
            """
                GHD_KEYCHAIN_V1
                ok=1
                present=1
                alias=user:4566ad2e.0
                detail=present
            """.trimIndent(),
        )

        assertTrue(parsed?.ok == true)
        assertTrue(parsed?.present == true)
        assertTrue(parsed?.alias == "user:4566ad2e.0")
        assertNull(
            AndroidSystemCaInstaller.parseKeyChainResult(
                "noise\nGHD_KEYCHAIN_V1\nok=1\npresent=0\nalias=\ndetail=missing",
            ),
        )
        assertNull(
            AndroidSystemCaInstaller.parseKeyChainResult(
                "GHD_KEYCHAIN_V1\nok=1\npresent=1\nalias=system:4566ad2e.0\ndetail=present",
            ),
        )
    }

    @Test
    fun `browser policy parser accepts only the owned Edge policy result`() {
        val parsed = AndroidSystemCaInstaller.parseBrowserPolicyResult(
            "GHD_BROWSER_POLICY_V1\nok=1\npresent=1\npackage=com.microsoft.emmx\ndetail=installed:merged",
        )

        assertTrue(parsed?.ok == true)
        assertTrue(parsed?.present == true)
        assertNull(
            AndroidSystemCaInstaller.parseBrowserPolicyResult(
                "GHD_BROWSER_POLICY_V1\nok=1\npresent=1\npackage=com.android.chrome\ndetail=installed:merged",
            ),
        )
        assertNull(
            AndroidSystemCaInstaller.parseBrowserPolicyResult(
                "noise\nGHD_BROWSER_POLICY_V1\nok=1\npresent=1\npackage=com.microsoft.emmx\ndetail=x",
            ),
        )
    }

    @Test
    fun `Edge policy follows root scope and explicit embedded capture`() {
        val edge = "com.microsoft.emmx"
        assertFalse(
            AndroidSystemCaInstaller.edgePolicyRequired(
                installed = false,
                scopeMode = AppScopeMode.ALL_APPS,
                scopedPackages = emptySet(),
                embeddedCapturePackages = emptySet(),
            ),
        )
        assertTrue(
            AndroidSystemCaInstaller.edgePolicyRequired(
                installed = true,
                scopeMode = AppScopeMode.SELECTED_APPS,
                scopedPackages = setOf(edge),
                embeddedCapturePackages = emptySet(),
            ),
        )
        assertFalse(
            AndroidSystemCaInstaller.edgePolicyRequired(
                installed = true,
                scopeMode = AppScopeMode.EXCLUDED_APPS,
                scopedPackages = setOf(edge),
                embeddedCapturePackages = emptySet(),
            ),
        )
        assertTrue(
            AndroidSystemCaInstaller.edgePolicyRequired(
                installed = true,
                scopeMode = AppScopeMode.EXCLUDED_APPS,
                scopedPackages = setOf(edge),
                embeddedCapturePackages = setOf(edge),
            ),
        )
    }
}

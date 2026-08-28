package org.xiyu.githubdirect.root

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootAppProcessDexTest {
    private val apk =
        "/data/app/~~abcDEF012_+=/org.xiyu.githubdirect-AbCdEf012_+=/base.apk"

    @Test
    fun `installed APK path and cache target are narrowly scoped`() {
        assertTrue(RootAppProcessDex.isSafeApkPath(apk))
        assertFalse(RootAppProcessDex.isSafeApkPath("/data/local/tmp/base.apk"))
        assertFalse(
            RootAppProcessDex.isSafeApkPath(
                "/data/app/~~x/other.package-x/base.apk",
            ),
        )
        assertFalse(
            RootAppProcessDex.isSafeApkPath(
                "/data/app/~~x/org.xiyu.githubdirect-x/../base.apk",
            ),
        )
        assertTrue(RootAppProcessDex.cacheDir(10_372) == "/data/local/tmp/ghd_app_process_10372")
    }

    @Test
    fun `prepare script extracts every ordered dex into root owned cache`() {
        val script = RootAppProcessDex.renderPrepareScript(apk, 10_372)

        assertTrue(script.contains("'classes*.dex'"))
        assertTrue(script.contains("classes\$GHD_I.dex"))
        assertTrue(script.contains("chown -R 0:0"))
        assertTrue(script.contains("chmod 0644"))
        assertTrue(script.contains("GHD_CLASSPATH"))
        assertTrue(script.contains("/data/local/tmp/ghd_app_process_10372.new"))
        assertTrue(script.contains("/data/local/tmp/ghd_app_process_10372.lock"))
        assertTrue(script.contains("kill -0 \"\$GHD_LOCK_PID\""))
        assertTrue(script.contains("GHD_LOCK_WAIT"))
        assertFalse(script.contains("rm -rf /data/local/tmp"))
        assertFalse(script.contains("ca.key"))
        assertFalse(script.contains("PRIVATE KEY"))
    }
}

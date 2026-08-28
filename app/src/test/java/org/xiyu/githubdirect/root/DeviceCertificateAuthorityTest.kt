package org.xiyu.githubdirect.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class DeviceCertificateAuthorityTest {
    @Test
    fun `Android certificate filename matches OpenSSL subject_hash_old`() {
        val resource = checkNotNull(javaClass.classLoader?.getResource("test-ca.pem"))
        val ca = DeviceCertificateAuthority.load(File(resource.toURI()))

        assertEquals("95b3a169", ca.subjectHashOld)
        assertEquals("95b3a169.0", ca.androidFileName)
        assertEquals(
            "0b9aaacb348ad40ba4215f8b4b85d3d76463deccd871ab23d1a9df6ec58ae7fd",
            ca.fingerprintSha256,
        )
        assertTrue(ca.certificate.basicConstraints >= 0)
    }
}

package org.xiyu.githubdirect.root

import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

data class DeviceCertificateAuthority(
    val file: File,
    val certificate: X509Certificate,
    /** Android cacerts 文件名使用 OpenSSL subject_hash_old（MD5、小端 32 位）。 */
    val subjectHashOld: String,
    /** DER 证书 SHA-256；不包含私钥。 */
    val fingerprintSha256: String,
) {
    val androidFileName: String get() = "$subjectHashOld.0"

    companion object {
        fun load(file: File): DeviceCertificateAuthority {
            require(file.isFile && file.length() in 1..MAX_CERT_BYTES) {
                "CA certificate is missing or oversized"
            }
            val certificate = file.inputStream().use { input ->
                CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
            }
            require(certificate.basicConstraints >= 0) { "certificate is not a CA" }
            require(certificate.subjectX500Principal == certificate.issuerX500Principal) {
                "CA certificate is not self-issued"
            }
            certificate.verify(certificate.publicKey)
            val keyUsage = certificate.keyUsage
            require(keyUsage == null || keyUsage.size > 5 && keyUsage[5]) {
                "CA certificate lacks keyCertSign"
            }
            return DeviceCertificateAuthority(
                file = file,
                certificate = certificate,
                subjectHashOld = subjectHashOld(certificate),
                fingerprintSha256 = digestHex("SHA-256", certificate.encoded),
            )
        }

        internal fun subjectHashOld(certificate: X509Certificate): String {
            val md5 = MessageDigest.getInstance("MD5")
                .digest(certificate.subjectX500Principal.encoded)
            val value = (md5[0].toLong() and 0xffL) or
                ((md5[1].toLong() and 0xffL) shl 8) or
                ((md5[2].toLong() and 0xffL) shl 16) or
                ((md5[3].toLong() and 0xffL) shl 24)
            return String.format(Locale.ROOT, "%08x", value)
        }

        internal fun digestHex(algorithm: String, bytes: ByteArray): String =
            MessageDigest.getInstance(algorithm).digest(bytes)
                .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }

        private const val MAX_CERT_BYTES = 256 * 1024L
    }
}

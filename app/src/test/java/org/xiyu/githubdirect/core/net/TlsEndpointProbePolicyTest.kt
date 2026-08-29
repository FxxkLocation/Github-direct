package org.xiyu.githubdirect.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.xiyu.githubdirect.core.routing.CandidateFailureStage

class TlsEndpointProbePolicyTest {

    @Test
    fun `HTTP状态行只接受HTTP一语法和三位状态码`() {
        assertEquals(204, TlsEndpointProbe.parseHttpStatus("HTTP/1.1 204 No Content\r\n".toByteArray()))
        assertEquals(302, TlsEndpointProbe.parseHttpStatus("HTTP/1.0 302 Found\n".toByteArray()))
        assertNull(TlsEndpointProbe.parseHttpStatus("HTTP/2 200\r\n".toByteArray()))
        assertNull(TlsEndpointProbe.parseHttpStatus("HTTP/1.1 XX\r\n".toByteArray()))
        assertNull(TlsEndpointProbe.parseHttpStatus("HTTP/1.1 200".toByteArray()))
    }

    @Test
    fun `失败阶段优先报告已到达的最深验证层`() {
        assertEquals(
            CandidateFailureStage.HTTP_SEMANTIC,
            TlsEndpointProbe.dominantFailureStage(
                listOf(CandidateFailureStage.TCP_CONNECT, CandidateFailureStage.HTTP_SEMANTIC),
            ),
        )
        assertEquals(
            CandidateFailureStage.CERTIFICATE,
            TlsEndpointProbe.dominantFailureStage(
                listOf(CandidateFailureStage.TLS_RESET, CandidateFailureStage.CERTIFICATE),
            ),
        )
        assertEquals(
            CandidateFailureStage.NONE,
            TlsEndpointProbe.dominantFailureStage(emptyList()),
        )
    }

    @Test
    fun `TCP未建立或业务语义错误时不重复ClientHello变体`() {
        assertEquals(false, TlsEndpointProbe.tlsBypassMayChangeOutcome(CandidateFailureStage.TCP_CONNECT))
        assertEquals(false, TlsEndpointProbe.tlsBypassMayChangeOutcome(CandidateFailureStage.HTTP_SEMANTIC))
        assertEquals(false, TlsEndpointProbe.tlsBypassMayChangeOutcome(CandidateFailureStage.INVALID_ADDRESS))
        assertEquals(true, TlsEndpointProbe.tlsBypassMayChangeOutcome(CandidateFailureStage.TLS_RESET))
        assertEquals(true, TlsEndpointProbe.tlsBypassMayChangeOutcome(CandidateFailureStage.TLS_HANDSHAKE))
        assertEquals(true, TlsEndpointProbe.tlsBypassMayChangeOutcome(CandidateFailureStage.CERTIFICATE))
    }
}

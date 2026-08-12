package org.xiyu.githubdirect.core.dns

/**
 * 解析后的 DNS 查询：
 * - domain      : Question Section 的域名（小写、原始 wire 形态；解析失败为 null）
 * - qtype       : QTYPE（1=A, 28=AAAA, ...）
 * - questionEnd : Question Section 结束偏移（应答构造从此开始追加 Answer）
 * - query       : 完整 DNS 查询字节（构造应答时复制头 + Question）
 */
data class DnsQuestion(
    val domain: String?,
    val qtype: Int,
    val questionEnd: Int,
    val query: ByteArray,
)

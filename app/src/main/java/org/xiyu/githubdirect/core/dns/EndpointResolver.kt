package org.xiyu.githubdirect.core.dns

import org.xiyu.githubdirect.core.data.ResolvedIps
import org.xiyu.githubdirect.core.net.NetworkBinder

/**
 * DoH 解析器（从原 DohResolver 迁移：多服务器回退 + CidrFilter 过滤 + GET 查询，参数化）。
 *
 * - 网络访问全部经 NetworkBinder（VPN 进程绑底层物理网络，防环回）
 * - 单次查询：服务器逐个尝试；任一服务器返回有效 IP 即成功（快速路径）
 * - 服务器有响应但 IP 全被 CIDR 过滤（污染）→ 继续下一个服务器
 */
class EndpointResolver(
    private val binder: NetworkBinder,
    private val servers: List<String> = DoHServers.DEFAULT,
    private val connectTimeoutMs: Int = 3000,
    private val readTimeoutMs: Int = 3000,
) {

    fun resolveA(domain: String, cidr: CidrFilter?): List<ByteArray>? =
        resolveType(domain, 1, cidr)

    /** 同时查询 A + AAAA，CIDR 过滤后返回。全部服务器失败返回 null。 */
    fun resolve(domain: String, cidr: CidrFilter?): ResolvedIps? {
        for (server in servers) {
            val v4 = queryDohType(server, domain, 1, cidr)
            val v6 = queryDohType(server, domain, 28, cidr)
            val responded = v4 != null || v6 != null
            val hasV4 = v4 != null && v4.isNotEmpty()
            val hasV6 = v6 != null && v6.isNotEmpty()
            if (responded && (hasV4 || hasV6)) {
                return ResolvedIps(
                    v4 = v4.orEmpty(),
                    v6 = v6.orEmpty(),
                )
            }
            // 有响应但全被过滤（污染）→ 尝试下一服务器；无响应同理
        }
        return null
    }

    /**
     * 按单个 qtype 查询（1=A, 28=AAAA），CIDR 过滤后返回。
     * 全部服务器失败返回 null；有响应但无有效 IP 返回空列表。
     */
    fun resolveType(domain: String, qtype: Int, cidr: CidrFilter?): List<ByteArray>? {
        // 当前实现是 IP-address JSON adapter，只允许 A/AAAA。
        // 其他 QTYPE 必须由后续 RFC8484 raw-wire forwarder 处理，不能伪装成 A 查询。
        if (qtype != 1 && qtype != 28) return emptyList()
        var lastResponded = false
        for (server in servers) {
            val result = queryDohType(server, domain, qtype, cidr)
            if (result != null) {
                lastResponded = true
                if (result.isNotEmpty()) return result
            }
        }
        return if (lastResponded) emptyList() else null
    }

    /** 单个 DoH 服务器、单个类型的查询。null = 服务器不可用；空列表 = 有响应但全被过滤。 */
    private fun queryDohType(server: String, domain: String, type: Int, cidr: CidrFilter?): List<ByteArray>? {
        val typeStr = if (type == 28) "AAAA" else "A"
        val url = "$server?name=$domain&type=$typeStr"
        val json = binder.httpGet(url, connectTimeoutMs, readTimeoutMs) ?: return null
        if (DoHJson.status(json) != 0) return null

        val result = ArrayList<ByteArray>(4)
        for ((answerType, data) in DoHJson.answers(json)) {
            if (answerType != type) continue
            val bytes = IpAddresses.parseIpAddress(data) ?: continue
            if (cidr != null) {
                if (bytes.size == 4 && !cidr.allowsIpv4(bytes)) continue
                if (bytes.size == 16 && !cidr.allowsIpv6(bytes)) continue
            }
            result.add(bytes)
        }
        return result
    }
}

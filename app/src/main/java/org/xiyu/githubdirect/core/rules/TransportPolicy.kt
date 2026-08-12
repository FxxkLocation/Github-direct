package org.xiyu.githubdirect.core.rules

/**
 * 传输策略（与 ResolverPolicy 正交）。
 *
 * - PASSTHROUGH        : 不拦截。VPN = 转发上游 DoH；Xposed = chain.proceed()
 * - CLEAN_DNS          : DoH 解析 + CIDR 过滤 → 真实 IP 直连，不 relay
 * - DIRECT_IP          : 走 relay 直连真实 IP，不做 TLS 分片（M1 不使用，保留供未来规则）
 * - TLS_FRAGMENT_RELAY : relay + ClientHello 分片（GitHub 现状行为）
 * - NXDOMAIN           : 屏蔽域（返回 NXDOMAIN 应答）
 */
enum class TransportPolicy {
    PASSTHROUGH,
    CLEAN_DNS,
    DIRECT_IP,
    TLS_FRAGMENT_RELAY,
    NXDOMAIN;

    companion object {
        /** 解析规则数据中的传输策略名；未知值返回 null。 */
        fun fromJson(name: String?): TransportPolicy? = when (name?.uppercase()) {
            "PASSTHROUGH" -> PASSTHROUGH
            "CLEAN_DNS" -> CLEAN_DNS
            "DIRECT_IP" -> DIRECT_IP
            "TLS_FRAGMENT_RELAY" -> TLS_FRAGMENT_RELAY
            "NXDOMAIN" -> NXDOMAIN
            else -> null
        }
    }
}

package org.xiyu.githubdirect.core.rules

import org.xiyu.githubdirect.core.dns.CidrFilter

/**
 * 服务配置（规则数据模型，构造后不可变）。
 *
 * id 即唯一键（如 "github"），无 github 前缀命名。
 * cidr 在规则加载时由 CidrFilter.parse 编译一次，运行时零解析。
 */
data class ServiceProfile(
    val id: String,
    val displayName: String,
    val category: String,
    val enabledByDefault: Boolean,
    val priority: Int = 0,
    val verifyStatus: VerifyStatus = VerifyStatus.NEEDS_VERIFY,
    val domains: List<DomainRule> = emptyList(),
    val testEndpoints: List<String> = emptyList(),
    val cidr: CidrFilter? = null,
    val aaaaSuppress: Boolean = false,
    val idleTimeoutSec: Int = 60,
    val providers: List<HostsProviderSpec> = emptyList(),
    val notes: String = "",
)

data class HostsProviderSpec(
    val providerId: String,
    val intervalHours: Long,
    val tcpProbePort: Int = 443,
)

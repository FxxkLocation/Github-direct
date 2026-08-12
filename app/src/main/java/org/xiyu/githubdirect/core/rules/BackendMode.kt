package org.xiyu.githubdirect.core.rules

/**
 * 代理后端模式（设计 §15/§16）。
 *
 * - AUTO：自动选择（探测 root → ROOT_TRANSPARENT，否则 VPN）
 * - ROOT_TRANSPARENT：Root 透明模式（iptables REDIRECT，不占用系统 VPN slot，§16 核心诉求）
 * - VPN：VpnService 模式（需用户授权）
 * - XPOSED_ONLY：仅 Xposed 本地 DNS 修复（不启动任何 backend）
 */
enum class BackendMode { AUTO, ROOT_TRANSPARENT, VPN, XPOSED_ONLY }

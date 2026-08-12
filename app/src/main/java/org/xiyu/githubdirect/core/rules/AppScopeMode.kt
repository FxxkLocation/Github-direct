package org.xiyu.githubdirect.core.rules

/**
 * 应用作用域（设计 §15/§40）。
 *
 * - ALL_APPS：全部应用（默认）
 * - SELECTED_APPS：仅作用域内选中的应用（白名单）
 * - EXCLUDED_APPS：排除选中的应用（黑名单）
 *
 * 三个后端（Root / VPN / Xposed）统一读取同一份 scope 配置，
 * 各自按能力映射：Root → FirewallRules scopeUids；VPN → Builder.addAllowed/DisallowedApplication。
 */
enum class AppScopeMode { ALL_APPS, SELECTED_APPS, EXCLUDED_APPS }

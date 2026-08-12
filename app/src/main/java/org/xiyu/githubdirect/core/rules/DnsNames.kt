package org.xiyu.githubdirect.core.rules

import java.net.IDN

/**
 * 统一域名规范化入口（唯一入口；禁止散落各处 toLowerCase）。
 *
 * 流程：trim → 去尾点 → IDN.toASCII（catch IllegalArgumentException → null）
 *      → 长度/标签合法性校验 → lowercase。
 * 非法输入返回 null。
 */
object DnsNames {

    /** 域名最大字节数（RFC 1035: 255 含根标签；这里按 253 保守处理） */
    private const val MAX_LENGTH = 253
    private const val MAX_LABEL_LENGTH = 63

    fun normalize(raw: String?): String? {
        if (raw == null) return null
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null

        // 去尾点（可多个）
        var s = trimmed
        while (s.endsWith(".")) {
            s = s.substring(0, s.length - 1)
        }
        if (s.isEmpty()) return null

        // IDN → punycode（也统一为小写输出前处理；对已 ASCII 的输入是恒等变换）
        val ascii = try {
            IDN.toASCII(s, IDN.ALLOW_UNASSIGNED)
        } catch (e: IllegalArgumentException) {
            return null
        }

        if (ascii.length > MAX_LENGTH) return null

        // 标签校验（空标签、超长标签、含非法字符的标签 → null）
        for (label in ascii.split(".")) {
            if (label.isEmpty()) return null
            if (label.length > MAX_LABEL_LENGTH) return null
            if (!isValidLabel(label)) return null
        }

        return ascii.lowercase()
    }

    /**
     * 标签合法性：允许 [a-z0-9-] 与 punycode 前缀 xn--（IDN.toASCII 输出域）。
     * 不允许下划线/空格等（非主机名输入）。
     */
    private fun isValidLabel(label: String): Boolean {
        if (label.startsWith("-") || label.endsWith("-")) return false
        for (c in label) {
            if (!(c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-')) return false
        }
        return true
    }
}

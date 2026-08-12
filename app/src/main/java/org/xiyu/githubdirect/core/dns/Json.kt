package org.xiyu.githubdirect.core.dns

/**
 * 最小 JSON 解析器（纯 JVM，零依赖）。
 * 仅用于解析 DoH (RFC 8484) 响应——Android 内置 org.json 在 JVM 单测中不可用
 * （android.jar 为 Stub），core 层保持纯 JVM 可测。
 */
object Json {

    sealed class Value {
        class Obj(val map: Map<String, Value>) : Value() {
            operator fun get(key: String): Value? = map[key]
        }

        class Arr(val list: List<Value>) : Value()
        class Str(val value: String) : Value()
        class Num(val value: Long) : Value()
        object True : Value()
        object False : Value()
        object Null : Value()
    }

    /** 解析 JSON 文本；失败返回 null。 */
    fun parse(text: String): Value? {
        val p = Parser(text)
        p.skipWs()
        val v = p.parseValue() ?: return null
        p.skipWs()
        return if (p.pos < p.text.length) null else v
    }

    private class Parser(val text: String) {
        var pos = 0

        fun skipWs() {
            while (pos < text.length && text[pos].isWhitespace()) pos++
        }

        fun parseValue(): Value? {
            if (pos >= text.length) return null
            return when (text[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()?.let { Value.Str(it) }
                't' -> parseLiteral("true")?.let { Value.True }
                'f' -> parseLiteral("false")?.let { Value.False }
                'n' -> parseLiteral("null")?.let { Value.Null }
                '-', in '0'..'9' -> parseNumber()
                else -> null
            }
        }

        private fun parseLiteral(lit: String): Boolean? {
            if (text.regionMatches(pos, lit, 0, lit.length)) {
                pos += lit.length
                return true
            }
            return null
        }

        private fun parseNumber(): Value? {
            val start = pos
            if (pos < text.length && text[pos] == '-') pos++
            var digits = 0
            while (pos < text.length && text[pos] in '0'..'9') {
                pos++
                digits++
            }
            if (pos < text.length && text[pos] == '.') {
                pos++
                while (pos < text.length && text[pos] in '0'..'9') pos++
            }
            if (pos < text.length && (text[pos] == 'e' || text[pos] == 'E')) {
                pos++
                if (pos < text.length && (text[pos] == '+' || text[pos] == '-')) pos++
                while (pos < text.length && text[pos] in '0'..'9') pos++
            }
            if (digits == 0) return null
            val raw = text.substring(start, pos)
            // DoH 只需要整数 Status/type；浮点转 long 截断
            val v = raw.toLongOrNull() ?: raw.toDoubleOrNull()?.toLong() ?: return null
            return Value.Num(v)
        }

        private fun parseString(): String? {
            if (pos >= text.length || text[pos] != '"') return null
            pos++
            val sb = StringBuilder()
            while (pos < text.length) {
                val c = text[pos]
                when {
                    c == '"' -> {
                        pos++
                        return sb.toString()
                    }
                    c == '\\' -> {
                        pos++
                        if (pos >= text.length) return null
                        when (val esc = text[pos]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append(0x0C.toChar())
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 >= text.length) return null
                                val hex = text.substring(pos + 1, pos + 5)
                                val code = hex.toIntOrNull(16) ?: return null
                                sb.append(code.toChar())
                                pos += 4
                            }
                            else -> return null
                        }
                        pos++
                    }
                    c < ' ' -> return null // 控制字符不允许
                    else -> {
                        sb.append(c)
                        pos++
                    }
                }
            }
            return null
        }

        private fun parseObject(): Value? {
            pos++ // '{'
            val map = LinkedHashMap<String, Value>()
            skipWs()
            if (pos < text.length && text[pos] == '}') {
                pos++
                return Value.Obj(map)
            }
            while (pos < text.length) {
                skipWs()
                val key = parseString() ?: return null
                skipWs()
                if (pos >= text.length || text[pos] != ':') return null
                pos++
                skipWs()
                val value = parseValue() ?: return null
                map[key] = value
                skipWs()
                if (pos >= text.length) return null
                when (text[pos]) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return Value.Obj(map)
                    }
                    else -> return null
                }
            }
            return null
        }

        private fun parseArray(): Value? {
            pos++ // '['
            val list = ArrayList<Value>()
            skipWs()
            if (pos < text.length && text[pos] == ']') {
                pos++
                return Value.Arr(list)
            }
            while (pos < text.length) {
                skipWs()
                val value = parseValue() ?: return null
                list.add(value)
                skipWs()
                if (pos >= text.length) return null
                when (text[pos]) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return Value.Arr(list)
                    }
                    else -> return null
                }
            }
            return null
        }
    }
}

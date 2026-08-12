package org.xiyu.githubdirect.core.rules

/**
 * 规则索引：exact 用 HashMap（O(1)），suffix 用反向 label trie（O(L)，L = label 数）。
 * 编译期构建（add 仅构建期调用），build() 之后只读，无锁并发读。
 */
class MatcherIndex {

    private val exact = HashMap<String, MutableList<IndexedRule>>()
    private val trie = SuffixTrie()
    private var built = false

    /** 构建期调用：添加一条带索引信息的规则。 */
    fun add(rule: IndexedRule) {
        check(!built) { "MatcherIndex already built" }
        when (val m = rule.rule.matcher) {
            is ExactMatcher -> exact.getOrPut(m.domain) { ArrayList() }.add(rule)
            is SuffixMatcher -> trie.insert(m.suffix, rule)
        }
    }

    /** 构建后不可再 add（防御）。 */
    fun build() {
        built = true
    }

    val isBuilt: Boolean get() = built

    /** 返回全部命中规则：exact 命中 + 全部 suffix 命中。入参必须已 normalize。 */
    fun matchAll(normalizedDomain: String): List<IndexedRule> {
        val result = ArrayList<IndexedRule>(4)
        exact[normalizedDomain]?.let { result.addAll(it) }

        val labels = normalizedDomain.split(".")
        var node = trie
        for (i in labels.indices.reversed()) {
            node = node.children[labels[i]] ?: break
            node.terminal?.let { result.addAll(it) }
        }
        return result
    }

    val exactSize: Int get() = exact.size
    val trieSize: Int get() = trie.nodeCount
}

/** 反向 label trie：suffix（含前导点）按 label 从右向左插入。 */
class SuffixTrie {
    internal val children = HashMap<String, SuffixTrie>()
    internal var terminal: List<IndexedRule>? = null
    internal var nodeCount: Int = 1

    internal fun insert(suffix: String, rule: IndexedRule) {
        val labels = suffix.removePrefix(".").split(".")
        var node = this
        for (i in labels.indices.reversed()) {
            val label = labels[i]
            val child = node.children[label] ?: SuffixTrie().also {
                node.children[label] = it
                nodeCount++
            }
            node = child
        }
        node.terminal = (node.terminal ?: emptyList()) + rule
    }
}

data class IndexedRule(
    val rule: DomainRule,
    val serviceId: String,
    val priority: Int,
)

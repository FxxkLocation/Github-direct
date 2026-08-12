package org.xiyu.githubdirect

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.ListView
import android.widget.Switch
import android.widget.TextView
import org.xiyu.githubdirect.core.rules.RuleRegistry
import org.xiyu.githubdirect.core.rules.ServiceProfile
import org.xiyu.githubdirect.core.rules.VerifyStatus
import org.xiyu.githubdirect.data.DirectEngine

/**
 * 服务管理页：按 category 分组列出全部服务 profile，
 * 支持按 displayName / id 搜索，每项显示 verifyStatus 徽标 + 启用开关。
 *
 * 轻量实现：框架 ListView + 双视图类型 BaseAdapter（分组头 / 服务项），
 * 无 androidx 依赖；开关变更走 RuleRegistry.setEnabled（与首页统计联动）。
 */
class ServiceManagerActivity : Activity() {

    private lateinit var registry: RuleRegistry
    private lateinit var countText: TextView
    private var rows: List<Row> = emptyList()

    private class Row(val category: String?, val profile: ServiceProfile?)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_services)

        DirectEngine.ensureInit(this, false)
        registry = DirectEngine.registry() ?: run {
            finish()
            return
        }

        countText = findViewById(R.id.sm_count)
        findViewById<View>(R.id.btn_back).setOnClickListener { finish() }

        val search = findViewById<EditText>(R.id.search_input)
        findViewById<View>(R.id.btn_enable_all).setOnClickListener {
            registry.setAllEnabled(true)
            rebuild(search.text?.toString().orEmpty())
        }
        findViewById<View>(R.id.btn_disable_all).setOnClickListener {
            registry.setAllEnabled(false)
            rebuild(search.text?.toString().orEmpty())
        }

        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                rebuild(s?.toString().orEmpty())
            }
        })

        rebuild("")
    }

    override fun onResume() {
        super.onResume()
        // 返回本页时刷新计数（开关可能被其它入口改动）
        val search = findViewById<EditText>(R.id.search_input)
        rebuild(search.text?.toString().orEmpty())
    }

    private fun rebuild(query: String) {
        val q = query.trim().lowercase()
        val all = DirectEngine.profiles().values
        val built = ArrayList<Row>(all.size + 16)
        var lastCategory: String? = null
        for (p in all) {
            if (q.isNotEmpty() &&
                !p.displayName.lowercase().contains(q) &&
                !p.id.lowercase().contains(q)
            ) {
                continue
            }
            if (p.category != lastCategory) {
                built.add(Row(p.category, null))
                lastCategory = p.category
            }
            built.add(Row(null, p))
        }
        rows = built
        val enabled = registry.enabledProfiles().size
        countText.text = getString(R.string.sm_enabled_count, enabled, all.size)
        findViewById<ListView>(R.id.service_list).adapter = ServiceAdapter()
    }

    private inner class ServiceAdapter : BaseAdapter() {

        private val TYPE_HEADER = 0
        private val TYPE_ITEM = 1

        override fun getCount(): Int = rows.size

        override fun getItem(position: Int): Any = rows[position]

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getItemViewType(position: Int): Int =
            if (rows[position].category != null) TYPE_HEADER else TYPE_ITEM

        override fun getViewTypeCount(): Int = 2

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val row = rows[position]

            if (row.category != null) {
                var v = convertView
                if (v == null) {
                    v = LayoutInflater.from(parent.context)
                        .inflate(R.layout.item_service_header, parent, false)
                }
                v!!.findViewById<TextView>(R.id.header_text).text = row.category
                return v
            }

            val profile = row.profile ?: return convertView ?: View(parent.context)
            var v = convertView
            if (v == null) {
                v = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_service, parent, false)
            }
            v!!.findViewById<TextView>(R.id.svc_name).text = profile.displayName
            v.findViewById<TextView>(R.id.svc_sub).text =
                getString(R.string.sm_rules_count, profile.domains.size) + " · " + profile.id

            val badge = v.findViewById<TextView>(R.id.svc_badge)
            when (profile.verifyStatus) {
                VerifyStatus.VERIFIED -> {
                    badge.text = getString(R.string.badge_verified)
                    badge.setBackgroundResource(R.drawable.bg_badge_green)
                }
                VerifyStatus.NEEDS_VERIFY -> {
                    badge.text = getString(R.string.badge_needs_verify)
                    badge.setBackgroundResource(R.drawable.bg_badge_yellow)
                }
                VerifyStatus.BROKEN -> {
                    badge.text = getString(R.string.badge_broken)
                    badge.setBackgroundResource(R.drawable.bg_badge_red)
                }
            }

            val sw = v.findViewById<Switch>(R.id.svc_switch)
            sw.setOnCheckedChangeListener(null)
            sw.isChecked = registry.isEnabled(profile.id)
            sw.setOnCheckedChangeListener { _, checked ->
                registry.setEnabled(profile.id, checked)
            }
            return v
        }
    }
}

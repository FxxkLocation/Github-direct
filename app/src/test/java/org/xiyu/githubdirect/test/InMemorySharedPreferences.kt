package org.xiyu.githubdirect.test

import android.content.SharedPreferences
import java.util.concurrent.CopyOnWriteArraySet

/** SharedPreferences 的最小内存实现，仅供 JVM 单测同步策略。 */
class InMemorySharedPreferences(initial: Map<String, Any> = emptyMap()) : SharedPreferences {
    private val values = LinkedHashMap<String, Any>(initial)
    private val listeners = CopyOnWriteArraySet<SharedPreferences.OnSharedPreferenceChangeListener>()

    override fun getAll(): MutableMap<String, *> = synchronized(values) { LinkedHashMap(values) }

    override fun getString(key: String?, defValue: String?): String? =
        synchronized(values) { values[key] as? String ?: defValue }

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
        synchronized(values) {
            (values[key] as? Set<String>)?.toMutableSet() ?: defValues?.toMutableSet()
        }

    override fun getInt(key: String?, defValue: Int): Int =
        synchronized(values) { values[key] as? Int ?: defValue }

    override fun getLong(key: String?, defValue: Long): Long =
        synchronized(values) { values[key] as? Long ?: defValue }

    override fun getFloat(key: String?, defValue: Float): Float =
        synchronized(values) { values[key] as? Float ?: defValue }

    override fun getBoolean(key: String?, defValue: Boolean): Boolean =
        synchronized(values) { values[key] as? Boolean ?: defValue }

    override fun contains(key: String?): Boolean = synchronized(values) { values.containsKey(key) }

    override fun edit(): SharedPreferences.Editor = Editor()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) {
        if (listener != null) listeners.add(listener)
    }

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) {
        if (listener != null) listeners.remove(listener)
    }

    private inner class Editor : SharedPreferences.Editor {
        private val updates = LinkedHashMap<String, Any?>()
        private var clear = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor = apply {
            requireNotNull(key)
            updates[key] = value
        }

        override fun putStringSet(
            key: String?,
            values: MutableSet<String>?,
        ): SharedPreferences.Editor = apply {
            requireNotNull(key)
            updates[key] = values?.toSet()
        }

        override fun putInt(key: String?, value: Int): SharedPreferences.Editor = apply {
            requireNotNull(key)
            updates[key] = value
        }

        override fun putLong(key: String?, value: Long): SharedPreferences.Editor = apply {
            requireNotNull(key)
            updates[key] = value
        }

        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = apply {
            requireNotNull(key)
            updates[key] = value
        }

        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = apply {
            requireNotNull(key)
            updates[key] = value
        }

        override fun remove(key: String?): SharedPreferences.Editor = apply {
            requireNotNull(key)
            updates[key] = null
        }

        override fun clear(): SharedPreferences.Editor = apply { clear = true }

        override fun commit(): Boolean {
            val changed = LinkedHashSet<String>()
            synchronized(values) {
                if (clear) {
                    changed.addAll(values.keys)
                    values.clear()
                }
                for ((key, value) in updates) {
                    val previous = values[key]
                    if (value == null) {
                        if (values.remove(key) != null) changed.add(key)
                    } else {
                        values[key] = value
                        if (previous != value) changed.add(key)
                    }
                }
            }
            for (key in changed) {
                for (listener in listeners) listener.onSharedPreferenceChanged(this@InMemorySharedPreferences, key)
            }
            return true
        }

        override fun apply() {
            commit()
        }
    }
}

package org.xiyu.githubdirect.core.dns

/**
 * DoH (RFC 8484) JSON 响应解析：{"Status":0,...,"Answer":[{"type":1,"data":"1.2.3.4"},...]}
 * 基于 core 内置最小 JSON 解析器，纯 JVM。
 */
object DoHJson {

    /** 根 "Status"（0 = NOERROR）；缺省/非法返回 -1。 */
    fun status(json: String): Int {
        val root = Json.parse(json) as? Json.Value.Obj ?: return -1
        val status = root["Status"] as? Json.Value.Num ?: return -1
        return status.value.toInt()
    }

    /**
     * Answer 数组中 (type, data) 列表（A=1 / AAAA=28，CNAME 等跳过）。
     */
    fun answers(json: String): List<Pair<Int, String>> {
        val root = Json.parse(json) as? Json.Value.Obj ?: return emptyList()
        val arr = root["Answer"] as? Json.Value.Arr ?: return emptyList()
        val result = ArrayList<Pair<Int, String>>(arr.list.size)
        for (item in arr.list) {
            val obj = item as? Json.Value.Obj ?: continue
            val type = (obj["type"] as? Json.Value.Num)?.value?.toInt() ?: continue
            if (type != 1 && type != 28) continue
            val data = (obj["data"] as? Json.Value.Str)?.value ?: continue
            result.add(type to data)
        }
        return result
    }
}

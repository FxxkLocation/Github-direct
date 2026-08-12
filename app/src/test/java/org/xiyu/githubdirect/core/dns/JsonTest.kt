package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonTest {

    @Test
    fun `解析对象和字符串`() {
        val v = Json.parse("""{"name":"github","ok":true}""")
        assertTrue(v is Json.Value.Obj)
        val obj = v as Json.Value.Obj
        assertEquals("github", (obj["name"] as Json.Value.Str).value)
        assertTrue(obj["ok"] is Json.Value.True)
    }

    @Test
    fun `解析数组和数字`() {
        val v = Json.parse("""[1, -2, 3.5, 1e2]""")
        assertTrue(v is Json.Value.Arr)
        val arr = v as Json.Value.Arr
        assertEquals(4, arr.list.size)
        assertEquals(1L, (arr.list[0] as Json.Value.Num).value)
        assertEquals(-2L, (arr.list[1] as Json.Value.Num).value)
        assertEquals(3L, (arr.list[2] as Json.Value.Num).value) // 浮点截断
        assertEquals(100L, (arr.list[3] as Json.Value.Num).value)
    }

    @Test
    fun `null和布尔`() {
        val v = Json.parse("""{"a":null,"b":false}""")
        assertTrue((v as Json.Value.Obj)["a"] is Json.Value.Null)
        assertTrue(v["b"] is Json.Value.False)
    }

    @Test
    fun `字符串转义`() {
        val v = Json.parse("""{"s":"a\"b\\c\/dA\n\t"}""")
        val s = ((v as Json.Value.Obj)["s"] as Json.Value.Str).value
        assertEquals("a\"b\\c/dA\n\t", s)
    }

    @Test
    fun `嵌套结构`() {
        val json = """{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4","ttl":300}]}"""
        val obj = Json.parse(json) as Json.Value.Obj
        assertEquals(0L, (obj["Status"] as Json.Value.Num).value)
        val answer = (obj["Answer"] as Json.Value.Arr).list[0] as Json.Value.Obj
        assertEquals(1L, (answer["type"] as Json.Value.Num).value)
        assertEquals("1.2.3.4", (answer["data"] as Json.Value.Str).value)
    }

    @Test
    fun `非法输入返回null`() {
        assertNull(Json.parse(""))
        assertNull(Json.parse("{"))
        assertNull(Json.parse("""{"a":}"""))
        assertNull(Json.parse("""[1,2] extra"""))
        assertNull(Json.parse("garbage"))
        assertNull(Json.parse("""{"a":"unterminated}"""))
    }

    @Test
    fun `unicode转义`() {
        val v = Json.parse("""{"s":"中文"}""")
        assertEquals("中文", ((v as Json.Value.Obj)["s"] as Json.Value.Str).value)
    }

    @Test
    fun `空白容忍`() {
        val v = Json.parse("""  { "a" : 1 , "b" : [ ] }  """)
        assertTrue(v is Json.Value.Obj)
        assertTrue(((v as Json.Value.Obj)["b"] as Json.Value.Arr).list.isEmpty())
    }
}

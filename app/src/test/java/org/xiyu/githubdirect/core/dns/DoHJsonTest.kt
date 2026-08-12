package org.xiyu.githubdirect.core.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DoHJsonTest {

    @Test
    fun `解析Status和Answer`() {
        val json = """{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"},{"type":28,"data":"::1"}]}"""
        assertEquals(0, DoHJson.status(json))
        val answers = DoHJson.answers(json)
        assertEquals(2, answers.size)
        assertEquals(1 to "1.2.3.4", answers[0])
        assertEquals(28 to "::1", answers[1])
    }

    @Test
    fun `CNAME和未知类型被跳过`() {
        val json = """{"Status":0,"Answer":[
            {"type":5,"data":"cname.example.com"},
            {"type":1,"data":"9.9.9.9"},
            {"type":99,"data":"x"}
        ]}"""
        val answers = DoHJson.answers(json)
        assertEquals(1, answers.size)
        assertEquals(1 to "9.9.9.9", answers[0])
    }

    @Test
    fun `缺省Status返回负一`() {
        assertEquals(-1, DoHJson.status("{}"))
        assertEquals(-1, DoHJson.status("not json"))
        assertEquals(-1, DoHJson.status("""{"Status":"0"}""")) // 类型不符
    }

    @Test
    fun `缺省Answer返回空`() {
        assertTrue(DoHJson.answers("{}").isEmpty())
        assertTrue(DoHJson.answers("""{"Status":0}""").isEmpty())
        assertTrue(DoHJson.answers("[]").isEmpty())
    }

    @Test
    fun `嵌套对象深度解析`() {
        val json = """{"Status":0,"Answer":[{"type":1,"data":"140.82.112.3","ttl":300}]}"""
        assertEquals(0, DoHJson.status(json))
        assertEquals(1 to "140.82.112.3", DoHJson.answers(json)[0])
    }
}

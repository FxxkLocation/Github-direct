package org.xiyu.githubdirect.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RuleCatalogCandidatePoolTest {

    @Test
    fun `候选池只接受受限引用名`() {
        val catalog = RuleCatalog.load(
            """{
              "profiles": [{
                "id": "test",
                "domains": [
                  {
                    "id": "safe",
                    "match": {"type": "EXACT", "value": "safe.example"},
                    "transport": "CLEAN_DNS",
                    "candidatePool": "edge.pool-1",
                    "echConfigDomain": "cloudflare-ech.com"
                  },
                  {
                    "id": "unsafe",
                    "match": {"type": "EXACT", "value": "unsafe.example"},
                    "transport": "CLEAN_DNS",
                    "candidatePool": "../../unbounded pool",
                    "echConfigDomain": "../../invalid"
                  }
                ]
              }]
            }""",
        )

        val rules = catalog.getValue("test").domains.associateBy { it.id }
        assertEquals("edge.pool-1", rules.getValue("safe").candidatePool)
        assertEquals("cloudflare-ech.com", rules.getValue("safe").echConfigDomain)
        assertNull(rules.getValue("unsafe").candidatePool)
        assertNull(rules.getValue("unsafe").echConfigDomain)
    }
}

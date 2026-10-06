package com.github.lechandonga.threatintelmatchingjava.tests;

import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;
import com.github.lechandonga.threatintelmatchingjava.service.dto.VerdictResponse;
import com.github.lechandonga.threatintelmatchingjava.support.TestSupport;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * 业务2：同一指标多来源合并、撤回只撤回无其它来源支撑的指标、重复导入幂等。
 */
class MergeWithdrawIdempotencyTest {

    private final String docA = TestSupport.flatDoc("source-a",
            TestSupport.flatRecord("ip", "203.0.113.10", "malicious", 90,
                    "2026-10-05T00:00:00Z", false));
    private final String docB = TestSupport.flatDoc("source-b",
            TestSupport.flatRecord("ip", "203.0.113.10", "suspicious", 70,
                    "2026-10-05T00:00:00Z", false));

    private IntelService service() {
        return TestSupport.newService(TestSupport.fixedClock(), 7, null);
    }

    @Test
    void sameIndicatorFromTwoSourcesMergesAndKeepsBoth() {
        IntelService service = service();
        service.importFeed("flat", docA);
        ImportResult second = service.importFeed("flat", docB);

        assertEquals(1, second.accepted());
        VerdictResponse response = service.query("ip", "203.0.113.10");
        assertEquals(2, response.sources().size(), "两个来源信息都要保留");
        assertEquals("MALICIOUS", response.verdict());
        assertEquals("source-a", response.decidingSource());
    }

    @Test
    void duplicateImportIsIdempotent() {
        IntelService service = service();
        service.importFeed("flat", docA);
        ImportResult again = service.importFeed("flat", docA);
        ImportResult andAgain = service.importFeed("flat", docA);

        assertEquals(0, again.accepted());
        assertEquals(1, again.unchanged());
        assertEquals(0, andAgain.accepted());
        assertEquals(1, andAgain.unchanged());

        VerdictResponse response = service.query("ip", "203.0.113.10");
        assertEquals(1, response.sources().size());
        assertEquals(1, response.sources().get(0).revision(), "重复导入不增加版本号");
    }

    @Test
    void changedRecordFromSameSourceUpdatesRevision() {
        IntelService service = service();
        service.importFeed("flat", docA);
        String updated = TestSupport.flatDoc("source-a",
                TestSupport.flatRecord("ip", "203.0.113.10", "malicious", 95,
                        "2026-10-05T06:00:00Z", false));
        ImportResult result = service.importFeed("flat", updated);
        assertEquals(1, result.accepted());
        VerdictResponse response = service.query("ip", "203.0.113.10");
        assertEquals(95, response.sources().get(0).rawConfidence());
        assertEquals(2, response.sources().get(0).revision());
    }

    @Test
    void revokeOneSourceKeepsIndicatorWhenOtherSourcesRemain() {
        IntelService service = service();
        service.importFeed("flat", docA);
        service.importFeed("flat", docB);

        String revokeA = TestSupport.flatDoc("source-a",
                TestSupport.flatRecord("ip", "203.0.113.10", "malicious", 90,
                        "2026-10-05T00:00:00Z", true));
        ImportResult result = service.importFeed("flat", revokeA);

        assertEquals(1, result.revoked());
        VerdictResponse response = service.query("ip", "203.0.113.10");
        assertTrueFoundWithOnlySourceB(response);
    }

    @Test
    void revokeLastSourceRemovesIndicator() {
        IntelService service = service();
        service.importFeed("flat", docA);

        String revokeA = TestSupport.flatDoc("source-a",
                TestSupport.flatRecord("ip", "203.0.113.10", "malicious", 90,
                        "2026-10-05T00:00:00Z", true));
        ImportResult result = service.importFeed("flat", revokeA);
        assertEquals(1, result.revoked());

        VerdictResponse response = service.query("ip", "203.0.113.10");
        assertFalse(response.found(), "没有其它来源支撑时指标应被移除");
        assertEquals("HARMLESS", response.verdict());
    }

    @Test
    void revokingAbsentObservationIsCountedButChangesNothing() {
        IntelService service = service();
        service.importFeed("flat", docA);
        String revokeB = TestSupport.flatDoc("source-b",
                TestSupport.flatRecord("ip", "203.0.113.10", "suspicious", 70,
                        "2026-10-05T00:00:00Z", true));
        ImportResult result = service.importFeed("flat", revokeB);
        assertEquals(1, result.alreadyAbsent());
        assertEquals(1, service.query("ip", "203.0.113.10").sources().size());
    }

    @Test
    void stixRevokedIndicatorWithdrawsSourceObservation() {
        IntelService service = service();
        String stix = """
                {"x_source":"stix-a","objects":[
                  {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.7']",
                   "confidence":90,"labels":["malicious"],
                   "created":"2026-10-05T00:00:00Z","modified":"2026-10-05T00:00:00Z"}]}
                """;
        service.importFeed("stix", stix);

        String revoke = """
                {"x_source":"stix-a","objects":[
                  {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.7']",
                   "revoked":true,
                   "created":"2026-10-05T00:00:00Z","modified":"2026-10-05T01:00:00Z"}]}
                """;
        ImportResult result = service.importFeed("stix", revoke);
        assertEquals(1, result.revoked());
        assertFalse(service.query("ip", "198.51.100.7").found());
    }

    @Test
    void canonicalNormalizationMergesEquivalentValues() {
        IntelService service = service();
        service.importFeed("flat", TestSupport.flatDoc("s1",
                TestSupport.flatRecord("domain", "WWW.Example.COM.", "malicious", 90,
                        "2026-10-05T00:00:00Z", false)));
        service.importFeed("flat", TestSupport.flatDoc("s2",
                TestSupport.flatRecord("domain", "www.example.com", "malicious", 80,
                        "2026-10-05T00:00:00Z", false)));
        VerdictResponse response = service.query("domain", "WWW.example.com");
        assertEquals("www.example.com", response.value());
        assertEquals(2, response.sources().size());
    }

    private static void assertTrueFoundWithOnlySourceB(VerdictResponse response) {
        assertEquals(1, response.sources().size());
        assertEquals("source-b", response.sources().get(0).source());
    }
}

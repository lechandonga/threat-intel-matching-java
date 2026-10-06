package com.github.lechandonga.threatintelmatchingjava.tests;

import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;
import com.github.lechandonga.threatintelmatchingjava.service.dto.VerdictResponse;
import com.github.lechandonga.threatintelmatchingjava.support.TestSupport;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务3：冲突固定裁决、置信度时间衰减、白名单优先，以及与导入顺序无关。
 */
class VerdictAdjudicationTest {

    @Test
    void conflictResolvedByMaxDecayedConfidenceThenWeightThenName() {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        String highConfBenign = TestSupport.flatDoc("z-benign",
                TestSupport.flatRecord("ip", "203.0.113.20", "benign", 100,
                        "2026-10-06T00:00:00Z", false));
        String lowConfMalicious = TestSupport.flatDoc("a-malware",
                TestSupport.flatRecord("ip", "203.0.113.20", "malicious", 40,
                        "2026-10-06T00:00:00Z", false));

        service.importFeed("flat", highConfBenign);
        service.importFeed("flat", lowConfMalicious);
        VerdictResponse response = service.query("ip", "203.0.113.20");
        assertEquals("z-benign", response.decidingSource(), "有效置信度最高者胜出");
        assertEquals("HARMLESS", response.verdict());
    }

    @Test
    void tieOnConfidenceBrokenByWeightThenSourceNameOrderIndependently() {
        String docX = TestSupport.flatDoc("source-x",
                TestSupport.flatRecord("ip", "203.0.113.21", "suspicious", 80,
                        "2026-10-06T00:00:00Z", false));
        String docY = TestSupport.flatDoc("source-y",
                TestSupport.flatRecord("ip", "203.0.113.21", "malicious", 80,
                        "2026-10-06T00:00:00Z", false));

        VerdictResponse firstOrder = verdictWithImportOrder("203.0.113.21", docX, docY);
        VerdictResponse reverseOrder = verdictWithImportOrder("203.0.113.21", docY, docX);

        assertEquals("source-y", firstOrder.decidingSource(), "置信度平分时按结论权重裁决");
        assertEquals("source-y", reverseOrder.decidingSource(), "换导入顺序结论必须一致");
        assertEquals(firstOrder.verdict(), reverseOrder.verdict());
    }

    @Test
    void nameTieBreakIsAlphabeticalAndStable() {
        String docAlpha = TestSupport.flatDoc("alpha",
                TestSupport.flatRecord("ip", "203.0.113.22", "malicious", 80,
                        "2026-10-06T00:00:00Z", false));
        String docBeta = TestSupport.flatDoc("beta",
                TestSupport.flatRecord("ip", "203.0.113.22", "malicious", 80,
                        "2026-10-06T00:00:00Z", false));

        assertEquals("alpha",
                verdictWithImportOrder("203.0.113.22", docBeta, docAlpha).decidingSource());
        assertEquals("alpha",
                verdictWithImportOrder("203.0.113.22", docAlpha, docBeta).decidingSource());
    }

    @Test
    void confidenceDecaysWithHalfLife() {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        service.importFeed("flat", TestSupport.flatDoc("s",
                TestSupport.flatRecord("ip", "203.0.113.23", "malicious", 100,
                        "2026-09-29T00:00:00Z", false)));
        VerdictResponse weekOne = service.query("ip", "203.0.113.23");
        assertEquals(0.5, weekOne.sources().get(0).decayedConfidence(), 0.0001,
                "恰好一个半衰期，置信度减半");
        assertEquals(0.5, weekOne.sources().get(0).score(), 0.0001);
        assertEquals("SUSPICIOUS", weekOne.verdict(), "0.5 落在可疑区间");

        IntelService old = TestSupport.newService(
                Clock.fixed(Instant.parse("2026-10-20T00:00:00Z"), ZoneOffset.UTC), 7, null);
        old.importFeed("flat", TestSupport.flatDoc("s",
                TestSupport.flatRecord("ip", "203.0.113.23", "malicious", 100,
                        "2026-09-29T00:00:00Z", false)));
        VerdictResponse threeWeeks = old.query("ip", "203.0.113.23");
        assertEquals(0.125, threeWeeks.sources().get(0).decayedConfidence(), 0.0001);
        assertEquals("HARMLESS", threeWeeks.verdict(), "三个半衰期后分数 0.125，低于可疑阈值");
    }

    @Test
    void verdictThresholdsMapToMaliciousSuspiciousHarmless() {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        service.importFeed("flat", TestSupport.flatDoc("s",
                TestSupport.flatRecord("ip", "203.0.113.24", "malicious", 80,
                        "2026-10-06T00:00:00Z", false)));
        assertEquals("MALICIOUS", service.query("ip", "203.0.113.24").verdict());

        IntelService suspicious = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        suspicious.importFeed("flat", TestSupport.flatDoc("s",
                TestSupport.flatRecord("ip", "203.0.113.25", "malicious", 50,
                        "2026-10-06T00:00:00Z", false)));
        assertEquals("SUSPICIOUS", suspicious.query("ip", "203.0.113.25").verdict());

        IntelService harmless = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        harmless.importFeed("flat", TestSupport.flatDoc("s",
                TestSupport.flatRecord("ip", "203.0.113.26", "benign", 100,
                        "2026-10-06T00:00:00Z", false)));
        assertEquals("HARMLESS", harmless.query("ip", "203.0.113.26").verdict());
    }

    @Test
    void whitelistOverridesMaliciousHitButKeepsEvidence() {
        Path whitelistFile = Path.of("data/whitelist.txt");
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, whitelistFile);
        service.importFeed("flat", TestSupport.flatDoc("s",
                TestSupport.flatRecord("ip", "8.8.8.8", "malicious", 100,
                        "2026-10-06T00:00:00Z", false)));

        VerdictResponse response = service.query("ip", "8.8.8.8");
        assertEquals("HARMLESS", response.verdict(), "白名单优先判无害");
        assertTrue(response.whitelisted());
        assertEquals("WHITELIST_PRIORITY", response.decidingRule());
        assertEquals(1, response.sources().size(), "原始命中证据仍保留可追溯");
    }

    @Test
    void queryResponseIsTraceableWithSourceConfidenceAndTimes() {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        ImportResult result = service.importFeed("stix", """
                {"x_source":"stix-a","objects":[
                  {"type":"indicator","pattern":"[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                   "confidence":77,"labels":["malicious"],
                   "created":"2026-10-03T00:00:00Z","modified":"2026-10-04T00:00:00Z"}]}
                """);
        assertEquals(1, result.accepted());

        VerdictResponse response = service.query(
                "md5", "d41d8cd98f00b204e9800998ecf8427e");
        assertEquals("HASH_MD5", response.type());
        assertEquals("stix-a", response.sources().get(0).source());
        assertEquals("MALICIOUS", response.sources().get(0).disposition());
        assertEquals(77, response.sources().get(0).rawConfidence());
        assertEquals(Instant.parse("2026-10-04T00:00:00Z"), response.sources().get(0).observedAt());
        assertEquals(TestSupport.NOW, response.evaluatedAt());
        assertEquals(7.0, response.halfLifeDays());
    }

    private static VerdictResponse verdictWithImportOrder(String ip, String firstDoc, String secondDoc) {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        service.importFeed("flat", firstDoc);
        service.importFeed("flat", secondDoc);
        return service.query("ip", ip);
    }
}

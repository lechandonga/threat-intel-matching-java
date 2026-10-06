package com.github.lechandonga.threatintelmatchingjava.tests;

import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.model.RejectReason;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;
import com.github.lechandonga.threatintelmatchingjava.support.TestSupport;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务1：坏数据不能静默跳过、不能拖垮整批，且拒绝原因可区分。
 */
class BadDataRejectionTest {

    private IntelService service() {
        return TestSupport.newService(TestSupport.fixedClock(), 7, null);
    }

    @Test
    void flatBatchKeepsGoodRowsAndReportsDistinctReasons() {
        String good = TestSupport.flatRecord("ip", "203.0.113.1", "malicious", 80,
                "2026-10-01T00:00:00Z", false);
        String badIp = TestSupport.flatRecord("ip", "999.1.1.1", "malicious", 80,
                "2026-10-01T00:00:00Z", false);
        String badDomain = TestSupport.flatRecord("domain", "not_a_domain!!", "malicious", 80,
                "2026-10-01T00:00:00Z", false);
        String badHash = TestSupport.flatRecord("sha256", "zzz", "malicious", 80,
                "2026-10-01T00:00:00Z", false);
        String badDisposition = TestSupport.flatRecord("ip", "203.0.113.2", "maybe", 80,
                "2026-10-01T00:00:00Z", false);
        String badConfidenceRange = TestSupport.flatRecord("ip", "203.0.113.3", "malicious", 150,
                "2026-10-01T00:00:00Z", false);
        String badTime = TestSupport.flatRecord("ip", "203.0.113.4", "malicious", 80,
                "not-a-time", false);

        String doc = TestSupport.flatDoc("src1", good, badIp, badDomain, badHash,
                badDisposition, badConfidenceRange, badTime);

        ImportResult result = service().importFeed("flat", doc);

        assertEquals(1, result.accepted(), "好记录照常接受");
        assertEquals(6, result.rejected().size(), "6 条坏数据全部给出拒绝原因，无静默跳过");
        Map<RejectReason, Long> counts = result.rejected().stream()
                .collect(Collectors.groupingBy(r -> r.reason(), Collectors.counting()));
        assertEquals(1L, counts.get(RejectReason.MALFORMED_IP));
        assertEquals(1L, counts.get(RejectReason.MALFORMED_DOMAIN));
        assertEquals(1L, counts.get(RejectReason.MALFORMED_HASH));
        assertEquals(1L, counts.get(RejectReason.UNSUPPORTED_DISPOSITION));
        assertEquals(1L, counts.get(RejectReason.CONFIDENCE_OUT_OF_RANGE));
        assertEquals(1L, counts.get(RejectReason.MALFORMED_TIME));
        assertEquals(7, result.totalInBatch());
    }

    @Test
    void missingFieldsAreRejectedIndividually() {
        String noValue = "{\"indicator_type\":\"ip\",\"disposition\":\"malicious\","
                + "\"confidence\":80,\"observed_at\":\"2026-10-01T00:00:00Z\"}";
        String noConfidence = "{\"indicator_type\":\"ip\",\"value\":\"203.0.113.9\","
                + "\"disposition\":\"malicious\",\"observed_at\":\"2026-10-01T00:00:00Z\"}";
        String noSourceDoc = "{\"records\":["
                + "{\"indicator_type\":\"ip\",\"value\":\"203.0.113.9\",\"disposition\":\"malicious\","
                + "\"confidence\":80,\"observed_at\":\"2026-10-01T00:00:00Z\"}]}";

        ImportResult result = service().importFeed("flat",
                TestSupport.flatDoc("src1", noValue, noConfidence));
        assertEquals(0, result.accepted());
        assertEquals(RejectReason.MISSING_VALUE, result.rejected().get(0).reason());
        assertEquals(RejectReason.MISSING_CONFIDENCE, result.rejected().get(1).reason());

        ImportResult noSourceResult = service().importFeed("flat", noSourceDoc);
        assertEquals(RejectReason.MISSING_SOURCE, noSourceResult.rejected().get(0).reason());
    }

    @Test
    void malformedDocumentDoesNotThrowAndBatchSurvives() {
        ImportResult notJson = service().importFeed("flat", "this is not json");
        assertEquals(1, notJson.rejected().size());
        assertEquals(RejectReason.DOCUMENT_NOT_OBJECT, notJson.rejected().get(0).reason());

        ImportResult missingRecords = service().importFeed("flat", "{\"source\":\"x\"}");
        assertEquals(RejectReason.MISSING_RECORDS, missingRecords.rejected().get(0).reason());
    }

    @Test
    void stixBadPatternAndUnknownLabelsAreRejected() {
        String doc = """
                {
                  "x_source": "stix1",
                  "objects": [
                    {"type":"indicator","pattern":"[email-message:from_ref.value = 'a@b.com']",
                     "confidence":80,"labels":["malicious"],
                     "created":"2026-10-01T00:00:00Z","modified":"2026-10-01T00:00:00Z"},
                    {"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.5']",
                     "confidence":80,"labels":["unclassified"],
                     "created":"2026-10-01T00:00:00Z","modified":"2026-10-01T00:00:00Z"},
                    {"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.6']",
                     "confidence":80,"labels":["malicious"],
                     "created":"2026-10-01T00:00:00Z","modified":"2026-10-01T00:00:00Z"}
                  ]
                }
                """;
        ImportResult result = service().importFeed("stix", doc);
        assertEquals(1, result.accepted());
        assertEquals(RejectReason.UNSUPPORTED_PATTERN, result.rejected().get(0).reason());
        assertEquals(RejectReason.MISSING_DISPOSITION, result.rejected().get(1).reason());
    }

    @Test
    void invalidValuesAreRejectedForEveryIndicatorKind() {
        String ip = TestSupport.flatRecord("ip", "1.2.3", "malicious", 50,
                "2026-10-01T00:00:00Z", false);
        String domain = TestSupport.flatRecord("domain", "bad..domain", "malicious", 50,
                "2026-10-01T00:00:00Z", false);
        String md5 = TestSupport.flatRecord("md5", "deadbeef", "malicious", 50,
                "2026-10-01T00:00:00Z", false);
        String sha1WrongLen = TestSupport.flatRecord("sha1", "ab", "malicious", 50,
                "2026-10-01T00:00:00Z", false);

        ImportResult result = service().importFeed("flat",
                TestSupport.flatDoc("src1", ip, domain, md5, sha1WrongLen));
        assertEquals(0, result.accepted());
        assertEquals(4, result.rejected().size());
        assertTrue(result.rejected().stream()
                .allMatch(r -> r.reason() == RejectReason.MALFORMED_IP
                        || r.reason() == RejectReason.MALFORMED_DOMAIN
                        || r.reason() == RejectReason.MALFORMED_HASH));
    }
}

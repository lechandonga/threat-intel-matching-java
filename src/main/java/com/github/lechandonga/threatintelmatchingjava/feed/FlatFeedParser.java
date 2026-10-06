package com.github.lechandonga.threatintelmatchingjava.feed;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatintelmatchingjava.model.Disposition;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;
import com.github.lechandonga.threatintelmatchingjava.model.ParsedEntry;
import com.github.lechandonga.threatintelmatchingjava.model.RejectReason;
import com.github.lechandonga.threatintelmatchingjava.model.RejectedRecord;
import com.github.lechandonga.threatintelmatchingjava.normalize.IndicatorNormalizer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 扁平厂商 Feed 解析器。文档形如：
 * <pre>
 * {
 *   "source": "vendor-a",
 *   "records": [
 *     {"indicator_type":"ip","value":"8.8.8.8","disposition":"malicious",
 *      "confidence":90,"observed_at":"2026-10-01T08:00:00Z","revoked":false}
 *   ]
 * }
 * </pre>
 * 每条记录可自带 "source" 覆盖文档级来源；indicator_type=hash 时按值长度推断哈希算法。
 */
public class FlatFeedParser implements FeedParser {

    private final ObjectMapper mapper;

    public FlatFeedParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String format() {
        return "flat";
    }

    @Override
    public ParseOutcome parse(String document) {
        List<ParsedEntry> entries = new ArrayList<>();
        List<RejectedRecord> rejected = new ArrayList<>();
        JsonNode root;
        try {
            root = mapper.readTree(document);
        } catch (Exception e) {
            rejected.add(FeedSupport.reject(-1, FeedSupport.snippet(document, 120),
                    RejectReason.DOCUMENT_NOT_OBJECT, "JSON 解析失败: " + e.getMessage()));
            return new ParseOutcome(entries, rejected);
        }
        if (root == null || !root.isObject()) {
            rejected.add(FeedSupport.reject(-1, FeedSupport.snippet(document, 120),
                    RejectReason.DOCUMENT_NOT_OBJECT, "文档根节点必须是 JSON 对象"));
            return new ParseOutcome(entries, rejected);
        }
        JsonNode recordsNode = root.get("records");
        if (recordsNode == null) {
            rejected.add(FeedSupport.reject(-1, FeedSupport.snippet(document, 120),
                    RejectReason.MISSING_RECORDS, "缺少 records 数组"));
            return new ParseOutcome(entries, rejected);
        }
        if (!recordsNode.isArray()) {
            rejected.add(FeedSupport.reject(-1, FeedSupport.snippet(document, 120),
                    RejectReason.RECORDS_NOT_ARRAY, "records 必须是数组"));
            return new ParseOutcome(entries, rejected);
        }
        String docSource = FeedSupport.text(root, "source");
        int index = 0;
        for (JsonNode node : recordsNode) {
            ParsedEntry entry = parseRecord(index, node, docSource, rejected);
            if (entry != null) {
                entries.add(entry);
            }
            index++;
        }
        return new ParseOutcome(entries, rejected);
    }

    private ParsedEntry parseRecord(int index, JsonNode node, String docSource, List<RejectedRecord> rejected) {
        if (node == null || !node.isObject()) {
            rejected.add(FeedSupport.reject(index, String.valueOf(node),
                    RejectReason.RECORD_NOT_OBJECT, "数组元素必须是 JSON 对象"));
            return null;
        }
        String raw = node.toString();
        String source = FeedSupport.text(node, "source");
        if (source == null) {
            source = docSource;
        }
        if (source == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.MISSING_SOURCE,
                    "记录与文档均未提供 source"));
            return null;
        }

        String typeRaw = FeedSupport.text(node, "indicator_type");
        if (typeRaw == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.MISSING_TYPE, "缺少 indicator_type"));
            return null;
        }
        IndicatorType type = TypeMapping.fromFlat(typeRaw);
        if (type == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.UNSUPPORTED_TYPE,
                    "indicator_type=" + typeRaw));
            return null;
        }

        String valueRaw = FeedSupport.text(node, "value");
        if (valueRaw == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.MISSING_VALUE, "缺少 value"));
            return null;
        }
        IndicatorType effectiveType = type;
        String value = IndicatorNormalizer.normalize(effectiveType, valueRaw);
        if (value == null && typeRaw.equalsIgnoreCase("hash")) {
            IndicatorType inferred = TypeMapping.inferHashType(valueRaw);
            if (inferred != null) {
                effectiveType = inferred;
                value = IndicatorNormalizer.normalize(effectiveType, valueRaw);
            }
        }
        if (value == null) {
            rejected.add(FeedSupport.reject(index, raw, valueReason(typeRaw), "value=" + valueRaw));
            return null;
        }

        String dispositionRaw = FeedSupport.text(node, "disposition");
        if (dispositionRaw == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.MISSING_DISPOSITION, "缺少 disposition"));
            return null;
        }
        Disposition disposition = DispositionMapping.fromFlat(dispositionRaw);
        if (disposition == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.UNSUPPORTED_DISPOSITION,
                    "disposition=" + dispositionRaw));
            return null;
        }

        JsonNode confidenceNode = node.get("confidence");
        if (confidenceNode == null || confidenceNode.isNull()) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.MISSING_CONFIDENCE, "缺少 confidence"));
            return null;
        }
        if (!confidenceNode.isNumber()) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.CONFIDENCE_NOT_NUMBER,
                    "confidence=" + confidenceNode));
            return null;
        }
        double confidenceDouble = confidenceNode.asDouble();
        if (confidenceDouble < 0 || confidenceDouble > 100) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.CONFIDENCE_OUT_OF_RANGE,
                    "confidence=" + confidenceDouble));
            return null;
        }

        String timeRaw = FeedSupport.text(node, "observed_at");
        Instant observedAt = IndicatorNormalizer.parseTime(timeRaw);
        if (observedAt == null) {
            RejectReason reason = timeRaw == null ? RejectReason.MISSING_TIME : RejectReason.MALFORMED_TIME;
            rejected.add(FeedSupport.reject(index, raw, reason, "observed_at=" + timeRaw));
            return null;
        }

        boolean revoked = node.path("revoked").asBoolean(false);
        return new ParsedEntry(source, effectiveType, value, disposition,
                (int) Math.round(confidenceDouble), observedAt, revoked);
    }

    private static RejectReason valueReason(String typeRaw) {
        return switch (typeRaw.toLowerCase()) {
            case "ip", "ipv4", "ipv6" -> RejectReason.MALFORMED_IP;
            case "domain", "hostname" -> RejectReason.MALFORMED_DOMAIN;
            default -> RejectReason.MALFORMED_HASH;
        };
    }
}

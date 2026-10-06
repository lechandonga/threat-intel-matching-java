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
import java.util.Iterator;
import java.util.List;

/**
 * STIX 2.x Bundle 解析器。文档形如：
 * <pre>
 * {
 *   "type": "bundle",
 *   "id": "bundle--...",
 *   "x_source": "stix-source-a",
 *   "objects": [
 *     {"type":"indicator","id":"indicator--...",
 *      "pattern":"[ipv4-addr:value = '8.8.8.8']",
 *      "confidence":80,"labels":["malicious"],
 *      "created":"2026-10-01T08:00:00Z","modified":"2026-10-01T08:00:00Z"}
 *   ]
 * }
 * </pre>
 * 来源解析顺序：indicator.x_source → indicator.created_by_ref（去掉 identity-- 前缀）
 * → bundle.x_source → bundle.id。撤回使用 STIX 标准字段 "revoked": true。
 */
public class StixFeedParser implements FeedParser {

    private final ObjectMapper mapper;

    public StixFeedParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String format() {
        return "stix";
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
        JsonNode objects = root.get("objects");
        if (objects == null) {
            rejected.add(FeedSupport.reject(-1, FeedSupport.snippet(document, 120),
                    RejectReason.MISSING_RECORDS, "缺少 objects 数组"));
            return new ParseOutcome(entries, rejected);
        }
        if (!objects.isArray()) {
            rejected.add(FeedSupport.reject(-1, FeedSupport.snippet(document, 120),
                    RejectReason.RECORDS_NOT_ARRAY, "objects 必须是数组"));
            return new ParseOutcome(entries, rejected);
        }
        String bundleSource = firstNonBlank(FeedSupport.text(root, "x_source"),
                stripPrefix(FeedSupport.text(root, "id"), "bundle--"));
        int index = 0;
        for (JsonNode node : objects) {
            if (node != null && node.isObject() && !"indicator".equals(FeedSupport.text(node, "type"))) {
                index++;
                continue;
            }
            ParsedEntry entry = parseIndicator(index, node, bundleSource, rejected);
            if (entry != null) {
                entries.add(entry);
            }
            index++;
        }
        return new ParseOutcome(entries, rejected);
    }

    private ParsedEntry parseIndicator(int index, JsonNode node, String bundleSource,
                                       List<RejectedRecord> rejected) {
        if (node == null || !node.isObject()) {
            rejected.add(FeedSupport.reject(index, String.valueOf(node),
                    RejectReason.RECORD_NOT_OBJECT, "数组元素必须是 JSON 对象"));
            return null;
        }
        String raw = node.toString();
        if (!"indicator".equals(FeedSupport.text(node, "type"))) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.STIX_OBJECT_NOT_INDICATOR,
                    "type=" + FeedSupport.text(node, "type")));
            return null;
        }

        String source = firstNonBlank(FeedSupport.text(node, "x_source"),
                stripPrefix(FeedSupport.text(node, "created_by_ref"), "identity--"),
                bundleSource);
        if (source == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.MISSING_SOURCE,
                    "indicator 与 bundle 均无法确定来源"));
            return null;
        }

        boolean revoked = node.path("revoked").asBoolean(false);

        String expression = FeedSupport.text(node, "pattern");
        if (expression == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.UNSUPPORTED_PATTERN, "缺少 pattern"));
            return null;
        }
        StixPattern.Extracted extracted = StixPattern.extract(expression);
        if (extracted == null) {
            rejected.add(FeedSupport.reject(index, raw, RejectReason.UNSUPPORTED_PATTERN, expression));
            return null;
        }
        IndicatorType type = extracted.type();
        String value = IndicatorNormalizer.normalize(type, extracted.value());
        if (value == null) {
            RejectReason reason = switch (type) {
                case IP -> RejectReason.MALFORMED_IP;
                case DOMAIN -> RejectReason.MALFORMED_DOMAIN;
                default -> RejectReason.MALFORMED_HASH;
            };
            rejected.add(FeedSupport.reject(index, raw, reason, "pattern 中的值=" + extracted.value()));
            return null;
        }

        Disposition disposition = null;
        if (!revoked) {
            List<String> labels = new ArrayList<>();
            JsonNode labelsNode = node.get("labels");
            if (labelsNode != null && labelsNode.isArray()) {
                for (JsonNode label : labelsNode) {
                    labels.add(label.asText());
                }
            }
            labels.add(FeedSupport.text(node, "x_disposition") == null
                    ? "" : FeedSupport.text(node, "x_disposition"));
            disposition = DispositionMapping.fromStixLabels(labels);
            if (disposition == null) {
                rejected.add(FeedSupport.reject(index, raw, RejectReason.MISSING_DISPOSITION,
                        "labels 中没有可识别的结论（malicious/suspicious/benign）"));
                return null;
            }
        }

        JsonNode confidenceNode = node.get("confidence");
        int confidence = 0;
        if (!revoked) {
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
            confidence = (int) Math.round(confidenceDouble);
        }

        String timeRaw = firstNonBlank(FeedSupport.text(node, "modified"), FeedSupport.text(node, "created"));
        Instant observedAt = IndicatorNormalizer.parseTime(timeRaw);
        if (observedAt == null) {
            RejectReason reason = timeRaw == null ? RejectReason.MISSING_TIME : RejectReason.MALFORMED_TIME;
            rejected.add(FeedSupport.reject(index, raw, reason, "modified/created=" + timeRaw));
            return null;
        }

        return new ParsedEntry(source, type, value,
                disposition == null ? Disposition.BENIGN : disposition,
                confidence, observedAt, revoked);
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static String stripPrefix(String value, String prefix) {
        if (value == null) {
            return null;
        }
        return value.startsWith(prefix) ? value.substring(prefix.length()) : value;
    }
}

package com.github.lechandonga.threatintelmatchingjava.feed;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatintelmatchingjava.normalize.RawIndicatorRecord;

import java.util.ArrayList;
import java.util.List;

/**
 * Parser for a STIX-bundle-like local JSON feed:
 * <pre>
 * {
 *   "sourceId": "vendor-alpha",
 *   "indicators": [
 *     {"id":"a-1","type":"ipv4-addr","value":"10.0.0.1",
 *      "verdict":"malicious","confidence":0.9,"observedAt":"2026-10-01T00:00:00Z"}
 *   ]
 * }
 * </pre>
 */
public class StixJsonFeedParser implements FeedParser {

    private final ObjectMapper objectMapper;

    public StixJsonFeedParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public List<RawIndicatorRecord> parse(String content) throws FeedParseException {
        JsonNode root;
        try {
            root = objectMapper.readTree(content);
        } catch (Exception e) {
            throw new FeedParseException("feed is not valid JSON: " + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new FeedParseException("feed root must be a JSON object");
        }
        String sourceId = textOrNull(root.get("sourceId"));
        if (sourceId == null) {
            throw new FeedParseException("feed is missing top-level sourceId");
        }
        JsonNode indicators = root.get("indicators");
        if (indicators == null || !indicators.isArray()) {
            throw new FeedParseException("feed is missing an 'indicators' array");
        }
        List<RawIndicatorRecord> rows = new ArrayList<>();
        for (JsonNode node : indicators) {
            rows.add(new RawIndicatorRecord(
                    sourceId,
                    textOrNull(node.get("id")),
                    textOrNull(node.get("type")),
                    textOrNull(node.get("value")),
                    textOrNull(node.get("verdict")),
                    textOrNull(node.get("confidence")),
                    textOrNull(node.get("observedAt"))));
        }
        return rows;
    }

    private String textOrNull(JsonNode node) {
        return node == null || node.isNull() ? null : node.asText();
    }
}

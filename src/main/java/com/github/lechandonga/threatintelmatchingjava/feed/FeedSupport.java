package com.github.lechandonga.threatintelmatchingjava.feed;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.threatintelmatchingjava.model.RejectReason;
import com.github.lechandonga.threatintelmatchingjava.model.RejectedRecord;

/**
 * 解析器共用的小工具。
 */
final class FeedSupport {

    private FeedSupport() {
    }

    static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        String text = value.asText();
        return text == null || text.isBlank() ? null : text.trim();
    }

    static String snippet(String document, int max) {
        if (document == null) {
            return "";
        }
        String compact = document.replaceAll("\\s+", " ").trim();
        return compact.length() <= max ? compact : compact.substring(0, max) + "...";
    }

    static RejectedRecord reject(int index, String raw, RejectReason reason, String detail) {
        return new RejectedRecord(index, raw, reason, detail);
    }
}

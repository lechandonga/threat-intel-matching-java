package com.github.lechandonga.threatintelmatchingjava.feed;

import com.github.lechandonga.threatintelmatchingjava.normalize.RawIndicatorRecord;

import java.util.ArrayList;
import java.util.List;

/**
 * Parser for a simple local CSV feed. Required header (order-insensitive):
 * {@code source_id,record_id,type,value,verdict,confidence,observed_at}.
 * Malformed individual lines are returned as rows carrying the parse error so
 * the importer can reject them with a distinct reason instead of aborting.
 */
public class CsvFeedParser implements FeedParser {

    private static final String[] COLUMNS = {
            "source_id", "record_id", "type", "value", "verdict", "confidence", "observed_at"
    };

    @Override
    public List<RawIndicatorRecord> parse(String content) throws FeedParseException {
        String[] lines = content.split("\\r?\\n", -1);
        if (lines.length == 0 || lines[0].isBlank()) {
            throw new FeedParseException("CSV feed is empty");
        }
        List<String> header = splitCsvLine(lines[0]);
        int[] index = new int[COLUMNS.length];
        for (int i = 0; i < COLUMNS.length; i++) {
            int pos = header.indexOf(COLUMNS[i]);
            if (pos < 0) {
                throw new FeedParseException("CSV header is missing column: " + COLUMNS[i]);
            }
            index[i] = pos;
        }
        List<RawIndicatorRecord> rows = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isBlank()) {
                continue;
            }
            List<String> fields;
            try {
                fields = splitCsvLine(line);
            } catch (IllegalArgumentException e) {
                rows.add(new RawIndicatorRecord(null, null, null, null, null, null, null));
                continue;
            }
            if (fields.size() != COLUMNS.length) {
                rows.add(new RawIndicatorRecord(null, null, null, null, null, null, null));
                continue;
            }
            rows.add(new RawIndicatorRecord(
                    fields.get(index[0]),
                    fields.get(index[1]),
                    fields.get(index[2]),
                    fields.get(index[3]),
                    fields.get(index[4]),
                    fields.get(index[5]),
                    fields.get(index[6])));
        }
        return rows;
    }

    /** Minimal RFC-4180-ish splitter supporting quoted fields and escaped quotes. */
    static List<String> splitCsvLine(String line) {
        List<String> result = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    field.append(c);
                }
            } else if (c == '"') {
                if (!field.isEmpty()) {
                    throw new IllegalArgumentException("quoted field must start at column boundary");
                }
                quoted = true;
            } else if (c == ',') {
                result.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        if (quoted) {
            throw new IllegalArgumentException("unterminated quoted field");
        }
        result.add(field.toString());
        return result;
    }
}

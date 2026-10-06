package com.github.lechandonga.threatintelmatchingjava.feed;

import com.github.lechandonga.threatintelmatchingjava.normalize.RawIndicatorRecord;

import java.util.List;

/** Parses one feed document into raw, unvalidated rows. */
public interface FeedParser {

    List<RawIndicatorRecord> parse(String content) throws FeedParseException;

    /** Raw representation of row {@code line} for rejection reporting. */
    default String render(List<String> rawLines, int line) {
        return rawLines.get(line - 1);
    }
}

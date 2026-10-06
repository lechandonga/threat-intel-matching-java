package com.github.lechandonga.threatintelmatchingjava.feed;

import com.github.lechandonga.threatintelmatchingjava.model.ParsedEntry;
import com.github.lechandonga.threatintelmatchingjava.model.RejectedRecord;

import java.util.List;

/**
 * 一种情报来源格式的解析器。
 */
public interface FeedParser {

    /**
     * 格式标识（stix / flat）。
     */
    String format();

    /**
     * 解析一批原始文档。坏数据逐条拒绝，不影响同批其它记录。
     */
    ParseOutcome parse(String document);

    record ParseOutcome(List<ParsedEntry> entries, List<RejectedRecord> rejected) {
    }
}

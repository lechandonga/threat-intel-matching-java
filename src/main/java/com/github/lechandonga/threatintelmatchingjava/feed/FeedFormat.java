package com.github.lechandonga.threatintelmatchingjava.feed;

/** Supported on-disk feed formats. */
public enum FeedFormat {
    /** STIX-like JSON: {"sourceId": ..., "indicators": [{"id","type","value","verdict","confidence","observedAt"}]}. */
    STIX_JSON,
    /** CSV with header: source_id,record_id,type,value,verdict,confidence,observed_at. */
    CSV
}

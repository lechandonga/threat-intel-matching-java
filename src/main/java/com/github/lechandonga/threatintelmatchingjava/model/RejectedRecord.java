package com.github.lechandonga.threatintelmatchingjava.model;

/**
 * 一条被拒绝的记录及其在批次中的位置和原因。
 */
public record RejectedRecord(int index, String rawSnippet, RejectReason reason, String detail) {
}

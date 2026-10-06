package com.github.lechandonga.threatintelmatchingjava.model;

/**
 * 记录被拒绝的可区分原因。
 */
public enum RejectReason {
    DOCUMENT_NOT_OBJECT("文档不是 JSON 对象"),
    MISSING_RECORDS("缺少记录数组（objects/records）"),
    RECORDS_NOT_ARRAY("记录字段不是数组"),
    RECORD_NOT_OBJECT("记录不是 JSON 对象"),
    MISSING_SOURCE("缺少来源标识 source"),
    MISSING_TYPE("缺少指标类型"),
    UNSUPPORTED_TYPE("不支持的指标类型"),
    MISSING_VALUE("缺少指标值"),
    MALFORMED_IP("IP 格式非法"),
    MALFORMED_DOMAIN("域名格式非法"),
    MALFORMED_HASH("哈希格式非法（要求十六进制）"),
    UNKNOWN_HASH_LENGTH("无法识别的哈希长度（仅支持 MD5/SHA-1/SHA-256）"),
    MISSING_DISPOSITION("缺少结论字段"),
    UNSUPPORTED_DISPOSITION("不支持的结论取值（仅支持 malicious/suspicious/benign）"),
    MISSING_CONFIDENCE("缺少置信度"),
    CONFIDENCE_NOT_NUMBER("置信度不是数字"),
    CONFIDENCE_OUT_OF_RANGE("置信度超出 0-100"),
    MISSING_TIME("缺少观测时间"),
    MALFORMED_TIME("时间格式非法（要求 ISO-8601，如 2026-10-01T08:00:00Z）"),
    UNSUPPORTED_PATTERN("无法解析的 STIX 指标表达式"),
    STIX_OBJECT_NOT_INDICATOR("STIX 对象不是 indicator 类型"),
    UNKNOWN_SOURCE_KEY("撤回请求缺少 source 标识");

    private final String description;

    RejectReason(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}

package com.github.lechandonga.threatintelmatchingjava.model;

/**
 * 支持的威胁情报指标类型。
 */
public enum IndicatorType {
    IP,
    DOMAIN,
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256;

    /**
     * 哈希长度（十六进制字符数）到类型的映射，用于扁平来源缺省 hash_type 时推断。
     */
    public static IndicatorType hashTypeByLength(int hexLength) {
        return switch (hexLength) {
            case 32 -> HASH_MD5;
            case 40 -> HASH_SHA1;
            case 64 -> HASH_SHA256;
            default -> null;
        };
    }
}

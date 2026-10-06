package com.github.lechandonga.threatintelmatchingjava.model;

/**
 * 指标的全局唯一键：类型 + 归一化后的值。
 */
public record IndicatorKey(IndicatorType type, String value) {
}

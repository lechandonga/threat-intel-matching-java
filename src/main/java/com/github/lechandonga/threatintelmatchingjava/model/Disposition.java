package com.github.lechandonga.threatintelmatchingjava.model;

/**
 * 来源给出的原始结论。
 * <p>裁决分值固定：恶意 1.0、可疑 0.5、良性 0.0（良性仍参与良性票统计）。
 */
public enum Disposition {
    MALICIOUS(1.0),
    SUSPICIOUS(0.5),
    BENIGN(0.0);

    private final double weight;

    Disposition(double weight) {
        this.weight = weight;
    }

    public double weight() {
        return weight;
    }
}

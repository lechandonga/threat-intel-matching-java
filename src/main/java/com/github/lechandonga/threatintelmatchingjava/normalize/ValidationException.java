package com.github.lechandonga.threatintelmatchingjava.normalize;

/** Thrown while normalizing one record; carries a distinguishable reason code. */
public class ValidationException extends Exception {
    private final String reasonCode;

    public ValidationException(String reasonCode, String message) {
        super(message);
        this.reasonCode = reasonCode;
    }

    public String reasonCode() {
        return reasonCode;
    }
}

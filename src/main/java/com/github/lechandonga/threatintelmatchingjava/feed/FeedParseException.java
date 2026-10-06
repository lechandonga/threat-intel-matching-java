package com.github.lechandonga.threatintelmatchingjava.feed;

/** Fatal parse error for a whole feed document (as opposed to a single bad row). */
public class FeedParseException extends Exception {
    public FeedParseException(String message) {
        super(message);
    }

    public FeedParseException(String message, Throwable cause) {
        super(message, cause);
    }
}

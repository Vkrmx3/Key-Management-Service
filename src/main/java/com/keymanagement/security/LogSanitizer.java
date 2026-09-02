package com.keymanagement.security;

import java.util.regex.Pattern;

/**
 * Sanitizes user-controlled values before they are written to logs.
 * Strips CR/LF characters that could be used for log forging (log injection).
 */
public final class LogSanitizer {

    private static final Pattern CRLF_PATTERN = Pattern.compile("[\\r\\n]");

    private LogSanitizer() {
    }

    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return CRLF_PATTERN.matcher(input).replaceAll("_");
    }
}

package com.keymanagement.security;

/**
 * Sanitizes user-controlled values before they are written to logs.
 * Strips line breaks that could be used for log forging (log injection).
 *
 * Uses String.replaceAll with the literal "\R" pattern directly (rather than a
 * precompiled java.util.regex.Pattern/Matcher) because CodeQL's log-injection
 * sanitizer recognition only matches String.replace/replaceAll call sites with
 * a compile-time-constant line-break pattern - it does not trace taint through
 * Matcher.replaceAll or a cached Pattern field.
 */
public final class LogSanitizer {

    private LogSanitizer() {
    }

    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("\\R", "_");
    }
}

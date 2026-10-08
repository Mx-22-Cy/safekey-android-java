package com.safekey.app.breach;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parses responses from the HIBP Pwned Passwords
 * SHA-1 range endpoint.
 *
 * Expected line format:
 *
 * 35-character-hash-suffix:count
 *
 * HIBP padding rows use count 0 and are discarded.
 */
public final class HibpRangeParser {

    private HibpRangeParser() {
        // Utility class.
    }

    public static List<HibpRangeEntry> parse(
            String responseBody
    ) {

        if (responseBody == null) {

            throw new IllegalArgumentException(
                    "HIBP response must not be null."
            );
        }

        /*
         * Reject oversized responses before split()
         * creates additional strings in memory.
         */
        if (responseBody.length()
                > HibpRangeClient.MAX_RESPONSE_LENGTH) {

            throw new IllegalArgumentException(
                    "HIBP response exceeded maximum allowed size."
            );
        }

        /*
         * Empty and whitespace-only responses are invalid.
         */
        if (responseBody.trim().isEmpty()) {

            throw new IllegalArgumentException(
                    "HIBP response must not be empty or blank."
            );
        }

        String[] lines =
                responseBody.split(
                        "\\r?\\n"
                );

        List<HibpRangeEntry> entries =
                new ArrayList<>();

        for (String rawLine : lines) {

            String line =
                    rawLine.trim();

            /*
             * Blank lines inside an otherwise valid response
             * are ignored.
             */
            if (line.isEmpty()) {
                continue;
            }

            int separatorIndex =
                    line.indexOf(':');

            if (separatorIndex <= 0
                    || separatorIndex
                    != line.lastIndexOf(':')) {

                throw new IllegalArgumentException(
                        "Invalid HIBP response line."
                );
            }

            String suffix =
                    line.substring(
                            0,
                            separatorIndex
                    );

            String countText =
                    line.substring(
                            separatorIndex + 1
                    );

            long count =
                    parseCount(
                            countText
                    );

            /*
             * Count 0 represents HIBP response-padding rows.
             * They are valid but are not breach entries.
             */
            if (count == 0) {

                validatePaddingSuffix(
                        suffix
                );

                continue;
            }

            entries.add(
                    new HibpRangeEntry(
                            suffix,
                            count
                    )
            );
        }

        return Collections.unmodifiableList(
                new ArrayList<>(
                        entries
                )
        );
    }

    private static long parseCount(
            String countText
    ) {

        if (countText == null
                || countText.isEmpty()) {

            throw new IllegalArgumentException(
                    "HIBP breach count is missing."
            );
        }

        for (int index = 0;
             index < countText.length();
             index++) {

            char character =
                    countText.charAt(index);

            if (character < '0'
                    || character > '9') {

                throw new IllegalArgumentException(
                        "HIBP breach count must contain only digits."
                );
            }
        }

        try {

            return Long.parseLong(
                    countText
            );

        } catch (NumberFormatException exception) {

            throw new IllegalArgumentException(
                    "HIBP breach count is too large.",
                    exception
            );
        }
    }

    private static void validatePaddingSuffix(
            String suffix
    ) {

        if (suffix == null
                || suffix.length()
                != HibpRangeEntry.SHA1_SUFFIX_LENGTH) {

            throw new IllegalArgumentException(
                    "Invalid HIBP padding hash suffix."
            );
        }

        /*
         * Validate the original characters directly.
         * Do not uppercase first, because Unicode case
         * conversion can change the length/content.
         */
        for (int index = 0;
             index < suffix.length();
             index++) {

            char character =
                    suffix.charAt(index);

            boolean hexadecimal =
                    (character >= '0'
                            && character <= '9')
                            || (character >= 'A'
                            && character <= 'F')
                            || (character >= 'a'
                            && character <= 'f');

            if (!hexadecimal) {

                throw new IllegalArgumentException(
                        "Invalid HIBP padding hash suffix."
                );
            }
        }
    }
}

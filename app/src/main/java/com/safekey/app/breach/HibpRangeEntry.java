package com.safekey.app.breach;

import java.util.Locale;

/**
 * One real entry returned by the HIBP Pwned Passwords
 * SHA-1 range endpoint.
 *
 * Padding entries with count 0 are discarded by the parser,
 * so instances of this class always have a positive count.
 */
public final class HibpRangeEntry {

    public static final int SHA1_SUFFIX_LENGTH = 35;

    private final String hashSuffix;
    private final long count;

    public HibpRangeEntry(
            String hashSuffix,
            long count
    ) {
        this.hashSuffix =
                normalizeSuffix(hashSuffix);

        if (count <= 0) {
            throw new IllegalArgumentException(
                    "HIBP breach count must be greater than zero."
            );
        }

        this.count = count;
    }

    public String getHashSuffix() {
        return hashSuffix;
    }

    public long getCount() {
        return count;
    }

    private static String normalizeSuffix(
            String hashSuffix
    ) {
        if (hashSuffix == null) {
            throw new IllegalArgumentException(
                    "HIBP hash suffix must not be null."
            );
        }

        String normalized =
                hashSuffix.toUpperCase(
                        Locale.US
                );

        if (normalized.length()
                != SHA1_SUFFIX_LENGTH) {

            throw new IllegalArgumentException(
                    "HIBP SHA-1 hash suffix must contain exactly "
                            + SHA1_SUFFIX_LENGTH
                            + " hexadecimal characters."
            );
        }

        for (int index = 0;
             index < normalized.length();
             index++) {

            char character =
                    normalized.charAt(index);

            boolean hexadecimal =
                    (character >= '0'
                            && character <= '9')
                            || (character >= 'A'
                            && character <= 'F');

            if (!hexadecimal) {
                throw new IllegalArgumentException(
                        "HIBP hash suffix must contain only hexadecimal characters."
                );
            }
        }

        return normalized;
    }
}
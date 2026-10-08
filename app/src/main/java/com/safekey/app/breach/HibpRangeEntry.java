package com.safekey.app.breach;

import java.util.Locale;

/**
 * One validated entry returned by the
 * HIBP Pwned Passwords range endpoint.
 */
public final class HibpRangeEntry {

    public static final int SHA1_SUFFIX_LENGTH =
            35;

    private final String hashSuffix;
    private final long count;

    public HibpRangeEntry(
            String hashSuffix,
            long count
    ) {

        this.hashSuffix =
                normalizeSuffix(
                        hashSuffix
                );

        if (count <= 0) {

            throw new IllegalArgumentException(
                    "HIBP breach count must be positive."
            );
        }

        this.count =
                count;
    }

    public String getHashSuffix() {

        return hashSuffix;
    }

    public long getCount() {

        return count;
    }

    /**
     * Validates the original suffix before normalizing case.
     *
     * Only exactly 35 ASCII hexadecimal characters
     * are accepted. Unicode case expansion must not be
     * able to transform malformed input into a valid suffix.
     */
    private static String normalizeSuffix(
            String hashSuffix
    ) {

        if (hashSuffix == null) {

            throw new IllegalArgumentException(
                    "HIBP hash suffix must not be null."
            );
        }

        if (hashSuffix.length()
                != SHA1_SUFFIX_LENGTH) {

            throw new IllegalArgumentException(
                    "HIBP hash suffix must contain exactly "
                            + SHA1_SUFFIX_LENGTH
                            + " hexadecimal characters."
            );
        }

        for (int index = 0;
             index < hashSuffix.length();
             index++) {

            char character =
                    hashSuffix.charAt(index);

            if (!isAsciiHexDigit(
                    character
            )) {

                throw new IllegalArgumentException(
                        "HIBP hash suffix must contain only "
                                + "ASCII hexadecimal characters."
                );
            }
        }

        return hashSuffix.toUpperCase(
                Locale.US
        );
    }

    private static boolean isAsciiHexDigit(
            char character
    ) {

        return (character >= '0'
                && character <= '9')
                || (character >= 'A'
                && character <= 'F')
                || (character >= 'a'
                && character <= 'f');
    }
}

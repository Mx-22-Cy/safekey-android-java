package com.safekey.app.breach;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.List;

public class HibpRangeParserTest {

    @Test
    public void parse_validEntry_returnsEntry() {

        String suffix =
                repeat(
                        'A',
                        35
                );

        String response =
                suffix + ":42\n";

        List<HibpRangeEntry> entries =
                HibpRangeParser.parse(
                        response
                );

        assertEquals(
                1,
                entries.size()
        );

        assertEquals(
                suffix,
                entries.get(0)
                        .getHashSuffix()
        );

        assertEquals(
                42L,
                entries.get(0)
                        .getCount()
        );
    }

    @Test
    public void parse_paddingEntryWithZeroCount_discardsEntry() {

        String realSuffix =
                repeat(
                        'A',
                        35
                );

        String paddingSuffix =
                repeat(
                        'B',
                        35
                );

        String response =
                realSuffix
                        + ":12\n"
                        + paddingSuffix
                        + ":0\n";

        List<HibpRangeEntry> entries =
                HibpRangeParser.parse(
                        response
                );

        assertEquals(
                1,
                entries.size()
        );

        assertEquals(
                realSuffix,
                entries.get(0)
                        .getHashSuffix()
        );

        assertEquals(
                12L,
                entries.get(0)
                        .getCount()
        );
    }

    @Test
    public void parse_onlyPaddingEntries_returnsEmptyList() {

        String paddingSuffix =
                repeat(
                        'B',
                        35
                );

        List<HibpRangeEntry> entries =
                HibpRangeParser.parse(
                        paddingSuffix + ":0\n"
                );

        assertEquals(
                0,
                entries.size()
        );
    }

    @Test
    public void parse_emptyResponse_throwsException() {

        assertInvalidResponse(
                ""
        );
    }

    @Test
    public void parse_blankResponse_throwsException() {

        assertInvalidResponse(
                "   \r\n\t   \n"
        );
    }

    @Test
    public void parse_nullResponse_throwsException() {

        try {

            HibpRangeParser.parse(
                    null
            );

            fail(
                    "Expected IllegalArgumentException."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }

    @Test
    public void parse_invalidLine_throwsException() {

        assertInvalidResponse(
                "INVALID_LINE"
        );
    }

    @Test
    public void parse_invalidSuffixLength_throwsException() {

        assertInvalidResponse(
                "ABCDEF:10\n"
        );
    }

    @Test
    public void parse_nonHexSuffix_throwsException() {

        String invalidSuffix =
                repeat(
                        'G',
                        35
                );

        assertInvalidResponse(
                invalidSuffix + ":10\n"
        );
    }

    @Test
    public void parse_negativeCount_throwsException() {

        String suffix =
                repeat(
                        'A',
                        35
                );

        assertInvalidResponse(
                suffix + ":-1\n"
        );
    }

    @Test
    public void parse_oversizedResponse_throwsBeforeSplit() {

        String oversizedResponse =
                repeat(
                        'A',
                        HibpRangeClient.MAX_RESPONSE_LENGTH + 1
                );

        assertInvalidResponse(
                oversizedResponse
        );
    }

    @Test
    public void parse_unicodeExpansionSuffix_throwsException() {

        /*
         * Original suffix length is 34 characters:
         * one U+FB00 ligature plus 33 ASCII characters.
         *
         * Uppercasing U+FB00 could expand it into two
         * characters. Validation must happen before that.
         */
        String malformedSuffix =
                "\uFB00"
                        + repeat(
                        'A',
                        33
                );

        assertInvalidResponse(
                malformedSuffix + ":10\n"
        );
    }

    @Test
    public void parse_resultList_isImmutable() {

        String suffix =
                repeat(
                        'A',
                        35
                );

        List<HibpRangeEntry> entries =
                HibpRangeParser.parse(
                        suffix + ":5\n"
                );

        try {

            entries.add(
                    new HibpRangeEntry(
                            repeat(
                                    'B',
                                    35
                            ),
                            1
                    )
            );

            fail(
                    "Expected UnsupportedOperationException."
            );

        } catch (UnsupportedOperationException expected) {

            // Expected.
        }
    }

    private static void assertInvalidResponse(
            String response
    ) {

        try {

            HibpRangeParser.parse(
                    response
            );

            fail(
                    "Expected IllegalArgumentException."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }

    private static String repeat(
            char character,
            int count
    ) {

        StringBuilder builder =
                new StringBuilder(
                        count
                );

        for (int index = 0;
             index < count;
             index++) {

            builder.append(
                    character
            );
        }

        return builder.toString();
    }
}

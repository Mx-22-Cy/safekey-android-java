package com.safekey.app.breach;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

public class HibpRangeClientTest {

    @Test
    public void normalizePrefix_validUppercasePrefix_returnsSamePrefix() {

        assertEquals(
                "ABCDE",
                HibpRangeClient.normalizePrefix(
                        "ABCDE"
                )
        );
    }

    @Test
    public void normalizePrefix_lowercasePrefix_returnsUppercasePrefix() {

        assertEquals(
                "ABCDE",
                HibpRangeClient.normalizePrefix(
                        "abcde"
                )
        );
    }

    @Test
    public void normalizePrefix_unicodeExpansionInput_throwsException() {

        /*
         * U+FB00 is the Unicode "ff" ligature.
         *
         * The original value contains four characters:
         * ligature + 1 + 2 + 3.
         *
         * Unicode uppercasing could expand the ligature
         * into FF and incorrectly produce FF123.
         *
         * The original input must therefore be rejected
         * before case normalization.
         */
        assertInvalidPrefix(
                "\uFB00123"
        );
    }

    @Test
    public void normalizePrefix_nullPrefix_throwsException() {

        assertInvalidPrefix(
                null
        );
    }

    @Test
    public void normalizePrefix_shortPrefix_throwsException() {

        assertInvalidPrefix(
                "ABCD"
        );
    }

    @Test
    public void normalizePrefix_longPrefix_throwsException() {

        assertInvalidPrefix(
                "ABCDEF"
        );
    }

    @Test
    public void normalizePrefix_nonHexPrefix_throwsException() {

        assertInvalidPrefix(
                "ABCG1"
        );
    }

    @Test
    public void normalizePrefix_completeSha1Hash_throwsException() {

        assertInvalidPrefix(
                "0123456789ABCDEF0123456789ABCDEF01234567"
        );
    }

    @Test
    public void normalizePrefix_passwordLikeValue_throwsException() {

        assertInvalidPrefix(
                "password123"
        );
    }

    @Test
    public void readBoundedResponse_responseAtLimit_succeeds()
            throws IOException {

        String body =
                repeat(
                        'A',
                        HibpRangeClient.MAX_RESPONSE_LENGTH
                );

        String result =
                HibpRangeClient.readBoundedResponse(
                        new StringReader(
                                body
                        )
                );

        assertEquals(
                HibpRangeClient.MAX_RESPONSE_LENGTH,
                result.length()
        );

        assertEquals(
                body,
                result
        );
    }

    @Test
    public void readBoundedResponse_singleOversizedLine_throwsBeforeFullDownload() {

        String body =
                repeat(
                        'A',
                        2_000_000
                );

        CountingReader reader =
                new CountingReader(
                        body
                );

        try {

            HibpRangeClient.readBoundedResponse(
                    reader
            );

            fail(
                    "Expected IOException for oversized HIBP response."
            );

        } catch (IOException expected) {

            assertTrue(
                    reader.getCharactersRead()
                            <= HibpRangeClient.MAX_RESPONSE_LENGTH + 1
            );

            assertTrue(
                    reader.getCharactersRead()
                            < body.length()
            );
        }
    }

    @Test
    public void readBoundedResponse_oversizedMultiLineBody_throwsBeforeFullDownload() {

        StringBuilder body =
                new StringBuilder();

        while (body.length()
                <= HibpRangeClient.MAX_RESPONSE_LENGTH + 10_000) {

            body.append(
                    repeat(
                            'A',
                            200
                    )
            );

            body.append(
                    ":1\n"
            );
        }

        CountingReader reader =
                new CountingReader(
                        body.toString()
                );

        try {

            HibpRangeClient.readBoundedResponse(
                    reader
            );

            fail(
                    "Expected IOException for oversized HIBP response."
            );

        } catch (IOException expected) {

            assertTrue(
                    reader.getCharactersRead()
                            <= HibpRangeClient.MAX_RESPONSE_LENGTH + 1
            );

            assertTrue(
                    reader.getCharactersRead()
                            < body.length()
            );
        }
    }

    private static void assertInvalidPrefix(
            String value
    ) {

        try {

            HibpRangeClient.normalizePrefix(
                    value
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

    private static final class CountingReader
            extends Reader {

        private final StringReader delegate;
        private int charactersRead;

        private CountingReader(
                String value
        ) {

            delegate =
                    new StringReader(
                            value
                    );
        }

        @Override
        public int read(
                char[] buffer,
                int offset,
                int length
        ) throws IOException {

            int count =
                    delegate.read(
                            buffer,
                            offset,
                            length
                    );

            if (count > 0) {

                charactersRead +=
                        count;
            }

            return count;
        }

        @Override
        public void close() {

            delegate.close();
        }

        private int getCharactersRead() {

            return charactersRead;
        }
    }
}

package com.safekey.app.breach;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

public class HibpRangeClientTest {

    @Test
    public void normalizePrefix_validUppercase_returnsSameValue() {

        assertEquals(
                "ABCDE",
                HibpRangeClient.normalizePrefix(
                        "ABCDE"
                )
        );
    }

    @Test
    public void normalizePrefix_lowercase_convertsToUppercase() {

        assertEquals(
                "A1B2C",
                HibpRangeClient.normalizePrefix(
                        "a1b2c"
                )
        );
    }

    @Test
    public void normalizePrefix_null_throwsException() {

        try {

            HibpRangeClient.normalizePrefix(
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
    public void normalizePrefix_tooShort_throwsException() {

        try {

            HibpRangeClient.normalizePrefix(
                    "ABCD"
            );

            fail(
                    "Expected IllegalArgumentException."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }

    @Test
    public void normalizePrefix_tooLong_throwsException() {

        try {

            HibpRangeClient.normalizePrefix(
                    "ABCDEF"
            );

            fail(
                    "Expected IllegalArgumentException."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }

    @Test
    public void normalizePrefix_nonHexValue_throwsException() {

        try {

            HibpRangeClient.normalizePrefix(
                    "ABCG1"
            );

            fail(
                    "Expected IllegalArgumentException."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }

    @Test
    public void normalizePrefix_completeSha1Hash_throwsException() {

        String completeSha1Hash =
                "0123456789ABCDEF0123456789ABCDEF01234567";

        try {

            HibpRangeClient.normalizePrefix(
                    completeSha1Hash
            );

            fail(
                    "A complete SHA-1 hash must not be accepted."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }

    @Test
    public void normalizePrefix_rawPasswordLikeInput_throwsException() {

        try {

            HibpRangeClient.normalizePrefix(
                    "password123"
            );

            fail(
                    "Raw password-like input must not be accepted."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }
}

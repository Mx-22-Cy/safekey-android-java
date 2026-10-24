package com.safekey.app.security.totp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class TotpVerifierTest {

    // Public RFC test data only. This is not an application secret.
    private static final String TEST_SECRET =
            "12345678901234567890";

    @Test
    public void currentStep_matchesKnownCode() {
        assertEquals(1L, verify("287082", 59L, -1L));
    }

    @Test
    public void previousStep_isAcceptedWithinTolerance() {
        assertEquals(0L, verify("755224", 59L, -1L));
    }

    @Test
    public void nextStep_isAcceptedWithinTolerance() {
        assertEquals(2L, verify("359152", 59L, -1L));
    }

    @Test
    public void codeMoreThanOneStepOld_isRejected() {
        assertEquals(
                TotpVerifier.NO_MATCH,
                verify("755224", 90L, -1L)
        );
    }

    @Test
    public void codeMoreThanOneStepAhead_isRejected() {
        assertEquals(
                TotpVerifier.NO_MATCH,
                verify("969429", 59L, -1L)
        );
    }

    @Test
    public void alreadyAcceptedStep_isRejected() {
        assertEquals(
                TotpVerifier.NO_MATCH,
                verify("287082", 59L, 1L)
        );
    }

    @Test
    public void olderStepAfterNewerAcceptance_isRejected() {
        assertEquals(
                TotpVerifier.NO_MATCH,
                verify("287082", 89L, 2L)
        );
    }

    @Test
    public void newerUnusedStep_isAccepted() {
        assertEquals(2L, verify("359152", 89L, 1L));
    }

    @Test
    public void leadingZero_isPreserved() {
        assertEquals(
                37_037_036L,
                verify("081804", 1_111_111_109L, -1L)
        );
    }

    @Test
    public void malformedCodes_areRejected() {
        String[] malformedCodes = {
                null,
                "",
                "28708",
                "0287082",
                "81804",
                " 287082",
                "28708 ",
                "28708A",
                "28708\n",
                "\u0662\u0668\u0667\u0660\u0668\u0662",
                "\uFF12\uFF18\uFF17\uFF10\uFF18\uFF12"
        };

        for (String code : malformedCodes) {
            assertEquals(
                    TotpVerifier.NO_MATCH,
                    verify(code, 59L, -1L)
            );
        }
    }

    @Test
    public void incorrectSixDigitCode_isRejected() {
        assertEquals(
                TotpVerifier.NO_MATCH,
                verify("287083", 59L, -1L)
        );
    }

    @Test
    public void oldestCodeExpiresAtExactWindowBoundary() {
        assertEquals(0L, verify("755224", 59L, -1L));

        assertEquals(
                TotpVerifier.NO_MATCH,
                verify("755224", 60L, -1L)
        );
    }

    @Test
    public void unixEpoch_isSupported() {
        assertEquals(0L, verify("755224", 0L, -1L));
    }

    @Test
    public void largestTimestamp_doesNotOverflow() {
        assertEquals(
                307_445_734_561_825_860L,
                verify("451934", Long.MAX_VALUE, -1L)
        );
    }

    @Test
    public void verification_leavesCallerBuffersUnchanged() {
        byte[] secret = secret();
        byte[] originalSecret = secret.clone();

        char[] code = "287082".toCharArray();
        char[] originalCode = code.clone();

        assertEquals(
                1L,
                TotpVerifier.findMatchingStep(
                        secret,
                        code,
                        59L,
                        -1L
                )
        );

        assertArrayEquals(originalSecret, secret);
        assertArrayEquals(originalCode, code);
    }

    @Test(expected = NullPointerException.class)
    public void nullSecret_isRejected() {
        TotpVerifier.findMatchingStep(
                null,
                "287082".toCharArray(),
                59L,
                -1L
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void shortSecret_isRejected() {
        TotpVerifier.findMatchingStep(
                new byte[15],
                "287082".toCharArray(),
                59L,
                -1L
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeUnixTime_isRejected() {
        verify("287082", -1L, -1L);
    }

    @Test(expected = IllegalArgumentException.class)
    public void lastAcceptedStepBelowMinusOne_isRejected() {
        verify("287082", 59L, -2L);
    }

    @Test(expected = IllegalArgumentException.class)
    public void lastAcceptedStepOutsideSupportedRange_isRejected() {
        verify("287082", 59L, Long.MAX_VALUE);
    }

    private static long verify(
            String code,
            long unixTimeSeconds,
            long lastAcceptedStep
    ) {
        return TotpVerifier.findMatchingStep(
                secret(),
                code == null ? null : code.toCharArray(),
                unixTimeSeconds,
                lastAcceptedStep
        );
    }

    private static byte[] secret() {
        return TEST_SECRET.getBytes(StandardCharsets.US_ASCII);
    }
}

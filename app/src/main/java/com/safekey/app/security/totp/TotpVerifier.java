package com.safekey.app.security.totp;

import java.util.Objects;

/**
 * Stateless verification for SafeKey's default TOTP configuration:
 * SHA-1, six digits, thirty-second periods and a one-step clock tolerance.
 *
 * Caller-owned secret and code arrays are left unchanged.
 * The caller remains responsible for clearing them.
 *
 * The caller must serialize verification with persistent replay-state updates,
 * save the accepted step before granting access, and enforce attempt limits.
 */
public final class TotpVerifier {

    public static final long NO_MATCH = -1L;

    private static final int MIN_SECRET_BYTES = 16;

    private static final long MAX_STEP =
            Long.MAX_VALUE / TotpGenerator.DEFAULT_PERIOD_SECONDS;

    private TotpVerifier() {
        // Utility class.
    }

    /**
     * Returns the newest matching, unused time step, or NO_MATCH.
     *
     * Pass -1 as lastAcceptedStep when no code has been accepted for this
     * secret. Otherwise pass the last successfully accepted, persisted step.
     *
     * Malformed submitted codes are rejected without trimming or conversion.
     * Invalid secret/time/state arguments indicate a programming or state error.
     */
    public static long findMatchingStep(
            byte[] secret,
            char[] submittedCode,
            long unixTimeSeconds,
            long lastAcceptedStep
    ) {
        Objects.requireNonNull(secret, "secret");

        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalArgumentException(
                    "TOTP secret must contain at least 16 bytes."
            );
        }

        if (unixTimeSeconds < 0) {
            throw new IllegalArgumentException(
                    "Unix time must not be negative."
            );
        }

        if (lastAcceptedStep < NO_MATCH || lastAcceptedStep > MAX_STEP) {
            throw new IllegalArgumentException(
                    "Last accepted TOTP step is invalid."
            );
        }

        if (!isSixAsciiDigits(submittedCode)) {
            return NO_MATCH;
        }

        long currentStep =
                unixTimeSeconds / TotpGenerator.DEFAULT_PERIOD_SECONDS;

        long matchedStep = NO_MATCH;

        for (int offset = -1; offset <= 1; offset++) {
            long candidateStep = currentStep + offset;

            if (candidateStep < 0 || candidateStep > MAX_STEP) {
                continue;
            }

            long candidateTimeSeconds =
                    candidateStep * TotpGenerator.DEFAULT_PERIOD_SECONDS;

            String expectedCode =
                    TotpGenerator.generate(secret, candidateTimeSeconds);

            boolean matches =
                    matchesAllDigits(expectedCode, submittedCode);

            if (matches
                    && candidateStep > lastAcceptedStep
                    && candidateStep > matchedStep) {
                matchedStep = candidateStep;
            }
        }

        return matchedStep;
    }

    private static boolean isSixAsciiDigits(char[] code) {
        if (code == null || code.length != TotpGenerator.DEFAULT_DIGITS) {
            return false;
        }

        for (char digit : code) {
            if (digit < '0' || digit > '9') {
                return false;
            }
        }

        return true;
    }

    private static boolean matchesAllDigits(
            String expectedCode,
            char[] submittedCode
    ) {
        int difference = 0;

        // Compare every digit without returning at the first mismatch.
        for (int index = 0; index < TotpGenerator.DEFAULT_DIGITS; index++) {
            difference |=
                    expectedCode.charAt(index) ^ submittedCode[index];
        }

        return difference == 0;
    }
}

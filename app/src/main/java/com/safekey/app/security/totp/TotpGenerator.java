package com.safekey.app.security.totp;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Stateless RFC 6238 TOTP calculation using standard Java APIs.
 * Time is supplied in Unix seconds, with T0 fixed at the Unix epoch.
 * Leaves the caller's secret unchanged; the caller must clear it after use.
 * Setup, storage, verification, replay prevention and throttling are separate.
 */
public final class TotpGenerator {

    public static final int DEFAULT_DIGITS = 6;
    public static final int DEFAULT_PERIOD_SECONDS = 30;

    private static final int MIN_SECRET_BYTES = 16;

    public enum Algorithm {
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA512("HmacSHA512");

        private final String macName;

        Algorithm(String macName) {
            this.macName = macName;
        }
    }

    private TotpGenerator() {
        // Utility class.
    }

    public static String generate(byte[] secret, long unixTimeSeconds) {
        return generate(
                secret,
                unixTimeSeconds,
                Algorithm.SHA1,
                DEFAULT_DIGITS,
                DEFAULT_PERIOD_SECONDS
        );
    }

    /**
     * Calculates a 6-, 7- or 8-digit ASCII code.
     * The secret is raw key bytes, not Base32 text or the master password.
     * Requires at least 16 bytes; secret generation is a separate operation.
     */
    public static String generate(
            byte[] secret,
            long unixTimeSeconds,
            Algorithm algorithm,
            int digits,
            int periodSeconds
    ) {
        Objects.requireNonNull(secret, "secret");
        Objects.requireNonNull(algorithm, "algorithm");

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

        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException(
                    "TOTP code length must be between 6 and 8."
            );
        }

        if (periodSeconds <= 0) {
            throw new IllegalArgumentException(
                    "TOTP period must be positive."
            );
        }

        long counter = unixTimeSeconds / periodSeconds;

        byte[] counterBytes = ByteBuffer.allocate(Long.BYTES)
                .putLong(counter)
                .array();

        char[] code = new char[digits];
        byte[] digest = null;
        byte[] secretCopy = secret.clone();

        try {
            Mac mac = Mac.getInstance(algorithm.macName);
            mac.init(new SecretKeySpec(secretCopy, algorithm.macName));
            digest = mac.doFinal(counterBytes);

            int offset = digest[digest.length - 1] & 0x0F;

            int truncated = ((digest[offset] & 0x7F) << 24)
                    | ((digest[offset + 1] & 0xFF) << 16)
                    | ((digest[offset + 2] & 0xFF) << 8)
                    | (digest[offset + 3] & 0xFF);

            int modulus = 1;

            for (int index = 0; index < digits; index++) {
                modulus *= 10;
            }

            int value = truncated % modulus;

            for (int index = digits - 1; index >= 0; index--) {
                code[index] = (char) ('0' + value % 10);
                value /= 10;
            }

            return new String(code);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Required TOTP HMAC operation is unavailable.",
                    exception
            );

        } finally {
            // Wipe the temporary buffers owned by this class.
            Arrays.fill(secretCopy, (byte) 0);
            Arrays.fill(counterBytes, (byte) 0);
            Arrays.fill(code, '\0');

            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }
}

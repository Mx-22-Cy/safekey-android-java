package com.safekey.app.security.totp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class TotpGeneratorTest {

    // Public RFC test data only. These values are not application secrets.
    private static final String SHA1_SECRET = "12345678901234567890";
    private static final String SHA256_SECRET =
            "12345678901234567890123456789012";
    private static final String SHA512_SECRET =
            "1234567890123456789012345678901234567890123456789012345678901234";

    @Test
    public void rfc6238Vectors_matchAll18ExpectedCodes() {
        // RFC 6238, Appendix B; key lengths follow Appendix A / Errata 2866.
        long[] timestamps = {
                59L, 1_111_111_109L, 1_111_111_111L,
                1_234_567_890L, 2_000_000_000L, 20_000_000_000L
        };

        String[][] expected = {
                {"94287082", "46119246", "90693936"},
                {"07081804", "68084774", "25091201"},
                {"14050471", "67062674", "99943326"},
                {"89005924", "91819424", "93441116"},
                {"69279037", "90698825", "38618901"},
                {"65353130", "77737706", "47863826"}
        };

        TotpGenerator.Algorithm[] algorithms = {
                TotpGenerator.Algorithm.SHA1,
                TotpGenerator.Algorithm.SHA256,
                TotpGenerator.Algorithm.SHA512
        };

        byte[][] secrets = {
                bytes(SHA1_SECRET),
                bytes(SHA256_SECRET),
                bytes(SHA512_SECRET)
        };

        for (int timeIndex = 0; timeIndex < timestamps.length; timeIndex++) {
            for (int algorithmIndex = 0;
                 algorithmIndex < algorithms.length;
                 algorithmIndex++) {

                assertEquals(
                        algorithms[algorithmIndex] + " at " + timestamps[timeIndex],
                        expected[timeIndex][algorithmIndex],
                        TotpGenerator.generate(
                                secrets[algorithmIndex],
                                timestamps[timeIndex],
                                algorithms[algorithmIndex],
                                8,
                                30
                        )
                );
            }
        }
    }

    @Test
    public void defaults_useSixDigitsSha1AndThirtySeconds() {
        assertEquals("287082", TotpGenerator.generate(bytes(SHA1_SECRET), 59L));
    }

    @Test
    public void generate_keepsLeadingZeros() {
        assertEquals(
                "081804",
                TotpGenerator.generate(bytes(SHA1_SECRET), 1_111_111_109L)
        );
    }

    @Test
    public void generate_changesAtExactStepBoundary() {
        byte[] secret = bytes(SHA1_SECRET);
        assertEquals("755224", TotpGenerator.generate(secret, 0L));
        assertEquals("755224", TotpGenerator.generate(secret, 29L));
        assertEquals("287082", TotpGenerator.generate(secret, 30L));
        assertEquals("287082", TotpGenerator.generate(secret, 59L));
        assertEquals("359152", TotpGenerator.generate(secret, 60L));
    }

    @Test
    public void generate_supportsCustomPeriod() {
        assertEquals(
                "287082",
                TotpGenerator.generate(
                        bytes(SHA1_SECRET), 119L,
                        TotpGenerator.Algorithm.SHA1, 6, 60
                )
        );
    }

    @Test
    public void generate_supportsSevenDigits() {
        assertEquals(
                "4287082",
                TotpGenerator.generate(
                        bytes(SHA1_SECRET), 59L,
                        TotpGenerator.Algorithm.SHA1, 7, 30
                )
        );
    }

    @Test
    public void generate_supportsCountersLargerThan32Bits() {
        assertEquals(
                "108930",
                TotpGenerator.generate(bytes(SHA1_SECRET), 128_849_018_910L)
        );
    }

    @Test
    public void generate_supportsLargestNonNegativeTimestamp() {
        assertEquals(
                "451934",
                TotpGenerator.generate(bytes(SHA1_SECRET), Long.MAX_VALUE)
        );
    }

    @Test
    public void generate_leavesCallerSecretUnchanged() {
        byte[] secret = bytes(SHA1_SECRET);
        byte[] original = secret.clone();
        TotpGenerator.generate(secret, 59L);
        assertArrayEquals(original, secret);
    }

    @Test
    public void generate_accepts128BitSecret() {
        assertEquals(6, TotpGenerator.generate(new byte[16], 59L).length());
    }

    @Test(expected = NullPointerException.class)
    public void nullSecret_isRejected() {
        TotpGenerator.generate(null, 59L);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shortSecret_isRejected() {
        TotpGenerator.generate(new byte[15], 59L);
    }

    @Test(expected = NullPointerException.class)
    public void nullAlgorithm_isRejected() {
        TotpGenerator.generate(bytes(SHA1_SECRET), 59L, null, 6, 30);
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeUnixTime_isRejected() {
        TotpGenerator.generate(bytes(SHA1_SECRET), -1L);
    }

    @Test(expected = IllegalArgumentException.class)
    public void digitsBelowSix_areRejected() {
        TotpGenerator.generate(
                bytes(SHA1_SECRET), 59L,
                TotpGenerator.Algorithm.SHA1, 5, 30
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void digitsAboveEight_areRejected() {
        TotpGenerator.generate(
                bytes(SHA1_SECRET), 59L,
                TotpGenerator.Algorithm.SHA1, 9, 30
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void zeroPeriod_isRejected() {
        TotpGenerator.generate(
                bytes(SHA1_SECRET), 59L,
                TotpGenerator.Algorithm.SHA1, 6, 0
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativePeriod_isRejected() {
        TotpGenerator.generate(
                bytes(SHA1_SECRET), 59L,
                TotpGenerator.Algorithm.SHA1, 6, -30
        );
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}

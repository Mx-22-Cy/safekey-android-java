package com.safekey.app.security.crypto;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class Argon2idMasterKeyDeriverTest {

    @Test
    public void configuration_matchesWeekFourPlan() {
        assertEquals(
                16,
                Argon2idMasterKeyDeriver.SALT_LENGTH_BYTES
        );

        assertEquals(
                32,
                Argon2idMasterKeyDeriver.DERIVED_KEY_LENGTH_BYTES
        );

        assertEquals(
                19 * 1024,
                Argon2idMasterKeyDeriver.MEMORY_KIB
        );

        assertEquals(
                2,
                Argon2idMasterKeyDeriver.ITERATIONS
        );

        assertEquals(
                1,
                Argon2idMasterKeyDeriver.PARALLELISM
        );
    }

    @Test
    public void generateSalt_twoCalls_returnDifferentSixteenByteSalts() {
        Argon2idMasterKeyDeriver keyDeriver =
                new Argon2idMasterKeyDeriver();

        byte[] firstSalt =
                keyDeriver.generateSalt();

        byte[] secondSalt =
                keyDeriver.generateSalt();

        assertEquals(
                Argon2idMasterKeyDeriver.SALT_LENGTH_BYTES,
                firstSalt.length
        );

        assertEquals(
                Argon2idMasterKeyDeriver.SALT_LENGTH_BYTES,
                secondSalt.length
        );

        assertFalse(
                Arrays.equals(
                        firstSalt,
                        secondSalt
                )
        );
    }

    @Test
    public void deriveKey_sameInputs_returnSameThirtyTwoByteKey() {
        Argon2idMasterKeyDeriver keyDeriver =
                new Argon2idMasterKeyDeriver();

        char[] password =
                "كلمة مرور آمنة جدًا".toCharArray();

        byte[] salt =
                createSalt(0);

        byte[] firstKey =
                keyDeriver.deriveKey(
                        password,
                        salt
                );

        byte[] secondKey =
                keyDeriver.deriveKey(
                        password,
                        salt
                );

        try {
            assertEquals(
                    Argon2idMasterKeyDeriver
                            .DERIVED_KEY_LENGTH_BYTES,
                    firstKey.length
            );

            assertArrayEquals(
                    firstKey,
                    secondKey
            );

        } finally {
            Arrays.fill(
                    firstKey,
                    (byte) 0
            );

            Arrays.fill(
                    secondKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void deriveKey_differentPasswords_returnDifferentKeys() {
        Argon2idMasterKeyDeriver keyDeriver =
                new Argon2idMasterKeyDeriver();

        byte[] salt =
                createSalt(10);

        byte[] firstKey =
                keyDeriver.deriveKey(
                        "first secure password".toCharArray(),
                        salt
                );

        byte[] secondKey =
                keyDeriver.deriveKey(
                        "second secure password".toCharArray(),
                        salt
                );

        try {
            assertFalse(
                    Arrays.equals(
                            firstKey,
                            secondKey
                    )
            );

        } finally {
            Arrays.fill(
                    firstKey,
                    (byte) 0
            );

            Arrays.fill(
                    secondKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void deriveKey_differentSalts_returnDifferentKeys() {
        Argon2idMasterKeyDeriver keyDeriver =
                new Argon2idMasterKeyDeriver();

        char[] password =
                "correct horse battery staple".toCharArray();

        byte[] firstKey =
                keyDeriver.deriveKey(
                        password,
                        createSalt(20)
                );

        byte[] secondKey =
                keyDeriver.deriveKey(
                        password,
                        createSalt(40)
                );

        try {
            assertFalse(
                    Arrays.equals(
                            firstKey,
                            secondKey
                    )
            );

        } finally {
            Arrays.fill(
                    firstKey,
                    (byte) 0
            );

            Arrays.fill(
                    secondKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void deriveKey_doesNotModifyPasswordOrSalt() {
        Argon2idMasterKeyDeriver keyDeriver =
                new Argon2idMasterKeyDeriver();

        char[] password =
                "unchanged password value".toCharArray();

        byte[] salt =
                createSalt(60);

        char[] expectedPassword =
                Arrays.copyOf(
                        password,
                        password.length
                );

        byte[] expectedSalt =
                Arrays.copyOf(
                        salt,
                        salt.length
                );

        byte[] derivedKey =
                keyDeriver.deriveKey(
                        password,
                        salt
                );

        try {
            assertArrayEquals(
                    expectedPassword,
                    password
            );

            assertArrayEquals(
                    expectedSalt,
                    salt
            );

        } finally {
            Arrays.fill(
                    derivedKey,
                    (byte) 0
            );
        }
    }

    @Test(expected = NullPointerException.class)
    public void constructor_nullSecureRandom_throwsNullPointerException() {
        new Argon2idMasterKeyDeriver(null);
    }

    @Test(expected = NullPointerException.class)
    public void deriveKey_nullPassword_throwsNullPointerException() {
        new Argon2idMasterKeyDeriver()
                .deriveKey(
                        null,
                        createSalt(0)
                );
    }

    @Test(expected = NullPointerException.class)
    public void deriveKey_nullSalt_throwsNullPointerException() {
        new Argon2idMasterKeyDeriver()
                .deriveKey(
                        "valid password".toCharArray(),
                        null
                );
    }

    @Test(expected = IllegalArgumentException.class)
    public void deriveKey_emptyPassword_throwsIllegalArgumentException() {
        new Argon2idMasterKeyDeriver()
                .deriveKey(
                        new char[0],
                        createSalt(0)
                );
    }

    @Test(expected = IllegalArgumentException.class)
    public void deriveKey_wrongSaltLength_throwsIllegalArgumentException() {
        new Argon2idMasterKeyDeriver()
                .deriveKey(
                        "valid password".toCharArray(),
                        new byte[15]
                );
    }

    private static byte[] createSalt(
            int startingValue
    ) {
        byte[] salt =
                new byte[
                        Argon2idMasterKeyDeriver
                                .SALT_LENGTH_BYTES
                        ];

        for (
                int index = 0;
                index < salt.length;
                index++
        ) {
            salt[index] =
                    (byte) (
                            startingValue
                                    + index
                    );
        }

        return salt;
    }
}

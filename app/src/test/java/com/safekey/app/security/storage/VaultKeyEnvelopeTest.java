package com.safekey.app.security.storage;

import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertThrows;

public class VaultKeyEnvelopeTest {

    private static final String WRAPPED_DATABASE_KEY =
            "SK1.AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBB";

    @Test
    public void constructor_validValues_storesEnvelope() {
        byte[] salt =
                createSalt();

        VaultKeyEnvelope envelope =
                new VaultKeyEnvelope(
                        salt,
                        WRAPPED_DATABASE_KEY
                );

        assertEquals(
                VaultKeyEnvelope.CURRENT_FORMAT_VERSION,
                envelope.getFormatVersion()
        );

        assertArrayEquals(
                salt,
                envelope.getSalt()
        );

        assertEquals(
                WRAPPED_DATABASE_KEY,
                envelope.getWrappedDatabaseKey()
        );
    }

    @Test
    public void constructor_copiesInputSalt() {
        byte[] salt =
                createSalt();

        byte[] expectedSalt =
                Arrays.copyOf(
                        salt,
                        salt.length
                );

        VaultKeyEnvelope envelope =
                new VaultKeyEnvelope(
                        salt,
                        WRAPPED_DATABASE_KEY
                );

        Arrays.fill(
                salt,
                (byte) 0
        );

        assertArrayEquals(
                expectedSalt,
                envelope.getSalt()
        );
    }

    @Test
    public void getSalt_returnsDefensiveCopy() {
        VaultKeyEnvelope envelope =
                new VaultKeyEnvelope(
                        createSalt(),
                        WRAPPED_DATABASE_KEY
                );

        byte[] firstSalt =
                envelope.getSalt();

        byte[] secondSalt =
                envelope.getSalt();

        assertNotSame(
                firstSalt,
                secondSalt
        );

        Arrays.fill(
                firstSalt,
                (byte) 0
        );

        assertArrayEquals(
                createSalt(),
                envelope.getSalt()
        );
    }

    @Test
    public void constructor_nullSalt_throwsNullPointerException() {
        NullPointerException exception =
                assertThrows(
                        NullPointerException.class,
                        () ->
                                new VaultKeyEnvelope(
                                        null,
                                        WRAPPED_DATABASE_KEY
                                )
                );

        assertEquals(
                "salt",
                exception.getMessage()
        );
    }

    @Test
    public void constructor_wrongSaltLength_throwsIllegalArgumentException() {
        byte[] shortSalt =
                new byte[
                        Argon2idMasterKeyDeriver
                                .SALT_LENGTH_BYTES
                                - 1
                        ];

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                new VaultKeyEnvelope(
                                        shortSalt,
                                        WRAPPED_DATABASE_KEY
                                )
                );

        assertEquals(
                "Salt must contain exactly 16 bytes.",
                exception.getMessage()
        );
    }

    @Test
    public void constructor_nullWrappedKey_throwsNullPointerException() {
        NullPointerException exception =
                assertThrows(
                        NullPointerException.class,
                        () ->
                                new VaultKeyEnvelope(
                                        createSalt(),
                                        null
                                )
                );

        assertEquals(
                "wrappedDatabaseKey",
                exception.getMessage()
        );
    }

    @Test
    public void constructor_blankWrappedKey_throwsIllegalArgumentException() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                new VaultKeyEnvelope(
                                        createSalt(),
                                        "   "
                                )
                );

        assertEquals(
                "Wrapped database key must not be empty.",
                exception.getMessage()
        );
    }

    @Test
    public void constructor_unsupportedVersion_throwsIllegalArgumentException() {
        int unsupportedVersion =
                VaultKeyEnvelope.CURRENT_FORMAT_VERSION
                        + 1;

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                new VaultKeyEnvelope(
                                        unsupportedVersion,
                                        createSalt(),
                                        WRAPPED_DATABASE_KEY
                                )
                );

        assertEquals(
                "Unsupported vault key envelope version: 2.",
                exception.getMessage()
        );
    }

    private static byte[] createSalt() {
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
                            index + 1
                    );
        }

        return salt;
    }
}

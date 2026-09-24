package com.safekey.app.security.crypto;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class VaultCryptographyIntegrationTest {

    @Test
    public void derivedMasterKey_wrapsAndUnwrapsRandomDatabaseKey()
            throws AesGcmException {
        Argon2idMasterKeyDeriver keyDeriver =
                new Argon2idMasterKeyDeriver();

        AesGcmCipher cipher =
                new AesGcmCipher();

        char[] masterPassword =
                "correct horse battery staple".toCharArray();

        byte[] salt =
                keyDeriver.generateSalt();

        byte[] derivedMasterKey =
                keyDeriver.deriveKey(
                        masterPassword,
                        salt
                );

        byte[] databaseKey =
                new byte[AesGcmCipher.KEY_LENGTH_BYTES];

        new SecureRandom().nextBytes(
                databaseKey
        );

        String wrappedDatabaseKey =
                cipher.encrypt(
                        databaseKey,
                        derivedMasterKey,
                        databaseKeyContext()
                );

        byte[] unwrappedDatabaseKey =
                cipher.decrypt(
                        wrappedDatabaseKey,
                        derivedMasterKey,
                        databaseKeyContext()
                );

        try {
            assertArrayEquals(
                    databaseKey,
                    unwrappedDatabaseKey
            );

        } finally {
            Arrays.fill(
                    masterPassword,
                    '\0'
            );

            Arrays.fill(
                    derivedMasterKey,
                    (byte) 0
            );

            Arrays.fill(
                    databaseKey,
                    (byte) 0
            );

            Arrays.fill(
                    unwrappedDatabaseKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void keyFromWrongPassword_cannotUnwrapDatabaseKey()
            throws AesGcmException {
        Argon2idMasterKeyDeriver keyDeriver =
                new Argon2idMasterKeyDeriver();

        AesGcmCipher cipher =
                new AesGcmCipher();

        char[] correctPassword =
                "correct horse battery staple".toCharArray();

        char[] wrongPassword =
                "incorrect master password value".toCharArray();

        byte[] salt =
                keyDeriver.generateSalt();

        byte[] correctMasterKey =
                keyDeriver.deriveKey(
                        correctPassword,
                        salt
                );

        byte[] wrongMasterKey =
                keyDeriver.deriveKey(
                        wrongPassword,
                        salt
                );

        byte[] databaseKey =
                new byte[AesGcmCipher.KEY_LENGTH_BYTES];

        new SecureRandom().nextBytes(
                databaseKey
        );

        String wrappedDatabaseKey =
                cipher.encrypt(
                        databaseKey,
                        correctMasterKey,
                        databaseKeyContext()
                );

        try {
            AesGcmException exception =
                    assertThrows(
                            AesGcmException.class,
                            () -> cipher.decrypt(
                                    wrappedDatabaseKey,
                                    wrongMasterKey,
                                    databaseKeyContext()
                            )
                    );

            assertEquals(
                    "Unable to decrypt protected data.",
                    exception.getMessage()
            );

        } finally {
            Arrays.fill(
                    correctPassword,
                    '\0'
            );

            Arrays.fill(
                    wrongPassword,
                    '\0'
            );

            Arrays.fill(
                    correctMasterKey,
                    (byte) 0
            );

            Arrays.fill(
                    wrongMasterKey,
                    (byte) 0
            );

            Arrays.fill(
                    databaseKey,
                    (byte) 0
            );
        }
    }

    private static byte[] databaseKeyContext() {
        return "safekey:database-key-envelope:v1"
                .getBytes(
                        StandardCharsets.UTF_8
                );
    }
}

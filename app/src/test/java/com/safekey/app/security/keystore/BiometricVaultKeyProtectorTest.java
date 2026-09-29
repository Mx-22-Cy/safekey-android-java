package com.safekey.app.security.keystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class BiometricVaultKeyProtectorTest {

    private static final String TRANSFORMATION =
            "AES/GCM/NoPadding";

    private static final int GCM_TAG_LENGTH_BITS =
            128;

    private final BiometricVaultKeyProtector protector =
            new BiometricVaultKeyProtector();

    @Test
    public void wrapAndUnwrapReturnsOriginalVaultKey()
            throws Exception {

        SecretKey wrappingKey =
                generateWrappingKey();

        byte[] vaultKey =
                randomBytes(
                        BiometricVaultKeyProtector
                                .VAULT_KEY_LENGTH_BYTES
                );

        Cipher encryptionCipher =
                createEncryptionCipher(
                        wrappingKey
                );

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                protector.wrap(
                        vaultKey,
                        encryptionCipher
                );

        assertEquals(
                12,
                wrappedKey.getIv().length
        );

        assertEquals(
                48,
                wrappedKey.getCiphertext().length
        );

        Cipher decryptionCipher =
                createDecryptionCipher(
                        wrappingKey,
                        wrappedKey.getIv()
                );

        byte[] unwrapped =
                protector.unwrap(
                        wrappedKey,
                        decryptionCipher
                );

        assertArrayEquals(
                vaultKey,
                unwrapped
        );
    }

    @Test
    public void wrapRejectsNullVaultKey()
            throws Exception {

        assertVaultKeyRejected(
                null
        );
    }

    @Test
    public void wrapRejectsEmptyVaultKey()
            throws Exception {

        assertVaultKeyRejected(
                new byte[0]
        );
    }

    @Test
    public void wrapRejectsShortVaultKey()
            throws Exception {

        assertVaultKeyRejected(
                new byte[
                        BiometricVaultKeyProtector
                                .VAULT_KEY_LENGTH_BYTES - 1
                        ]
        );
    }

    @Test
    public void wrapRejectsLongVaultKey()
            throws Exception {

        assertVaultKeyRejected(
                new byte[
                        BiometricVaultKeyProtector
                                .VAULT_KEY_LENGTH_BYTES + 1
                        ]
        );
    }

    @Test
    public void tamperedCiphertextIsRejected()
            throws Exception {

        SecretKey wrappingKey =
                generateWrappingKey();

        byte[] vaultKey =
                randomBytes(
                        BiometricVaultKeyProtector
                                .VAULT_KEY_LENGTH_BYTES
                );

        Cipher encryptionCipher =
                createEncryptionCipher(
                        wrappingKey
                );

        BiometricVaultKeyProtector.WrappedKey original =
                protector.wrap(
                        vaultKey,
                        encryptionCipher
                );

        byte[] tamperedCiphertext =
                original.getCiphertext();

        tamperedCiphertext[
                tamperedCiphertext.length - 1
                ] ^= 0x01;

        BiometricVaultKeyProtector.WrappedKey tampered =
                new BiometricVaultKeyProtector.WrappedKey(
                        original.getIv(),
                        tamperedCiphertext
                );

        Cipher decryptionCipher =
                createDecryptionCipher(
                        wrappingKey,
                        original.getIv()
                );

        try {

            protector.unwrap(
                    tampered,
                    decryptionCipher
            );

            fail(
                    "Expected tampered ciphertext to be rejected."
            );

        } catch (GeneralSecurityException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void mismatchedIvIsRejected()
            throws Exception {

        SecretKey wrappingKey =
                generateWrappingKey();

        byte[] vaultKey =
                randomBytes(
                        BiometricVaultKeyProtector
                                .VAULT_KEY_LENGTH_BYTES
                );

        Cipher encryptionCipher =
                createEncryptionCipher(
                        wrappingKey
                );

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                protector.wrap(
                        vaultKey,
                        encryptionCipher
                );

        byte[] differentIv =
                Arrays.copyOf(
                        wrappedKey.getIv(),
                        wrappedKey.getIv().length
                );

        differentIv[0] ^= 0x01;

        Cipher decryptionCipher =
                createDecryptionCipher(
                        wrappingKey,
                        differentIv
                );

        try {

            protector.unwrap(
                    wrappedKey,
                    decryptionCipher
            );

            fail(
                    "Expected mismatched IV to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void wrappedKeyRejectsInvalidIvLength() {

        byte[] ciphertext =
                randomBytes(
                        48
                );

        try {

            new BiometricVaultKeyProtector.WrappedKey(
                    new byte[11],
                    ciphertext
            );

            fail(
                    "Expected short IV to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }

        try {

            new BiometricVaultKeyProtector.WrappedKey(
                    new byte[13],
                    ciphertext
            );

            fail(
                    "Expected long IV to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void wrappedKeyRejectsInvalidCiphertextLength() {

        byte[] iv =
                randomBytes(
                        12
                );

        try {

            new BiometricVaultKeyProtector.WrappedKey(
                    iv,
                    new byte[47]
            );

            fail(
                    "Expected short ciphertext to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }

        try {

            new BiometricVaultKeyProtector.WrappedKey(
                    iv,
                    new byte[49]
            );

            fail(
                    "Expected long ciphertext to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void wrappedKeyUsesDefensiveCopies() {

        byte[] iv =
                randomBytes(
                        12
                );

        byte[] ciphertext =
                randomBytes(
                        48
                );

        byte[] expectedIv =
                Arrays.copyOf(
                        iv,
                        iv.length
                );

        byte[] expectedCiphertext =
                Arrays.copyOf(
                        ciphertext,
                        ciphertext.length
                );

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                new BiometricVaultKeyProtector.WrappedKey(
                        iv,
                        ciphertext
                );

        iv[0] ^= 0x01;
        ciphertext[0] ^= 0x01;

        assertArrayEquals(
                expectedIv,
                wrappedKey.getIv()
        );

        assertArrayEquals(
                expectedCiphertext,
                wrappedKey.getCiphertext()
        );

        byte[] returnedIv =
                wrappedKey.getIv();

        byte[] returnedCiphertext =
                wrappedKey.getCiphertext();

        returnedIv[0] ^= 0x01;
        returnedCiphertext[0] ^= 0x01;

        assertArrayEquals(
                expectedIv,
                wrappedKey.getIv()
        );

        assertArrayEquals(
                expectedCiphertext,
                wrappedKey.getCiphertext()
        );
    }

    private void assertVaultKeyRejected(
            byte[] vaultKey
    ) throws Exception {

        SecretKey wrappingKey =
                generateWrappingKey();

        Cipher encryptionCipher =
                createEncryptionCipher(
                        wrappingKey
                );

        try {

            protector.wrap(
                    vaultKey,
                    encryptionCipher
            );

            fail(
                    "Expected invalid vault key length to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertEquals(
                    "Vault key must contain exactly 32 bytes.",
                    expected.getMessage()
            );
        }
    }

    private SecretKey generateWrappingKey()
            throws Exception {

        KeyGenerator keyGenerator =
                KeyGenerator.getInstance(
                        "AES"
                );

        keyGenerator.init(
                256
        );

        return keyGenerator.generateKey();
    }

    private Cipher createEncryptionCipher(
            SecretKey key
    ) throws Exception {

        Cipher cipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                key
        );

        return cipher;
    }

    private Cipher createDecryptionCipher(
            SecretKey key,
            byte[] iv
    ) throws Exception {

        Cipher cipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new GCMParameterSpec(
                        GCM_TAG_LENGTH_BITS,
                        iv
                )
        );

        return cipher;
    }

    private byte[] randomBytes(
            int length
    ) {

        byte[] bytes =
                new byte[length];

        new SecureRandom()
                .nextBytes(
                        bytes
                );

        return bytes;
    }
}
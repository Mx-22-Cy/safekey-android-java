package com.safekey.app.security.keystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class BiometricVaultKeyProtectorTest {

    private static final String TRANSFORMATION =
            "AES/GCM/NoPadding";

    private static final int AES_KEY_SIZE_BITS =
            256;

    private static final int GCM_TAG_LENGTH_BITS =
            128;

    private static final int VAULT_KEY_LENGTH_BYTES =
            32;

    @Test
    public void wrapAndUnwrapReturnsOriginalVaultKey()
            throws Exception {

        SecretKey wrappingKey =
                createTestWrappingKey();

        Cipher encryptionCipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        encryptionCipher.init(
                Cipher.ENCRYPT_MODE,
                wrappingKey
        );

        byte[] vaultKey =
                createRandomVaultKey();

        BiometricVaultKeyProtector protector =
                new BiometricVaultKeyProtector();

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                protector.wrap(
                        vaultKey,
                        encryptionCipher
                );

        assertFalse(
                java.util.Arrays.equals(
                        vaultKey,
                        wrappedKey.getCiphertext()
                )
        );

        Cipher decryptionCipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        decryptionCipher.init(
                Cipher.DECRYPT_MODE,
                wrappingKey,
                new GCMParameterSpec(
                        GCM_TAG_LENGTH_BITS,
                        wrappedKey.getIv()
                )
        );

        byte[] unwrappedVaultKey =
                protector.unwrap(
                        wrappedKey,
                        decryptionCipher
                );

        assertArrayEquals(
                vaultKey,
                unwrappedVaultKey
        );
    }

    @Test
    public void tamperedCiphertextIsRejected()
            throws Exception {

        SecretKey wrappingKey =
                createTestWrappingKey();

        Cipher encryptionCipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        encryptionCipher.init(
                Cipher.ENCRYPT_MODE,
                wrappingKey
        );

        byte[] vaultKey =
                createRandomVaultKey();

        BiometricVaultKeyProtector protector =
                new BiometricVaultKeyProtector();

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                protector.wrap(
                        vaultKey,
                        encryptionCipher
                );

        byte[] tamperedCiphertext =
                wrappedKey.getCiphertext();

        tamperedCiphertext[0] =
                (byte) (
                        tamperedCiphertext[0] ^ 0x01
                );

        BiometricVaultKeyProtector.WrappedKey tamperedWrappedKey =
                new BiometricVaultKeyProtector.WrappedKey(
                        wrappedKey.getIv(),
                        tamperedCiphertext
                );

        Cipher decryptionCipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        decryptionCipher.init(
                Cipher.DECRYPT_MODE,
                wrappingKey,
                new GCMParameterSpec(
                        GCM_TAG_LENGTH_BITS,
                        tamperedWrappedKey.getIv()
                )
        );

        try {

            protector.unwrap(
                    tamperedWrappedKey,
                    decryptionCipher
            );

            fail(
                    "Expected tampered ciphertext to be rejected."
            );

        } catch (AEADBadTagException expected) {

            // Expected: AES-GCM authentication detected tampering.

        } catch (GeneralSecurityException expected) {

            /*
             * Some JCA providers may expose another
             * GeneralSecurityException subtype for
             * authentication-tag failure.
             */
        }
    }

    @Test
    public void mismatchedIvIsRejected()
            throws Exception {

        SecretKey wrappingKey =
                createTestWrappingKey();

        Cipher encryptionCipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        encryptionCipher.init(
                Cipher.ENCRYPT_MODE,
                wrappingKey
        );

        BiometricVaultKeyProtector protector =
                new BiometricVaultKeyProtector();

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                protector.wrap(
                        createRandomVaultKey(),
                        encryptionCipher
                );

        byte[] differentIv =
                wrappedKey.getIv();

        differentIv[0] =
                (byte) (
                        differentIv[0] ^ 0x01
                );

        Cipher wrongDecryptionCipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        wrongDecryptionCipher.init(
                Cipher.DECRYPT_MODE,
                wrappingKey,
                new GCMParameterSpec(
                        GCM_TAG_LENGTH_BITS,
                        differentIv
                )
        );

        try {

            protector.unwrap(
                    wrappedKey,
                    wrongDecryptionCipher
            );

            fail(
                    "Expected mismatched IV to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            // Expected.
        }
    }

    private SecretKey createTestWrappingKey()
            throws Exception {

        KeyGenerator keyGenerator =
                KeyGenerator.getInstance(
                        "AES"
                );

        keyGenerator.init(
                AES_KEY_SIZE_BITS
        );

        return keyGenerator.generateKey();
    }

    private byte[] createRandomVaultKey() {

        byte[] vaultKey =
                new byte[VAULT_KEY_LENGTH_BYTES];

        new SecureRandom().nextBytes(
                vaultKey
        );

        return vaultKey;
    }
}
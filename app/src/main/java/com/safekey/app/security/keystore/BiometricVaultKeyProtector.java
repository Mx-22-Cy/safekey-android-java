package com.safekey.app.security.keystore;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

public class BiometricVaultKeyProtector {

    public static final int VAULT_KEY_LENGTH_BYTES =
            32;

    static final int GCM_IV_LENGTH_BYTES =
            12;

    static final int GCM_TAG_LENGTH_BYTES =
            16;

    static final int WRAPPED_CIPHERTEXT_LENGTH_BYTES =
            VAULT_KEY_LENGTH_BYTES
                    + GCM_TAG_LENGTH_BYTES;

    /*
     * Versioned associated data binds the encrypted
     * material to SafeKey's biometric vault-key use.
     *
     * AAD is authenticated by AES-GCM but is not secret.
     */
    private static final byte[] VAULT_KEY_AAD =
            "SafeKey/BiometricVaultKey/v1"
                    .getBytes(
                            StandardCharsets.UTF_8
                    );

    public static void validateVaultKey(
            byte[] vaultKey
    ) {

        if (vaultKey == null
                || vaultKey.length
                != VAULT_KEY_LENGTH_BYTES) {

            throw new IllegalArgumentException(
                    "Vault key must contain exactly 32 bytes."
            );
        }
    }

    public WrappedKey wrap(
            byte[] vaultKey,
            Cipher authenticatedEncryptionCipher
    ) throws GeneralSecurityException {

        validateVaultKey(
                vaultKey
        );

        if (authenticatedEncryptionCipher == null) {

            throw new IllegalArgumentException(
                    "Authenticated encryption cipher cannot be null."
            );
        }

        byte[] iv =
                authenticatedEncryptionCipher.getIV();

        if (iv == null
                || iv.length != GCM_IV_LENGTH_BYTES) {

            throw new IllegalStateException(
                    "Authenticated encryption cipher must have a 12-byte GCM IV."
            );
        }

        authenticatedEncryptionCipher.updateAAD(
                VAULT_KEY_AAD
        );

        byte[] ciphertext =
                authenticatedEncryptionCipher.doFinal(
                        vaultKey
                );

        return new WrappedKey(
                iv,
                ciphertext
        );
    }

    public byte[] unwrap(
            WrappedKey wrappedKey,
            Cipher authenticatedDecryptionCipher
    ) throws GeneralSecurityException {

        if (wrappedKey == null) {

            throw new IllegalArgumentException(
                    "Wrapped vault key cannot be null."
            );
        }

        if (authenticatedDecryptionCipher == null) {

            throw new IllegalArgumentException(
                    "Authenticated decryption cipher cannot be null."
            );
        }

        byte[] cipherIv =
                authenticatedDecryptionCipher.getIV();

        if (cipherIv == null
                || !Arrays.equals(
                cipherIv,
                wrappedKey.getIv()
        )) {

            throw new IllegalArgumentException(
                    "Decryption cipher IV does not match the wrapped vault key."
            );
        }

        authenticatedDecryptionCipher.updateAAD(
                VAULT_KEY_AAD
        );

        byte[] vaultKey =
                authenticatedDecryptionCipher.doFinal(
                        wrappedKey.getCiphertext()
                );

        if (vaultKey.length
                != VAULT_KEY_LENGTH_BYTES) {

            Arrays.fill(
                    vaultKey,
                    (byte) 0
            );

            throw new GeneralSecurityException(
                    "Unwrapped vault key must contain exactly 32 bytes."
            );
        }

        return vaultKey;
    }

    public static final class WrappedKey {

        private final byte[] iv;
        private final byte[] ciphertext;

        public WrappedKey(
                byte[] iv,
                byte[] ciphertext
        ) {

            if (iv == null
                    || iv.length
                    != GCM_IV_LENGTH_BYTES) {

                throw new IllegalArgumentException(
                        "Wrapped key IV must contain exactly 12 bytes."
                );
            }

            if (ciphertext == null
                    || ciphertext.length
                    != WRAPPED_CIPHERTEXT_LENGTH_BYTES) {

                throw new IllegalArgumentException(
                        "Wrapped key ciphertext must contain exactly 48 bytes."
                );
            }

            this.iv =
                    Arrays.copyOf(
                            iv,
                            iv.length
                    );

            this.ciphertext =
                    Arrays.copyOf(
                            ciphertext,
                            ciphertext.length
                    );
        }

        public byte[] getIv() {

            return Arrays.copyOf(
                    iv,
                    iv.length
            );
        }

        public byte[] getCiphertext() {

            return Arrays.copyOf(
                    ciphertext,
                    ciphertext.length
            );
        }
    }
}
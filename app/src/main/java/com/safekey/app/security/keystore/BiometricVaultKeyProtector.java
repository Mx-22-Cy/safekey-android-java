package com.safekey.app.security.keystore;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

public class BiometricVaultKeyProtector {

    private static final int GCM_IV_LENGTH_BYTES =
            12;

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

    public WrappedKey wrap(
            byte[] vaultKey,
            Cipher authenticatedEncryptionCipher
    ) throws GeneralSecurityException {

        if (vaultKey == null
                || vaultKey.length == 0) {

            throw new IllegalArgumentException(
                    "Vault key cannot be null or empty."
            );
        }

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

        return authenticatedDecryptionCipher.doFinal(
                wrappedKey.getCiphertext()
        );
    }

    public static final class WrappedKey {

        private final byte[] iv;
        private final byte[] ciphertext;

        public WrappedKey(
                byte[] iv,
                byte[] ciphertext
        ) {

            if (iv == null
                    || iv.length != GCM_IV_LENGTH_BYTES) {

                throw new IllegalArgumentException(
                        "Wrapped key IV must contain exactly 12 bytes."
                );
            }

            if (ciphertext == null
                    || ciphertext.length == 0) {

                throw new IllegalArgumentException(
                        "Wrapped key ciphertext cannot be null or empty."
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
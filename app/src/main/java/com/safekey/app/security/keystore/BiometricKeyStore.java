package com.safekey.app.security.keystore;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class BiometricKeyStore {

    private static final String ANDROID_KEY_STORE =
            "AndroidKeyStore";

    private static final String KEY_ALIAS =
            "safekey_biometric_vault_key";

    private static final String TRANSFORMATION =
            "AES/GCM/NoPadding";

    private static final int GCM_TAG_LENGTH_BITS =
            128;

    private static final int GCM_IV_LENGTH_BYTES =
            12;

    public SecretKey getOrCreateKey()
            throws Exception {

        KeyStore keyStore =
                loadKeyStore();

        if (keyStore.containsAlias(
                KEY_ALIAS
        )) {

            return requireSecretKey(
                    keyStore
            );
        }

        KeyGenerator keyGenerator =
                KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        ANDROID_KEY_STORE
                );

        KeyGenParameterSpec.Builder builder =
                new KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT
                                | KeyProperties.PURPOSE_DECRYPT
                )
                        .setBlockModes(
                                KeyProperties.BLOCK_MODE_GCM
                        )
                        .setEncryptionPaddings(
                                KeyProperties.ENCRYPTION_PADDING_NONE
                        )
                        .setKeySize(
                                256
                        )
                        .setUserAuthenticationRequired(
                                true
                        )
                        .setInvalidatedByBiometricEnrollment(
                                true
                        );

        /*
         * Android 11+ can explicitly require a
         * strong biometric for each key use.
         *
         * Android 8-10 use the legacy per-use
         * authentication setting below.
         */
        if (Build.VERSION.SDK_INT
                >= Build.VERSION_CODES.R) {

            builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
            );

        } else {

            builder.setUserAuthenticationValidityDurationSeconds(
                    -1
            );
        }

        keyGenerator.init(
                builder.build()
        );

        return keyGenerator.generateKey();
    }

    public SecretKey getExistingKey()
            throws Exception {

        KeyStore keyStore =
                loadKeyStore();

        if (!keyStore.containsAlias(
                KEY_ALIAS
        )) {

            throw new BiometricKeyMissingException(
                    "Biometric Android Keystore key is missing."
            );
        }

        return requireSecretKey(
                keyStore
        );
    }

    public boolean containsKey()
            throws Exception {

        KeyStore keyStore =
                loadKeyStore();

        return keyStore.containsAlias(
                KEY_ALIAS
        );
    }

    public Cipher createEncryptionCipher()
            throws Exception {

        SecretKey secretKey =
                getOrCreateKey();

        Cipher cipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey
        );

        return cipher;
    }

    public Cipher createDecryptionCipher(
            byte[] iv
    ) throws Exception {

        if (iv == null
                || iv.length
                != GCM_IV_LENGTH_BYTES) {

            throw new IllegalArgumentException(
                    "Encryption IV must contain exactly 12 bytes."
            );
        }

        /*
         * Unlock must never create a replacement key.
         *
         * The stored envelope can only be decrypted by
         * the Android Keystore key that originally
         * protected it.
         */
        SecretKey secretKey =
                getExistingKey();

        Cipher cipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        GCMParameterSpec gcmParameterSpec =
                new GCMParameterSpec(
                        GCM_TAG_LENGTH_BITS,
                        iv
                );

        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                gcmParameterSpec
        );

        return cipher;
    }

    public void deleteKey()
            throws Exception {

        KeyStore keyStore =
                loadKeyStore();

        if (keyStore.containsAlias(
                KEY_ALIAS
        )) {

            keyStore.deleteEntry(
                    KEY_ALIAS
            );
        }
    }

    private KeyStore loadKeyStore()
            throws Exception {

        KeyStore keyStore =
                KeyStore.getInstance(
                        ANDROID_KEY_STORE
                );

        keyStore.load(
                null
        );

        return keyStore;
    }

    private SecretKey requireSecretKey(
            KeyStore keyStore
    ) throws Exception {

        Key key =
                keyStore.getKey(
                        KEY_ALIAS,
                        null
                );

        if (!(key instanceof SecretKey)) {

            throw new BiometricKeyMissingException(
                    "Biometric Android Keystore key is unavailable."
            );
        }

        return (SecretKey) key;
    }

    public static class BiometricKeyMissingException
            extends GeneralSecurityException {

        public BiometricKeyMissingException(
                String message
        ) {

            super(
                    message
            );
        }
    }
}
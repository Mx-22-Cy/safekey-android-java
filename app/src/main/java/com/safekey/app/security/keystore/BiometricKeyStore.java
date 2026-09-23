package com.safekey.app.security.keystore;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

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

    public SecretKey getOrCreateKey()
            throws Exception {

        KeyStore keyStore =
                KeyStore.getInstance(
                        ANDROID_KEY_STORE
                );

        keyStore.load(
                null
        );

        if (keyStore.containsAlias(
                KEY_ALIAS
        )) {

            return (SecretKey)
                    keyStore.getKey(
                            KEY_ALIAS,
                            null
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

    public boolean containsKey()
            throws Exception {

        KeyStore keyStore =
                KeyStore.getInstance(
                        ANDROID_KEY_STORE
                );

        keyStore.load(
                null
        );

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
                || iv.length == 0) {

            throw new IllegalArgumentException(
                    "Encryption IV cannot be null or empty."
            );
        }

        SecretKey secretKey =
                getOrCreateKey();

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
                KeyStore.getInstance(
                        ANDROID_KEY_STORE
                );

        keyStore.load(
                null
        );

        if (keyStore.containsAlias(
                KEY_ALIAS
        )) {

            keyStore.deleteEntry(
                    KEY_ALIAS
            );
        }
    }
}
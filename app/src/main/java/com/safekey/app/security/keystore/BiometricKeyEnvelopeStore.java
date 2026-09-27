package com.safekey.app.security.keystore;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Base64;

public class BiometricKeyEnvelopeStore {

    static final String PREFERENCES_NAME =
            "safekey_biometric_key_envelope";

    static final String KEY_VERSION =
            "version";

    static final String KEY_IV =
            "iv";

    static final String KEY_CIPHERTEXT =
            "ciphertext";

    static final int ENVELOPE_VERSION =
            1;

    private final SharedPreferences preferences;

    public BiometricKeyEnvelopeStore(
            Context context
    ) {

        if (context == null) {

            throw new IllegalArgumentException(
                    "Context cannot be null."
            );
        }

        preferences =
                context.getApplicationContext()
                        .getSharedPreferences(
                                PREFERENCES_NAME,
                                Context.MODE_PRIVATE
                        );
    }

    public void save(
            BiometricVaultKeyProtector.WrappedKey wrappedKey
    ) {

        if (wrappedKey == null) {

            throw new IllegalArgumentException(
                    "Wrapped vault key cannot be null."
            );
        }

        String encodedIv =
                Base64.getEncoder()
                        .encodeToString(
                                wrappedKey.getIv()
                        );

        String encodedCiphertext =
                Base64.getEncoder()
                        .encodeToString(
                                wrappedKey.getCiphertext()
                        );

        boolean saved =
                preferences.edit()
                        .putInt(
                                KEY_VERSION,
                                ENVELOPE_VERSION
                        )
                        .putString(
                                KEY_IV,
                                encodedIv
                        )
                        .putString(
                                KEY_CIPHERTEXT,
                                encodedCiphertext
                        )
                        .commit();

        if (!saved) {

            throw new IllegalStateException(
                    "Unable to store biometric key envelope."
            );
        }
    }

    public boolean hasEnvelope() {

        return preferences.contains(
                KEY_VERSION
        )
                && preferences.contains(
                KEY_IV
        )
                && preferences.contains(
                KEY_CIPHERTEXT
        );
    }

    public BiometricVaultKeyProtector.WrappedKey load() {

        boolean hasVersion =
                preferences.contains(
                        KEY_VERSION
                );

        boolean hasIv =
                preferences.contains(
                        KEY_IV
                );

        boolean hasCiphertext =
                preferences.contains(
                        KEY_CIPHERTEXT
                );

        /*
         * No stored fields means biometric unlock
         * has never been configured.
         */
        if (!hasVersion
                && !hasIv
                && !hasCiphertext) {

            return null;
        }

        /*
         * If any field exists, all version-1 envelope
         * fields must be present.
         */
        if (!hasVersion
                || !hasIv
                || !hasCiphertext) {

            throw new IllegalStateException(
                    "Biometric key envelope is incomplete."
            );
        }

        final int version;
        final String encodedIv;
        final String encodedCiphertext;

        try {

            version =
                    preferences.getInt(
                            KEY_VERSION,
                            -1
                    );

            encodedIv =
                    preferences.getString(
                            KEY_IV,
                            null
                    );

            encodedCiphertext =
                    preferences.getString(
                            KEY_CIPHERTEXT,
                            null
                    );

        } catch (ClassCastException exception) {

            throw new IllegalStateException(
                    "Biometric key envelope contains invalid stored field types.",
                    exception
            );
        }

        if (version != ENVELOPE_VERSION) {

            throw new IllegalStateException(
                    "Unsupported biometric key envelope version: "
                            + version
            );
        }

        if (encodedIv == null
                || encodedIv.isEmpty()
                || encodedCiphertext == null
                || encodedCiphertext.isEmpty()) {

            throw new IllegalStateException(
                    "Biometric key envelope contains empty data."
            );
        }

        final byte[] iv;
        final byte[] ciphertext;

        try {

            iv =
                    Base64.getDecoder()
                            .decode(
                                    encodedIv
                            );

            ciphertext =
                    Base64.getDecoder()
                            .decode(
                                    encodedCiphertext
                            );

        } catch (IllegalArgumentException exception) {

            throw new IllegalStateException(
                    "Biometric key envelope contains invalid Base64 data.",
                    exception
            );
        }

        try {

            return new BiometricVaultKeyProtector.WrappedKey(
                    iv,
                    ciphertext
            );

        } catch (IllegalArgumentException exception) {

            throw new IllegalStateException(
                    "Biometric key envelope contains invalid version-1 data.",
                    exception
            );
        }
    }

    public void clear() {

        boolean cleared =
                preferences.edit()
                        .clear()
                        .commit();

        if (!cleared) {

            throw new IllegalStateException(
                    "Unable to clear biometric key envelope."
            );
        }
    }
}
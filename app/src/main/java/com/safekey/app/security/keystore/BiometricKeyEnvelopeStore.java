package com.safekey.app.security.keystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

public class BiometricKeyEnvelopeStore {

    private static final String PREFERENCES_NAME =
            "safekey_biometric_key_envelope";

    private static final String KEY_VERSION =
            "version";

    private static final String KEY_IV =
            "iv";

    private static final String KEY_CIPHERTEXT =
            "ciphertext";

    private static final int ENVELOPE_VERSION =
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
                Base64.encodeToString(
                        wrappedKey.getIv(),
                        Base64.NO_WRAP
                );

        String encodedCiphertext =
                Base64.encodeToString(
                        wrappedKey.getCiphertext(),
                        Base64.NO_WRAP
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

        if (!hasEnvelope()) {

            return null;
        }

        int version =
                preferences.getInt(
                        KEY_VERSION,
                        -1
                );

        if (version != ENVELOPE_VERSION) {

            throw new IllegalStateException(
                    "Unsupported biometric key envelope version: "
                            + version
            );
        }

        String encodedIv =
                preferences.getString(
                        KEY_IV,
                        null
                );

        String encodedCiphertext =
                preferences.getString(
                        KEY_CIPHERTEXT,
                        null
                );

        if (encodedIv == null
                || encodedCiphertext == null) {

            throw new IllegalStateException(
                    "Biometric key envelope is incomplete."
            );
        }

        final byte[] iv;
        final byte[] ciphertext;

        try {

            iv =
                    Base64.decode(
                            encodedIv,
                            Base64.NO_WRAP
                    );

            ciphertext =
                    Base64.decode(
                            encodedCiphertext,
                            Base64.NO_WRAP
                    );

        } catch (IllegalArgumentException exception) {

            throw new IllegalStateException(
                    "Biometric key envelope contains invalid encoded data.",
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
                    "Biometric key envelope contains invalid data.",
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

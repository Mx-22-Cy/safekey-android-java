package com.safekey.app.security.storage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.util.Objects;

public final class VaultKeyEnvelopeStore {

    static final String PREFERENCES_NAME =
            "safekey_vault_key_envelope";

    static final String KEY_FORMAT_VERSION =
            "format_version";

    static final String KEY_SALT =
            "salt";

    static final String KEY_WRAPPED_DATABASE_KEY =
            "wrapped_database_key";

    private static final String INVALID_ENVELOPE_MESSAGE =
            "Stored vault key envelope is invalid.";

    private final SharedPreferences preferences;

    public VaultKeyEnvelopeStore(
            Context context
    ) {
        Objects.requireNonNull(
                context,
                "context"
        );

        preferences =
                context
                        .getApplicationContext()
                        .getSharedPreferences(
                                PREFERENCES_NAME,
                                Context.MODE_PRIVATE
                        );
    }

    public boolean hasEnvelope() {
        return preferences.contains(
                KEY_FORMAT_VERSION
        )
                || preferences.contains(
                KEY_SALT
        )
                || preferences.contains(
                KEY_WRAPPED_DATABASE_KEY
        );
    }

    public void save(
            VaultKeyEnvelope envelope
    ) {
        Objects.requireNonNull(
                envelope,
                "envelope"
        );

        String encodedSalt =
                Base64.encodeToString(
                        envelope.getSalt(),
                        Base64.URL_SAFE
                                | Base64.NO_WRAP
                                | Base64.NO_PADDING
                );

        boolean saved =
                preferences
                        .edit()
                        .putInt(
                                KEY_FORMAT_VERSION,
                                envelope.getFormatVersion()
                        )
                        .putString(
                                KEY_SALT,
                                encodedSalt
                        )
                        .putString(
                                KEY_WRAPPED_DATABASE_KEY,
                                envelope.getWrappedDatabaseKey()
                        )
                        .commit();

        if (!saved) {
            throw new IllegalStateException(
                    "Unable to save vault key envelope."
            );
        }
    }

    public VaultKeyEnvelope load() {
        boolean hasVersion =
                preferences.contains(
                        KEY_FORMAT_VERSION
                );

        boolean hasSalt =
                preferences.contains(
                        KEY_SALT
                );

        boolean hasWrappedDatabaseKey =
                preferences.contains(
                        KEY_WRAPPED_DATABASE_KEY
                );

        if (!hasVersion
                && !hasSalt
                && !hasWrappedDatabaseKey) {

            return null;
        }

        if (!hasVersion
                || !hasSalt
                || !hasWrappedDatabaseKey) {

            throw new IllegalStateException(
                    INVALID_ENVELOPE_MESSAGE
            );
        }

        int formatVersion =
                preferences.getInt(
                        KEY_FORMAT_VERSION,
                        -1
                );

        String encodedSalt =
                preferences.getString(
                        KEY_SALT,
                        null
                );

        String wrappedDatabaseKey =
                preferences.getString(
                        KEY_WRAPPED_DATABASE_KEY,
                        null
                );

        try {
            if (encodedSalt == null
                    || wrappedDatabaseKey == null) {

                throw new IllegalArgumentException(
                        "Missing envelope value."
                );
            }

            byte[] salt =
                    Base64.decode(
                            encodedSalt,
                            Base64.URL_SAFE
                                    | Base64.NO_WRAP
                                    | Base64.NO_PADDING
                    );

            return new VaultKeyEnvelope(
                    formatVersion,
                    salt,
                    wrappedDatabaseKey
            );

        } catch (
                IllegalArgumentException
                | NullPointerException invalidEnvelope
        ) {
            throw new IllegalStateException(
                    INVALID_ENVELOPE_MESSAGE,
                    invalidEnvelope
            );
        }
    }

    public void clear() {
        boolean cleared =
                preferences
                        .edit()
                        .clear()
                        .commit();

        if (!cleared) {
            throw new IllegalStateException(
                    "Unable to clear vault key envelope."
            );
        }
    }
}

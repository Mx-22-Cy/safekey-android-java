package com.safekey.app.security.storage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.util.Objects;

public final class VaultKeyEnvelopeStore
        implements VaultKeyEnvelopeStorage {

    /*
     * Existing real-vault preferences name.
     *
     * Keep this unchanged so existing users,
     * tests and real-vault code continue to use
     * the same stored envelope.
     */
    static final String PREFERENCES_NAME =
            "safekey_vault_key_envelope";

    /*
     * Week 10 Decoy Vault.
     *
     * The Decoy Vault must never share its wrapped
     * database key or salt with the real vault.
     */
    static final String DECOY_PREFERENCES_NAME =
            "safekey_decoy_vault_key_envelope";

    static final String KEY_FORMAT_VERSION =
            "format_version";

    static final String KEY_SALT =
            "salt";

    static final String KEY_WRAPPED_DATABASE_KEY =
            "wrapped_database_key";

    private static final String INVALID_ENVELOPE_MESSAGE =
            "Stored vault key envelope is invalid.";

    private final SharedPreferences preferences;

    /**
     * Creates storage for the primary real-vault envelope.
     */
    public VaultKeyEnvelopeStore(
            Context context
    ) {
        this(
                context,
                PREFERENCES_NAME
        );
    }

    /**
     * Creates storage dedicated to the Decoy Vault envelope.
     */
    public static VaultKeyEnvelopeStore forDecoy(
            Context context
    ) {
        return new VaultKeyEnvelopeStore(
                context,
                DECOY_PREFERENCES_NAME
        );
    }

    private VaultKeyEnvelopeStore(
            Context context,
            String preferencesName
    ) {
        Objects.requireNonNull(
                context,
                "context"
        );

        Objects.requireNonNull(
                preferencesName,
                "preferencesName"
        );

        preferences =
                context
                        .getApplicationContext()
                        .getSharedPreferences(
                                preferencesName,
                                Context.MODE_PRIVATE
                        );
    }

    @Override
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

    @Override
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

    @Override
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

        try {
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
                ClassCastException
                | IllegalArgumentException
                | NullPointerException invalidEnvelope
        ) {
            throw new IllegalStateException(
                    INVALID_ENVELOPE_MESSAGE,
                    invalidEnvelope
            );
        }
    }

    @Override
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

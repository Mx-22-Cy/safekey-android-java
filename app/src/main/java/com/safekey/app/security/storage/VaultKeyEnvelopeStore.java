package com.safekey.app.security.storage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.util.Objects;
import java.util.Arrays;

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

    private static final Object STORE_LOCK = new Object();
    private static final String KEY_PASSWORD_CHECK = "master_password_check";

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
        synchronized (STORE_LOCK) {
            return hasEnvelopeLocked();
        }
    }

    private boolean hasEnvelopeLocked() {
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

    public void save(VaultKeyEnvelope envelope) {
        save(envelope, MasterPasswordCheckStatus.PENDING);
    }

    void save(VaultKeyEnvelope envelope, MasterPasswordCheckStatus status) {
        synchronized (STORE_LOCK) {
            saveLocked(envelope, status);
        }
    }

    private void saveLocked(VaultKeyEnvelope envelope, MasterPasswordCheckStatus status) {
        Objects.requireNonNull(status, "status");
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
                        .putString(KEY_PASSWORD_CHECK, status.name())
                        .commit();

        if (!saved) {
            throw new IllegalStateException(
                    "Unable to save vault key envelope."
            );
        }
    }

    public VaultKeyEnvelope load() {
        synchronized (STORE_LOCK) {
            return loadLocked();
        }
    }

    private VaultKeyEnvelope loadLocked() {
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

    public MasterPasswordCheckStatus getMasterPasswordCheckStatus() {
        synchronized (STORE_LOCK) {
            try {
                String stored = preferences.getString(KEY_PASSWORD_CHECK, null);
                return stored == null ? MasterPasswordCheckStatus.PENDING
                        : MasterPasswordCheckStatus.valueOf(stored);
            } catch (IllegalArgumentException | ClassCastException invalid) {
                return MasterPasswordCheckStatus.PENDING;
            }
        }
    }

    public boolean updateMasterPasswordCheckStatus(
            VaultKeyEnvelope expected, MasterPasswordCheckStatus status
    ) {
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(status, "status");
        synchronized (STORE_LOCK) {
            if (!matches(loadLocked(), expected)) {
                return false;
            }
            if (!preferences.edit().putString(KEY_PASSWORD_CHECK, status.name()).commit()) {
                throw new IllegalStateException("Unable to save password check status.");
            }
            return true;
        }
    }

    boolean replaceIfMatches(
            VaultKeyEnvelope expected,
            VaultKeyEnvelope replacement,
            MasterPasswordCheckStatus status
    ) {
        synchronized (STORE_LOCK) {
            if (!matches(loadLocked(), expected)) {
                return false;
            }
            saveLocked(replacement, status);
            return true;
        }
    }

    private static boolean matches(VaultKeyEnvelope first, VaultKeyEnvelope second) {
        return first != null && second != null
                && first.getFormatVersion() == second.getFormatVersion()
                && Arrays.equals(first.getSalt(), second.getSalt())
                && first.getWrappedDatabaseKey().equals(second.getWrappedDatabaseKey());
    }

    public void clear() {
        synchronized (STORE_LOCK) {
            clearLocked();
        }
    }

    private void clearLocked() {
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

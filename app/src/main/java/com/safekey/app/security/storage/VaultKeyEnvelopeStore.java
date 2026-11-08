package com.safekey.app.security.storage;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWorkGate;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.util.Arrays;
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

    private static final String KEY_RECOVERY_FORMAT_VERSION = "recovery_format_version";
    private static final String KEY_RECOVERY_SALT = "recovery_salt";
    private static final String KEY_RECOVERY_WRAPPED_DATABASE_KEY = "recovery_wrapped_database_key";

    private static final String INVALID_ENVELOPE_MESSAGE =
            "Stored vault key envelope is invalid.";

    /*
     * T45: Synchronize envelope reads, writes,
     * password-check updates and replacements.
     */
    private static final Object STORE_LOCK =
            com.safekey.app.security.panic.PanicCredentialConfiguration.lock();

    private static final String KEY_PASSWORD_CHECK =
            "master_password_check";

    private final PanicRuntimeScope runtimeScope;
    private final SharedPreferences preferences;
    private final boolean realVaultStore;

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

        realVaultStore = PREFERENCES_NAME.equals(preferencesName);
        runtimeScope = PanicRuntimeScope.capture(context);

        preferences =
                context
                        .getApplicationContext()
                        .getSharedPreferences(
                                preferencesName,
                                Context.MODE_PRIVATE
                        );
    }

    private boolean hasEnvelopeWhileRunning() {
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

    @Override
    public void save(
            VaultKeyEnvelope envelope
    ) {
        save(
                envelope,
                MasterPasswordCheckStatus.PENDING
        );
    }

    private void saveWhileRunning(
            VaultKeyEnvelope envelope,
            MasterPasswordCheckStatus status
    ) {
        synchronized (STORE_LOCK) {
            saveLocked(
                    envelope,
                    status
            );
        }
    }

    private void saveLocked(VaultKeyEnvelope envelope, MasterPasswordCheckStatus status) {
        saveLocked(envelope, status, null);
    }

    private void saveLocked(
            VaultKeyEnvelope envelope,
            MasterPasswordCheckStatus status,
            VaultKeyEnvelope recoveryEnvelope
    ) {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(envelope, "envelope");

        SharedPreferences.Editor editor = preferences.edit();
        putEnvelope(editor, envelope, KEY_FORMAT_VERSION, KEY_SALT, KEY_WRAPPED_DATABASE_KEY);
        editor.putString(KEY_PASSWORD_CHECK, status.name());
        if (recoveryEnvelope != null) {
            putEnvelope(editor, recoveryEnvelope, KEY_RECOVERY_FORMAT_VERSION,
                    KEY_RECOVERY_SALT, KEY_RECOVERY_WRAPPED_DATABASE_KEY);
        }

        boolean saved;
        try {
            saved = editor.commit();
        } finally {
            com.safekey.app.security.panic.PanicCredentialConfiguration.changed();
        }
        if (!saved) {
            throw new IllegalStateException("Unable to save vault key envelope.");
        }
    }

    private static void putEnvelope(
            SharedPreferences.Editor editor,
            VaultKeyEnvelope envelope,
            String versionKey,
            String saltKey,
            String wrappedKey
    ) {
        String encodedSalt = Base64.encodeToString(envelope.getSalt(),
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        editor.putInt(versionKey, envelope.getFormatVersion())
                .putString(saltKey, encodedSalt)
                .putString(wrappedKey, envelope.getWrappedDatabaseKey());
    }

    private VaultKeyEnvelope loadWhileRunning() {
        synchronized (STORE_LOCK) {
            return loadLocked();
        }
    }

    private VaultKeyEnvelope loadLocked() {
        return loadEnvelopeLocked(KEY_FORMAT_VERSION, KEY_SALT, KEY_WRAPPED_DATABASE_KEY);
    }

    private VaultKeyEnvelope loadEnvelopeLocked(String versionKey, String saltKey, String wrappedKey) {
        boolean hasVersion =
                preferences.contains(
                        versionKey
                );

        boolean hasSalt =
                preferences.contains(
                        saltKey
                );

        boolean hasWrappedDatabaseKey =
                preferences.contains(
                        wrappedKey
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
                            versionKey,
                            -1
                    );

            String encodedSalt =
                    preferences.getString(
                            saltKey,
                            null
                    );

            String wrappedDatabaseKey =
                    preferences.getString(
                            wrappedKey,
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

    /**
     * T45: Returns the current master-password check status.
     * Missing or invalid status defaults to PENDING.
     */
    private MasterPasswordCheckStatus getMasterPasswordCheckStatusWhileRunning() {
        synchronized (STORE_LOCK) {
            try {
                String stored =
                        preferences.getString(
                                KEY_PASSWORD_CHECK,
                                null
                        );

                return stored == null
                        ? MasterPasswordCheckStatus.PENDING
                        : MasterPasswordCheckStatus.valueOf(stored);

            } catch (
                    IllegalArgumentException
                    | ClassCastException invalid
            ) {
                return MasterPasswordCheckStatus.PENDING;
            }
        }
    }

    /**
     * T45: Update the password-check status only when
     * the stored envelope matches the expected envelope.
     */
    private boolean updateMasterPasswordCheckStatusWhileRunning(
            VaultKeyEnvelope expected,
            MasterPasswordCheckStatus status
    ) {
        Objects.requireNonNull(
                expected,
                "expected"
        );

        Objects.requireNonNull(
                status,
                "status"
        );

        synchronized (STORE_LOCK) {
            if (!matches(loadLocked(), expected)) {
                return false;
            }

            boolean saved =
                    preferences
                            .edit()
                            .putString(
                                    KEY_PASSWORD_CHECK,
                                    status.name()
                            )
                            .commit();

            if (!saved) {
                throw new IllegalStateException(
                        "Unable to save password check status."
                );
            }

            return true;
        }
    }

    /**
     * T45: Replace the protected envelope only when
     * the previously stored envelope still matches.
     *
     * This protects against replacing an envelope
     * that has changed since authentication began.
     */
    private boolean replaceIfMatchesWhileRunning(
            VaultKeyEnvelope expected,
            VaultKeyEnvelope replacement,
            MasterPasswordCheckStatus status
    ) {
        synchronized (STORE_LOCK) {
            if (!matches(loadLocked(), expected)) {
                return false;
            }

            saveLocked(
                    replacement,
                    status
            );

            return true;
        }
    }

    private static boolean matches(
            VaultKeyEnvelope first,
            VaultKeyEnvelope second
    ) {
        return first != null
                && second != null
                && first.getFormatVersion() == second.getFormatVersion()
                && Arrays.equals(
                first.getSalt(),
                second.getSalt()
        )
                && first.getWrappedDatabaseKey().equals(
                second.getWrappedDatabaseKey()
        );
    }

    private void clearWhileRunning() {
        synchronized (STORE_LOCK) {
            clearLocked();
        }
    }

    private void clearLocked() {
        boolean cleared;
        try {
            cleared = preferences
                        .edit()
                        .clear()
                        .commit();
        } finally {
            com.safekey.app.security.panic.PanicCredentialConfiguration.changed();
        }

        if (!cleared) {
            throw new IllegalStateException(
                    "Unable to clear vault key envelope."
            );
        }
    }

    @Override
    public boolean hasEnvelope() {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return hasEnvelopeWhileRunning();
        }
    }


    void save(
            VaultKeyEnvelope envelope,
            MasterPasswordCheckStatus status
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            saveWhileRunning(envelope, status);
        }
    }


    @Override
    public VaultKeyEnvelope load() {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return loadWhileRunning();
        }
    }


    public MasterPasswordCheckStatus getMasterPasswordCheckStatus() {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return getMasterPasswordCheckStatusWhileRunning();
        }
    }


    public boolean updateMasterPasswordCheckStatus(
            VaultKeyEnvelope expected,
            MasterPasswordCheckStatus status
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return updateMasterPasswordCheckStatusWhileRunning(expected, status);
        }
    }


    boolean replaceIfMatches(
            VaultKeyEnvelope expected,
            VaultKeyEnvelope replacement,
            MasterPasswordCheckStatus status
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return replaceIfMatchesWhileRunning(expected, replacement, status);
        }
    }


    void saveForEnrollmentWithRecovery(
            VaultKeyEnvelope masterEnvelope,
            MasterPasswordCheckStatus status,
            VaultKeyEnvelope recoveryEnvelope
    ) {
        requireRealVaultStore();
        Objects.requireNonNull(recoveryEnvelope, "recoveryEnvelope");
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            synchronized (STORE_LOCK) {
                if (!preferences.getAll().isEmpty()) {
                    throw new IllegalStateException("Real vault key storage is not empty.");
                }
                try {
                    saveLocked(masterEnvelope, status, recoveryEnvelope);
                } catch (RuntimeException failure) {
                    // A failed commit may already have updated the in-memory preferences.
                    try {
                        clearLocked();
                    } catch (RuntimeException rollbackFailure) {
                        failure.addSuppressed(rollbackFailure);
                    }
                    throw failure;
                }
            }
        }
    }

    VaultKeyEnvelope loadRecoveryEnvelope() {
        requireRealVaultStore();
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            synchronized (STORE_LOCK) {
                return loadRecoveryEnvelopeLocked();
            }
        }
    }

    private VaultKeyEnvelope loadRecoveryEnvelopeLocked() {
        return loadEnvelopeLocked(KEY_RECOVERY_FORMAT_VERSION, KEY_RECOVERY_SALT,
                KEY_RECOVERY_WRAPPED_DATABASE_KEY);
    }

    boolean replaceMasterEnvelopeAfterRecovery(
            VaultKeyEnvelope expectedMaster,
            VaultKeyEnvelope expectedRecovery,
            VaultKeyEnvelope replacement,
            MasterPasswordCheckStatus status
    ) {
        requireRealVaultStore();
        Objects.requireNonNull(replacement, "replacement");
        Objects.requireNonNull(status, "status");

        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            synchronized (STORE_LOCK) {
                if (!matches(loadLocked(), expectedMaster)
                        || !matches(loadRecoveryEnvelopeLocked(), expectedRecovery)) {
                    return false;
                }

                MasterPasswordCheckStatus previousStatus =
                        getMasterPasswordCheckStatusWhileRunning();
                try {
                    saveLocked(replacement, status);
                } catch (RuntimeException failure) {
                    try {
                        saveLocked(expectedMaster, previousStatus);
                    } catch (RuntimeException rollbackFailure) {
                        failure.addSuppressed(rollbackFailure);
                    }
                    throw failure;
                }
                return true;
            }
        }
    }

    private void requireRealVaultStore() {
        if (!realVaultStore) {
            throw new IllegalStateException("Recovery requires the Real vault key store.");
        }
    }

    @Override
    public void clear() {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            clearWhileRunning();
        }
    }

}

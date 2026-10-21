package com.safekey.app.security.storage;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.DecoyVaultDataService;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Week 10 Decoy Vault security/storage coordinator.
 *
 * This coordinator owns a completely separate:
 * - SQLCipher database connection
 * - VaultDataService
 * - database key
 * - key envelope
 * - encryption associated-data context
 *
 * It never delegates Decoy operations to SecureVaultCoordinator
 * or its primary VaultDataService.
 */
public final class DecoyVaultCoordinator {

    private static final String DATABASE_KEY_CONTEXT =
            "safekey:decoy-database-key-envelope:v1";

    private final Context applicationContext;
    private final DecoyVaultDataService vaultDataService;
    private final VaultKeyEnvelopeStore envelopeStore;
    private final Argon2idMasterKeyDeriver keyDeriver;
    private final AesGcmCipher cipher;
    private final SecureRandom secureRandom;
    private final ExecutorService securityExecutor;
    private final Handler mainHandler;

    public DecoyVaultCoordinator(
            Context context
    ) {
        Objects.requireNonNull(
                context,
                "context"
        );

        applicationContext =
                context.getApplicationContext();

        vaultDataService =
                new DecoyVaultDataService(
                        applicationContext,
                        DecoyVaultStorage.DATABASE_NAME
                );

        envelopeStore =
                VaultKeyEnvelopeStore.forDecoy(
                        applicationContext
                );

        keyDeriver =
                new Argon2idMasterKeyDeriver();

        cipher =
                new AesGcmCipher();

        secureRandom =
                new SecureRandom();

        securityExecutor =
                Executors.newSingleThreadExecutor();

        mainHandler =
                new Handler(
                        Looper.getMainLooper()
                );
    }

    public boolean hasDecoyVault() {
        return envelopeStore.hasEnvelope();
    }

    public boolean isDecoyVaultOpen() {
        return vaultDataService.isVaultOpen();
    }

    public void createDecoyVault(
            char[] decoyPassword,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(
                callback,
                "callback"
        );

        char[] passwordCopy =
                copyAndValidatePassword(
                        decoyPassword
                );

        try {
            securityExecutor.execute(
                    () ->
                            createDecoyVaultInBackground(
                                    passwordCopy,
                                    callback
                            )
            );

        } catch (RuntimeException schedulingError) {
            clear(
                    passwordCopy
            );

            throw schedulingError;
        }
    }

    private void createDecoyVaultInBackground(
            char[] decoyPassword,
            VaultDataService.SimpleCallback callback
    ) {
        byte[] salt = null;
        byte[] derivedMasterKey = null;
        byte[] databaseKey = null;

        boolean enrollmentStarted =
                false;

        boolean envelopeSaved =
                false;

        try {
            if (envelopeStore.hasEnvelope()) {
                throw new IllegalStateException(
                        "A Decoy Vault has already been created."
                );
            }

            salt =
                    keyDeriver.generateSalt();

            derivedMasterKey =
                    keyDeriver.deriveKey(
                            decoyPassword,
                            salt
                    );

            databaseKey =
                    new byte[
                            SafeKeyDatabase
                                    .DATABASE_KEY_LENGTH_BYTES
                            ];

            secureRandom.nextBytes(
                    databaseKey
            );

            String wrappedDatabaseKey =
                    cipher.encrypt(
                            databaseKey,
                            derivedMasterKey,
                            databaseKeyContext()
                    );

            /*
             * The always-present secondary file currently holds
             * an unconfigured cover database with an intentionally
             * forgotten random key. Replace it now with the actual
             * Decoy SQLCipher vault.
             */
            DecoyVaultStorage.prepareDatabaseForEnrollment(
                    applicationContext
            );

            enrollmentStarted =
                    true;

            initializeDecoyDatabase(
                    databaseKey
            );

            VaultKeyEnvelope envelope =
                    new VaultKeyEnvelope(
                            salt,
                            wrappedDatabaseKey
                    );

            envelopeStore.save(
                    envelope
            );

            envelopeSaved =
                    true;

            vaultDataService.openVault(
                    databaseKey,
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            callback.onSuccess();
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {
                            scheduleCreationFailureCleanup(
                                    callback,
                                    exception
                            );
                        }
                    }
            );

        } catch (Exception exception) {
            if (enrollmentStarted
                    || envelopeSaved) {

                cleanupFailedCreation(
                        exception
                );
            }

            deliverError(
                    callback,
                    exception
            );

        } finally {
            clear(
                    decoyPassword
            );

            clear(
                    salt
            );

            clear(
                    derivedMasterKey
            );

            clear(
                    databaseKey
            );
        }
    }

    private void initializeDecoyDatabase(
            byte[] databaseKey
    ) {
        SafeKeyDatabase databaseManager =
                new SafeKeyDatabase(
                        applicationContext,
                        DecoyVaultStorage.DATABASE_NAME
                );

        try {
            databaseManager.open(
                    databaseKey
            );

        } finally {
            databaseManager.close();
        }
    }

    public void unlockDecoyVault(
            char[] decoyPassword,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(
                callback,
                "callback"
        );

        char[] passwordCopy =
                copyAndValidatePassword(
                        decoyPassword
                );

        try {
            securityExecutor.execute(
                    () ->
                            unlockDecoyVaultInBackground(
                                    passwordCopy,
                                    callback
                            )
            );

        } catch (RuntimeException schedulingError) {
            clear(
                    passwordCopy
            );

            throw schedulingError;
        }
    }

    private void unlockDecoyVaultInBackground(
            char[] decoyPassword,
            VaultDataService.SimpleCallback callback
    ) {
        byte[] salt = null;
        byte[] derivedMasterKey = null;
        byte[] databaseKey = null;

        try {
            VaultKeyEnvelope envelope =
                    envelopeStore.load();

            if (envelope == null) {
                throw new IllegalStateException(
                        "No Decoy Vault has been created."
                );
            }

            salt =
                    envelope.getSalt();

            derivedMasterKey =
                    keyDeriver.deriveKey(
                            decoyPassword,
                            salt
                    );

            databaseKey =
                    cipher.decrypt(
                            envelope.getWrappedDatabaseKey(),
                            derivedMasterKey,
                            databaseKeyContext()
                    );

            vaultDataService.openVault(
                    databaseKey,
                    callback
            );

        } catch (Exception exception) {
            deliverError(
                    callback,
                    exception
            );

        } finally {
            clear(
                    decoyPassword
            );

            clear(
                    salt
            );

            clear(
                    derivedMasterKey
            );

            clear(
                    databaseKey
            );
        }
    }

    public void closeDecoyVault(
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(
                callback,
                "callback"
        );

        vaultDataService.closeVault(
                callback
        );
    }

    public void getVaultCounts(
            VaultDataService.ResultCallback<VaultCounts> callback
    ) {
        vaultDataService.getVaultCounts(
                Objects.requireNonNull(
                        callback,
                        "callback"
                )
        );
    }

    public void addCredential(
            Credential credential,
            VaultDataService.ResultCallback<Long> callback
    ) {
        vaultDataService.addCredential(
                credential,
                callback
        );
    }

    public void getCredentials(
            VaultDataService.ResultCallback<List<Credential>> callback
    ) {
        vaultDataService.getCredentials(
                callback
        );
    }

    public void addSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Long> callback
    ) {
        vaultDataService.addSecureNote(
                note,
                callback
        );
    }

    public void getSecureNotes(
            VaultDataService.ResultCallback<List<SecureNote>> callback
    ) {
        vaultDataService.getSecureNotes(
                callback
        );
    }

    public void shutdown() {
        if (securityExecutor.isShutdown()) {
            return;
        }

        securityExecutor.execute(
                vaultDataService::shutdown
        );

        securityExecutor.shutdown();
    }

    private void scheduleCreationFailureCleanup(
            VaultDataService.SimpleCallback callback,
            Exception originalError
    ) {
        try {
            securityExecutor.execute(
                    () -> {
                        cleanupFailedCreation(
                                originalError
                        );

                        deliverError(
                                callback,
                                originalError
                        );
                    }
            );

        } catch (RuntimeException schedulingError) {
            originalError.addSuppressed(
                    schedulingError
            );

            deliverError(
                    callback,
                    originalError
            );
        }
    }

    private void cleanupFailedCreation(
            Exception originalError
    ) {
        try {
            envelopeStore.clear();

        } catch (RuntimeException clearingError) {
            originalError.addSuppressed(
                    clearingError
            );
        }

        try {
            DecoyVaultStorage.restoreCoverDatabase(
                    applicationContext
            );

        } catch (RuntimeException restoringError) {
            originalError.addSuppressed(
                    restoringError
            );
        }
    }

    private void deliverError(
            VaultDataService.SimpleCallback callback,
            Exception exception
    ) {
        mainHandler.post(
                () ->
                        callback.onError(
                                exception
                        )
        );
    }

    private static char[] copyAndValidatePassword(
            char[] password
    ) {
        if (password == null) {
            throw new IllegalArgumentException(
                    "Decoy password cannot be null."
            );
        }

        if (password.length == 0) {
            throw new IllegalArgumentException(
                    "Decoy password cannot be empty."
            );
        }

        return Arrays.copyOf(
                password,
                password.length
        );
    }

    private static byte[] databaseKeyContext() {
        return DATABASE_KEY_CONTEXT.getBytes(
                StandardCharsets.UTF_8
        );
    }

    private static void clear(
            byte[] value
    ) {
        if (value != null) {
            Arrays.fill(
                    value,
                    (byte) 0
            );
        }
    }

    private static void clear(
            char[] value
    ) {
        if (value != null) {
            Arrays.fill(
                    value,
                    '\0'
            );
        }
    }
}

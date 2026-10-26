
package com.safekey.app.security.storage;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWorkGate;

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
 * Decoy storage, key envelope, SQLCipher database and encryption context
 * are independent of the real vault.
 */
public final class DecoyVaultCoordinator implements VaultOperations {

    private static final String DATABASE_KEY_CONTEXT =
            "safekey:decoy-database-key-envelope:v1";

    private final PanicRuntimeScope runtimeScope;
    private final Context applicationContext;
    private final DecoyVaultDataService vaultDataService;
    private final VaultKeyEnvelopeStore envelopeStore;
    private final Argon2idMasterKeyDeriver keyDeriver;
    private final AesGcmCipher cipher;
    private final SecureRandom secureRandom;
    private final ExecutorService securityExecutor;
    private final Handler mainHandler;
    private final Object lifecycleLock = new Object();

    // Test-only scheduling hook; no effect in production.
    volatile Runnable enrollmentDerivationTestHook = () -> {};
    private long unlockGeneration = 0L;
    private boolean closeInProgress = false;

    public DecoyVaultCoordinator(Context context) {
        Objects.requireNonNull(context, "context");
        applicationContext = context.getApplicationContext();
        runtimeScope = PanicRuntimeScope.capture(applicationContext);
        vaultDataService = new DecoyVaultDataService(
                applicationContext, DecoyVaultStorage.DATABASE_NAME);
        envelopeStore = VaultKeyEnvelopeStore.forDecoy(applicationContext);
        keyDeriver = new Argon2idMasterKeyDeriver();
        cipher = new AesGcmCipher();
        secureRandom = new SecureRandom();
        securityExecutor = Executors.newSingleThreadExecutor();
        runtimeScope.registerExecutor(securityExecutor);
        mainHandler = new Handler(Looper.getMainLooper());
    }

    public boolean hasDecoyVault() {
        return envelopeStore.hasEnvelope();
    }

    public boolean isDecoyVaultOpen() {
        return vaultDataService.isVaultOpen();
    }

    private void createDecoyVaultWhileRunning(char[] decoyPassword,
                                 VaultDataService.SimpleCallback callback) {
        Objects.requireNonNull(callback, "callback");
        char[] passwordCopy = copyAndValidatePassword(decoyPassword);
        final long requestGeneration;
        synchronized (lifecycleLock) {
            if (runtimeScope.isStopped() || closeInProgress) {
                clear(passwordCopy);
                deliverError(callback, new IllegalStateException("Decoy Vault is closing."));
                return;
            }
            requestGeneration = unlockGeneration;
        }
        try {
            executeSecurity(() -> createDecoyVaultInBackground(
                    passwordCopy, callback, requestGeneration));
        } catch (RuntimeException schedulingError) {
            clear(passwordCopy);
            throw schedulingError;
        }
    }

    private void createDecoyVaultInBackground(char[] decoyPassword,
                                              VaultDataService.SimpleCallback callback,
                                              long requestGeneration) {
        byte[] salt = null;
        byte[] derivedMasterKey = null;
        byte[] databaseKey = null;
        boolean enrollmentStarted = false;
        boolean envelopeSaved = false;

        try {
            if (envelopeStore.hasEnvelope()) {
                throw new IllegalStateException("A Decoy Vault has already been created.");
            }

            salt = keyDeriver.generateSalt();
            derivedMasterKey = keyDeriver.deriveKey(decoyPassword, salt);
            enrollmentDerivationTestHook.run();
            databaseKey = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
            secureRandom.nextBytes(databaseKey);
            String wrappedDatabaseKey = cipher.encrypt(
                    databaseKey, derivedMasterKey, databaseKeyContext());

            // Replace the unconfigured cover DB with the enrolled Decoy SQLCipher DB.
            synchronized (lifecycleLock) {
                if (runtimeScope.isStopped() || requestGeneration != unlockGeneration || closeInProgress) {
                    throw new IllegalStateException("Decoy enrollment was invalidated.");
                }

                DecoyVaultStorage.prepareDatabaseForEnrollment(applicationContext);
                enrollmentStarted = true;
                initializeDecoyDatabase(databaseKey);
                VaultKeyEnvelope envelope = new VaultKeyEnvelope(salt, wrappedDatabaseKey);
                envelopeStore.save(envelope);
                envelopeSaved = true;

                vaultDataService.openVault(databaseKey, new VaultDataService.SimpleCallback() {
                    @Override
                    public void onSuccess() {
                        deliverOpenedVaultResult(callback, requestGeneration,
                                "Decoy enrollment was invalidated.");
                    }

                    @Override
                    public void onError(Exception exception) {
                        scheduleCreationFailureCleanup(callback, exception, requestGeneration);
                    }
                });
            }
        } catch (Exception exception) {
            if (enrollmentStarted || envelopeSaved) {
                cleanupFailedCreation(exception, requestGeneration);
            }
            deliverError(callback, exception);
        } finally {
            clear(decoyPassword);
            clear(salt);
            clear(derivedMasterKey);
            clear(databaseKey);
        }
    }

    private void initializeDecoyDatabase(byte[] databaseKey) {
        SafeKeyDatabase databaseManager = new SafeKeyDatabase(
                applicationContext, DecoyVaultStorage.DATABASE_NAME);
        try {
            databaseManager.open(databaseKey);
        } finally {
            databaseManager.close();
        }
    }

    private void unlockDecoyVaultWhileRunning(char[] decoyPassword,
                                 VaultDataService.SimpleCallback callback) {
        Objects.requireNonNull(callback, "callback");
        char[] passwordCopy = copyAndValidatePassword(decoyPassword);
        final long requestGeneration;
        synchronized (lifecycleLock) {
            if (runtimeScope.isStopped() || closeInProgress) {
                clear(passwordCopy);
                deliverError(callback, new IllegalStateException("Decoy Vault is closing."));
                return;
            }
            requestGeneration = unlockGeneration;
        }
        try {
            executeSecurity(() -> unlockDecoyVaultInBackground(
                    passwordCopy, callback, requestGeneration));
        } catch (RuntimeException schedulingError) {
            clear(passwordCopy);
            throw schedulingError;
        }
    }

    private void unlockDecoyVaultInBackground(char[] decoyPassword,
                                              VaultDataService.SimpleCallback callback,
                                              long requestGeneration) {
        byte[] salt = null;
        byte[] derivedMasterKey = null;
        byte[] databaseKey = null;
        try {
            VaultKeyEnvelope envelope = envelopeStore.load();
            if (envelope == null) {
                throw new IllegalStateException("No Decoy Vault has been created.");
            }

            salt = envelope.getSalt();
            derivedMasterKey = keyDeriver.deriveKey(decoyPassword, salt);
            databaseKey = cipher.decrypt(envelope.getWrappedDatabaseKey(),
                    derivedMasterKey, databaseKeyContext());

            synchronized (lifecycleLock) {
                if (runtimeScope.isStopped() || requestGeneration != unlockGeneration || closeInProgress) {
                    throw new IllegalStateException("Decoy unlock was invalidated.");
                }

                vaultDataService.openVault(databaseKey, new VaultDataService.SimpleCallback() {
                    @Override
                    public void onSuccess() {
                        deliverOpenedVaultResult(callback, requestGeneration,
                                "Decoy unlock was invalidated.");
                    }

                    @Override
                    public void onError(Exception exception) {
                        deliverError(callback, exception);
                    }
                });
            }
        } catch (Exception exception) {
            deliverError(callback, exception);
        } finally {
            clear(decoyPassword);
            clear(salt);
            clear(derivedMasterKey);
            clear(databaseKey);
        }
    }

    public void closeDecoyVault(VaultDataService.SimpleCallback callback) {
        Objects.requireNonNull(callback, "callback");
        synchronized (lifecycleLock) {
            final long closeGeneration = ++unlockGeneration;
            closeInProgress = true;

            vaultDataService.closeVault(new VaultDataService.SimpleCallback() {
                @Override
                public void onSuccess() {
                    // Defer delivery even if closeVault completes synchronously.
                    runtimeScope.deliver(mainHandler, () -> {
                        boolean current;
                        synchronized (lifecycleLock) {
                            current = closeGeneration == unlockGeneration;
                            if (current) {
                                closeInProgress = false;
                            }
                        }
                        // Never call external code while holding lifecycleLock.
                        if (current) {
                            if (!runtimeScope.isStopped()) { callback.onSuccess(); }
                        } else {
                            callback.onError(new IllegalStateException(
                                    "Decoy close was superseded."));
                        }
                    });
                }

                @Override
                public void onError(Exception exception) {
                    // Remain closed to new unlock attempts until a later close succeeds.
                    deliverError(callback, exception);
                }
            });
        }
    }

    @Override
    public void getCredential(long id, VaultDataService.ResultCallback<Credential> callback) {
        vaultDataService.getCredential(id, callback);
    }

    @Override
    public void addCredential(Credential credential, VaultDataService.ResultCallback<Long> callback) {
        vaultDataService.addCredential(credential, callback);
    }

    @Override
    public void updateCredential(Credential credential,
                                 VaultDataService.ResultCallback<Integer> callback) {
        vaultDataService.updateCredential(credential, callback);
    }

    @Override
    public void deleteCredential(long id, VaultDataService.ResultCallback<Integer> callback) {
        vaultDataService.deleteCredential(id, callback);
    }

    @Override
    public void setCredentialFavorite(long id, boolean favorite,
                                      VaultDataService.ResultCallback<Integer> callback) {
        vaultDataService.setCredentialFavorite(id, favorite, callback);
    }

    @Override
    public void getVaultCounts(VaultDataService.ResultCallback<VaultCounts> callback) {
        vaultDataService.getVaultCounts(Objects.requireNonNull(callback, "callback"));
    }

    @Override
    public void getCredentials(VaultDataService.ResultCallback<List<Credential>> callback) {
        vaultDataService.getCredentials(callback);
    }

    @Override
    public void getSecureNote(long id, VaultDataService.ResultCallback<SecureNote> callback) {
        // The data service exposes the list, not direct secure-note lookup.
        vaultDataService.getSecureNotes(new VaultDataService.ResultCallback<List<SecureNote>>() {
            @Override
            public void onSuccess(List<SecureNote> notes) {
                SecureNote matchingNote = null;
                if (notes != null) {
                    for (SecureNote note : notes) {
                        if (note.getId() == id) {
                            matchingNote = note;
                            break;
                        }
                    }
                }
                callback.onSuccess(matchingNote);
            }

            @Override
            public void onError(Exception exception) {
                callback.onError(exception);
            }
        });
    }

    @Override
    public void addSecureNote(SecureNote note, VaultDataService.ResultCallback<Long> callback) {
        vaultDataService.addSecureNote(note, callback);
    }

    @Override
    public void updateSecureNote(SecureNote note, VaultDataService.ResultCallback<Integer> callback) {
        vaultDataService.updateSecureNote(note, callback);
    }

    @Override
    public void deleteSecureNote(long id, VaultDataService.ResultCallback<Integer> callback) {
        vaultDataService.deleteSecureNote(id, callback);
    }

    @Override
    public void getSecureNotes(VaultDataService.ResultCallback<List<SecureNote>> callback) {
        vaultDataService.getSecureNotes(callback);
    }

    public void shutdown() {
        if (securityExecutor.isShutdown()) {
            return;
        }
        executeSecurity(vaultDataService::shutdown);
        securityExecutor.shutdown();
    }

    private void scheduleCreationFailureCleanup(VaultDataService.SimpleCallback callback,
                                                Exception originalError,
                                                long requestGeneration) {
        try {
            executeSecurity(() -> {
                cleanupFailedCreation(originalError, requestGeneration);
                deliverError(callback, originalError);
            });
        } catch (RuntimeException schedulingError) {
            originalError.addSuppressed(schedulingError);
            // Emergency worker avoids blocking the Android UI with cleanup.
            try {
                PanicWorkGate.Operation recovery = runtimeScope.begin();
                try {
                    Thread fallbackWorker = new Thread(() -> {
                        try {
                            cleanupFailedCreation(originalError, requestGeneration);
                            deliverError(callback, originalError);
                        } finally { recovery.close(); }
                    }, "SafeKey-Decoy-Recovery");
                    fallbackWorker.start();
                } catch (RuntimeException error) {
                    recovery.close();
                    throw error;
                }
            } catch (RuntimeException threadError) {
                originalError.addSuppressed(threadError);
                deliverError(callback, originalError);
            }
        }
    }

    private void cleanupFailedCreation(Exception originalError, long requestGeneration) {
        synchronized (lifecycleLock) {
            // An old enrollment must never erase a newer vault.
            if (runtimeScope.isStopped() || requestGeneration != unlockGeneration || closeInProgress) {
                return;
            }
            cleanupFailedCreationStorageOnly(originalError);
        }
    }

    private void cleanupFailedCreationStorageOnly(Exception originalError) {
        try {
            envelopeStore.clear();
        } catch (RuntimeException clearingError) {
            originalError.addSuppressed(clearingError);
        }
        try {
            DecoyVaultStorage.restoreCoverDatabase(applicationContext);
        } catch (RuntimeException restoringError) {
            originalError.addSuppressed(restoringError);
        }
    }

    /**
     * Revalidate at callback-delivery time. The handler defers even a
     * synchronous openVault success until after lifecycleLock is released.
     */
    private void deliverOpenedVaultResult(VaultDataService.SimpleCallback callback,
                                          long requestGeneration,
                                          String invalidatedMessage) {
        runtimeScope.deliver(mainHandler, () -> {
            boolean active;
            synchronized (lifecycleLock) {
                active = requestGeneration == unlockGeneration && !closeInProgress;
            }
            if (active) {
                if (!runtimeScope.isStopped()) { callback.onSuccess(); }
            } else {
                callback.onError(new IllegalStateException(invalidatedMessage));
            }
        });
    }

    private void deliverError(VaultDataService.SimpleCallback callback, Exception exception) {
        runtimeScope.deliver(mainHandler, () -> { if (!runtimeScope.isStopped()) { callback.onError(exception); } });
    }

    private static char[] copyAndValidatePassword(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("Decoy password cannot be null.");
        }
        if (password.length == 0) {
            throw new IllegalArgumentException("Decoy password cannot be empty.");
        }
        return Arrays.copyOf(password, password.length);
    }

    private static byte[] databaseKeyContext() {
        return DATABASE_KEY_CONTEXT.getBytes(StandardCharsets.UTF_8);
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static void clear(char[] value) {
        if (value != null) {
            Arrays.fill(value, '\0');
        }
    }

    public void createDecoyVault(char[] decoyPassword,
                                 VaultDataService.SimpleCallback callback) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            createDecoyVaultWhileRunning(decoyPassword, callback);
        }
    }


    public void unlockDecoyVault(char[] decoyPassword,
                                 VaultDataService.SimpleCallback callback) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            unlockDecoyVaultWhileRunning(decoyPassword, callback);
        }
    }


    private void executeSecurity(Runnable work) {
        runtimeScope.execute(securityExecutor, work);
    }

}

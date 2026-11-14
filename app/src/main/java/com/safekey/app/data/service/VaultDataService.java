package com.safekey.app.data.service;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWorkGate;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.repository.CredentialRepository;
import com.safekey.app.data.repository.SecureNoteRepository;
import com.safekey.app.data.repository.VaultCountsRepository;
import com.safekey.app.data.repository.VaultProfileRepository;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VaultDataService {

    private final PanicRuntimeScope runtimeScope;
    private java.util.concurrent.FutureTask<Void> panicCloseTask;

    private final AtomicLong vaultGeneration = new AtomicLong();

    private final SafeKeyDatabase databaseManager;
    private final ExecutorService executorService;
    private final Handler mainHandler;

    private CredentialRepository credentialRepository;
    private SecureNoteRepository secureNoteRepository;
    private VaultCountsRepository vaultCountsRepository;
    private VaultProfileRepository vaultProfileRepository;

    // One owned, purpose-separated field-encryption key per opened vault.
    private volatile VaultItemCipher itemCipher;

    public VaultDataService(
            Context context
    ) {

        this(
                new SafeKeyDatabase(
                        context.getApplicationContext()
                ),
                PanicRuntimeScope.capture(context)
        );
    }

    /*
     * Package-private constructor used by
     * instrumented tests so they can supply
     * an isolated test database.
     */
    VaultDataService(
            SafeKeyDatabase databaseManager
    ) {
        this(databaseManager, new PanicRuntimeScope());
    }

    VaultDataService(SafeKeyDatabase databaseManager, PanicRuntimeScope runtimeScope) {
        this.runtimeScope = java.util.Objects.requireNonNull(runtimeScope, "runtimeScope");


        if (databaseManager == null) {

            throw new IllegalArgumentException(
                    "Database manager cannot be null."
            );
        }

        this.databaseManager =
                databaseManager;

        executorService =
                Executors.newSingleThreadExecutor();

        /*
         * Callbacks are delivered on Android's
         * main thread so UI callers can safely
         * update views.
         */
        mainHandler =
                new Handler(
                        Looper.getMainLooper()
                );

        runtimeScope.registerResource(new PanicRuntimeScope.Resource() {
            @Override public void closeAndAwait(long deadline) throws Exception {
                closeForPanic(deadline);
            }
            @Override public boolean isClosed() {
                return executorService.isTerminated() && !databaseManager.isOpen()
                        && (itemCipher == null || itemCipher.isClosed());
            }
        });
    }

    /**
     * Open only after v3->v4 migration and repository initialization succeed.
     * The worker owns the copied database key and all cipher state. No repository
     * or callback is published until the migration commits.
     */
    private void openVaultWhileRunning(
            byte[] databaseKey,
            SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");
        if (databaseKey == null
                || databaseKey.length != SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("Database key must contain exactly "
                    + SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES + " bytes.");
        }

        final byte[] databaseKeyCopy = Arrays.copyOf(databaseKey, databaseKey.length);
        vaultGeneration.incrementAndGet();
        try {
            executeWork(() -> {
                VaultItemCipher pendingCipher = null;
                Exception openingError = null;
                try {
                    // Always retire the old connection and field key first.
                    // This prevents reuse with a different Real/Decoy database key.
                    closeVaultResources();

                    pendingCipher = new VaultItemCipher(databaseKeyCopy);
                    SQLiteDatabase openedDatabase = databaseManager.openForItemEncryption(
                            databaseKeyCopy, pendingCipher);

                    CredentialRepository openedCredentialRepository =
                            new CredentialRepository(openedDatabase, pendingCipher);
                    SecureNoteRepository openedSecureNoteRepository =
                            new SecureNoteRepository(openedDatabase, pendingCipher);
                    VaultCountsRepository openedCountsRepository =
                            new VaultCountsRepository(openedDatabase);
                    VaultProfileRepository openedProfileRepository =
                            new VaultProfileRepository(openedDatabase);

                    // Publish the entire new generation only after validation.
                    credentialRepository = openedCredentialRepository;
                    secureNoteRepository = openedSecureNoteRepository;
                    vaultCountsRepository = openedCountsRepository;
                    vaultProfileRepository = openedProfileRepository;
                    itemCipher = pendingCipher;
                    pendingCipher = null;
                } catch (Exception | Error failure) {
                    try {
                        closeVaultResources();
                    } catch (Exception | Error cleanupError) {
                        failure.addSuppressed(cleanupError);
                    }
                    if (failure instanceof Error) {
                        throw (Error) failure;
                    }
                    openingError = (Exception) failure;
                } finally {
                    if (pendingCipher != null) {
                        pendingCipher.close();
                    }
                    Arrays.fill(databaseKeyCopy, (byte) 0);
                }

                if (openingError != null) {
                    deliverSimpleError(callback, openingError);
                } else {
                    deliverSimpleSuccess(callback);
                }
            });
        } catch (RuntimeException schedulingError) {
            Arrays.fill(databaseKeyCopy, (byte) 0);
            throw schedulingError;
        }
    }

    /** Close database and the owned cipher, even if SQLCipher closure throws. */
    private void closeVaultResources() {
        try {
            databaseManager.close();
        } finally {
            credentialRepository = null;
            secureNoteRepository = null;
            vaultCountsRepository = null;
            vaultProfileRepository = null;
            VaultItemCipher previousCipher = itemCipher;
            itemCipher = null;
            if (previousCipher != null) {
                previousCipher.close();
            }
        }
    }

    public void closeVault(SimpleCallback callback) {
        Objects.requireNonNull(callback, "callback");
        vaultGeneration.incrementAndGet();
        executeWork(() -> {
            try {
                closeVaultResources();
                deliverSimpleSuccess(callback);
            } catch (Exception failure) {
                deliverSimpleError(callback, failure);
            }
        });
    }

    public boolean isVaultOpen() {
        VaultItemCipher currentCipher = itemCipher;
        return databaseManager.isOpen() && currentCipher != null
                && !currentCipher.isClosed();
    }

    /** Cache work belongs to this database opening, not a replacement session. */
    public long getVaultGeneration() {
        return vaultGeneration.get();
    }

    public void updateCredentialBreachStatus(
            long expectedGeneration,
            long credentialId,
            String expectedPassword,
            PasswordBreachResult.Status status,
            ResultCallback<PasswordBreachResult.Status> callback
    ) {
        Objects.requireNonNull(expectedPassword, "expectedPassword");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(callback, "callback");
        executeWork(() -> {
            try {
                if (vaultGeneration.get() != expectedGeneration) {
                    throw new IllegalStateException("The vault opening changed during the check.");
                }
                PasswordBreachResult.Status saved = requireCredentialRepository()
                        .updateBreachStatus(credentialId, expectedPassword, status);
                deliverResultSuccess(callback, saved);
            } catch (Exception error) {
                deliverResultError(callback, error);
            }
        });
    }

    /**
     * Reads the display name from the currently opened vault database.
     */
    public void getVaultDisplayName(
            ResultCallback<String> callback
    ) {
        Objects.requireNonNull(callback, "callback");

        executeWork(() -> {
            try {
                String displayName =
                        requireVaultProfileRepository().getDisplayName();

                deliverResultSuccess(callback, displayName);

            } catch (Exception exception) {
                deliverResultError(callback, exception);
            }
        });
    }

    /**
     * Saves the display name in the currently opened vault database.
     *
     * REAL and DECOY vaults use separate SQLCipher databases.
     */
    public void updateVaultDisplayName(
            String displayName,
            ResultCallback<Integer> callback
    ) {
        Objects.requireNonNull(callback, "callback");

        // Bind the request to the database opening active at submission.
        final long expectedGeneration = vaultGeneration.get();

        executeWork(() -> {
            try {
                if (vaultGeneration.get() != expectedGeneration) {
                    throw new IllegalStateException(
                            "The vault opening changed before the rename."
                    );
                }

                int updatedRows =
                        requireVaultProfileRepository()
                                .updateDisplayName(displayName);

                deliverResultSuccess(callback, updatedRows);

            } catch (Exception exception) {
                deliverResultError(callback, exception);
            }
        });
    }
    public void getVaultCounts(
            ResultCallback<VaultCounts> callback
    ) {
        executeWork(() -> {
            final VaultCounts counts;

            try {
                counts = requireVaultCountsRepository().getCounts();
            } catch (Exception exception) {
                deliverResultError(callback, exception);
                return;
            }

            deliverResultSuccess(callback, counts);
        });
    }

    public void addCredential(
            Credential credential,
            ResultCallback<Long> callback
    ) {

        executeWork(() -> {

            final long id;

            try {

                id =
                        requireCredentialRepository()
                                .insert(
                                        credential
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    id
            );
        });
    }

    public void getCredential(
            long id,
            ResultCallback<Credential> callback
    ) {

        executeWork(() -> {

            final Credential credential;

            try {

                credential =
                        requireCredentialRepository()
                                .getById(
                                        id
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    credential
            );
        });
    }

    public void getCredentials(
            ResultCallback<List<Credential>> callback
    ) {

        executeWork(() -> {

            final List<Credential> credentials;

            try {

                credentials =
                        requireCredentialRepository()
                                .getAll();

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    credentials
            );
        });
    }

    public void updateCredential(
            Credential credential,
            ResultCallback<Integer> callback
    ) {

        executeWork(() -> {

            final int rows;

            try {

                rows =
                        requireCredentialRepository()
                                .update(
                                        credential
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    rows
            );
        });
    }

    public void deleteCredential(
            long id,
            ResultCallback<Integer> callback
    ) {

        executeWork(() -> {

            final int rows;

            try {

                rows =
                        requireCredentialRepository()
                                .delete(
                                        id
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    rows
            );
        });
    }

    public void searchCredentials(
            String query,
            ResultCallback<List<Credential>> callback
    ) {

        executeWork(() -> {

            final List<Credential> results;

            try {

                results =
                        requireCredentialRepository()
                                .search(
                                        query
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    results
            );
        });
    }

    public void setCredentialFavorite(
            long id,
            boolean favorite,
            ResultCallback<Integer> callback
    ) {

        executeWork(() -> {

            final int rows;

            try {

                rows =
                        requireCredentialRepository()
                                .setFavorite(
                                        id,
                                        favorite
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    rows
            );
        });
    }

    public void addSecureNote(
            SecureNote note,
            ResultCallback<Long> callback
    ) {

        executeWork(() -> {

            final long id;

            try {

                id =
                        requireSecureNoteRepository()
                                .insert(
                                        note
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    id
            );
        });
    }

    public void getSecureNotes(
            ResultCallback<List<SecureNote>> callback
    ) {

        executeWork(() -> {

            final List<SecureNote> notes;

            try {

                notes =
                        requireSecureNoteRepository()
                                .getAll();

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    notes
            );
        });
    }

    public void getSecureNote(
            long id,
            ResultCallback<SecureNote> callback
    ) {

        executeWork(() -> {

            final SecureNote note;

            try {

                note =
                        requireSecureNoteRepository()
                                .getById(
                                        id
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    note
            );
        });
    }

    public void updateSecureNote(
            SecureNote note,
            ResultCallback<Integer> callback
    ) {

        executeWork(() -> {

            final int rows;

            try {

                rows =
                        requireSecureNoteRepository()
                                .update(
                                        note
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    rows
            );
        });
    }

    public void deleteSecureNote(
            long id,
            ResultCallback<Integer> callback
    ) {

        executeWork(() -> {

            final int rows;

            try {

                rows =
                        requireSecureNoteRepository()
                                .delete(
                                        id
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    rows
            );
        });
    }

    public void searchSecureNotes(
            String query,
            ResultCallback<List<SecureNote>> callback
    ) {

        executeWork(() -> {

            final List<SecureNote> results;

            try {

                results =
                        requireSecureNoteRepository()
                                .search(
                                        query
                                );

            } catch (Exception exception) {

                deliverResultError(
                        callback,
                        exception
                );

                return;
            }

            deliverResultSuccess(
                    callback,
                    results
            );
        });
    }

    private CredentialRepository
    requireCredentialRepository() {

        if (credentialRepository == null) {

            throw new IllegalStateException(
                    "Vault is not open."
            );
        }

        return credentialRepository;
    }

    private SecureNoteRepository
    requireSecureNoteRepository() {

        if (secureNoteRepository == null) {

            throw new IllegalStateException(
                    "Vault is not open."
            );
        }

        return secureNoteRepository;
    }

    private VaultProfileRepository requireVaultProfileRepository() {
        if (vaultProfileRepository == null) {
            throw new IllegalStateException("Vault is not open.");
        }

        return vaultProfileRepository;
    }
    private VaultCountsRepository requireVaultCountsRepository() {
        if (vaultCountsRepository == null) {
            throw new IllegalStateException("Vault is not open.");
        }

        return vaultCountsRepository;
    }

    private void deliverSimpleSuccess(
            SimpleCallback callback
    ) {

        runtimeScope.deliver(mainHandler,
                () -> { if (!runtimeScope.isStopped()) { callback.onSuccess(); } }
        );
    }

    private void deliverSimpleError(
            SimpleCallback callback,
            Exception exception
    ) {

        runtimeScope.deliver(mainHandler,
                () -> { if (!runtimeScope.isStopped()) { callback.onError(exception); } }
        );
    }

    private <T> void deliverResultSuccess(
            ResultCallback<T> callback,
            T result
    ) {

        runtimeScope.deliver(mainHandler,
                () -> { if (!runtimeScope.isStopped()) { callback.onSuccess(result); } }
        );
    }

    private <T> void deliverResultError(
            ResultCallback<T> callback,
            Exception exception
    ) {

        runtimeScope.deliver(mainHandler,
                () -> { if (!runtimeScope.isStopped()) { callback.onError(exception); } }
        );
    }

    /*
     * Queue database cleanup before shutting down
     * the executor.
     */
    public synchronized void shutdown() {
        vaultGeneration.incrementAndGet();

        if (executorService.isShutdown()) {

            return;
        }

        executeWork(this::closeVaultResources);

        executorService.shutdown();
    }

    public interface SimpleCallback {

        void onSuccess();

        void onError(
                Exception exception
        );
    }

    public interface ResultCallback<T> {

        void onSuccess(
                T result
        );

        void onError(
                Exception exception
        );
    }

    public void openVault(
            byte[] databaseKey,
            SimpleCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            openVaultWhileRunning(databaseKey, callback);
        }
    }


    private void executeWork(Runnable work) {
        runtimeScope.execute(executorService, work);
    }

    private void closeForPanic(long deadline) throws Exception {
        java.util.concurrent.FutureTask<Void> closing;
        synchronized (this) {
            if (panicCloseTask == null && !executorService.isShutdown()) {
                panicCloseTask = new java.util.concurrent.FutureTask<>(() -> {
                    try {
                        closeVaultResources();
                    } finally {
                        vaultGeneration.incrementAndGet();
                    }
                    if (databaseManager.isOpen()) {
                        throw new java.io.IOException("Vault database is still open.");
                    }
                    return null;
                });
                try { executorService.execute(panicCloseTask); }
                finally { executorService.shutdown(); }
            }
            closing = panicCloseTask;
        }
        if (closing != null) {
            closing.get(PanicRuntimeScope.remainingMillis(deadline),
                    java.util.concurrent.TimeUnit.MILLISECONDS);
        }
        if (!executorService.awaitTermination(PanicRuntimeScope.remainingMillis(deadline),
                java.util.concurrent.TimeUnit.MILLISECONDS) || databaseManager.isOpen()
                || (itemCipher != null && !itemCipher.isClosed())) {
            throw new java.io.IOException("Vault database worker did not close.");
        }
    }

}

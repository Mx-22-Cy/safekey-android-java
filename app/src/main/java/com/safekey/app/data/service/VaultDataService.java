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
                return executorService.isTerminated() && !databaseManager.isOpen();
            }
        });
    }

    private void openVaultWhileRunning(
            byte[] databaseKey,
            SimpleCallback callback
    ) {

        if (databaseKey == null) {

            throw new IllegalArgumentException(
                    "Database key cannot be null."
            );
        }

        if (
                databaseKey.length
                        != SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES
        ) {

            throw new IllegalArgumentException(
                    "Database key must contain exactly "
                            + SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES
                            + " bytes."
            );
        }

        /*
         * Copy before scheduling asynchronous work.
         * The caller may clear its original array as
         * soon as this method returns.
         */
        final byte[] databaseKeyCopy =
                Arrays.copyOf(
                        databaseKey,
                        databaseKey.length
                );

        vaultGeneration.incrementAndGet();
        try {

            executeWork(() -> {

                Exception openingError =
                        null;

                try {

                    SQLiteDatabase database =
                            databaseManager.open(
                                    databaseKeyCopy
                            );

                    CredentialRepository openedCredentialRepository =
                            new CredentialRepository(
                                    database
                            );

                    SecureNoteRepository openedSecureNoteRepository =
                            new SecureNoteRepository(
                                    database
                            );

                    VaultCountsRepository openedVaultCountsRepository =
                            new VaultCountsRepository(database);

                    credentialRepository =
                            openedCredentialRepository;

                    secureNoteRepository =
                            openedSecureNoteRepository;

                    vaultCountsRepository =
                            openedVaultCountsRepository;

                } catch (Exception exception) {

                    openingError =
                            exception;

                } finally {

                    Arrays.fill(
                            databaseKeyCopy,
                            (byte) 0
                    );
                }

                if (openingError != null) {

                    deliverSimpleError(
                            callback,
                            openingError
                    );

                    return;
                }

                deliverSimpleSuccess(
                        callback
                );
            });

        } catch (RuntimeException schedulingError) {

            Arrays.fill(
                    databaseKeyCopy,
                    (byte) 0
            );

            throw schedulingError;
        }
    }

    public void closeVault(
            SimpleCallback callback
    ) {
        vaultGeneration.incrementAndGet();
        executeWork(() -> {
            try {
                databaseManager.close();
            } catch (Exception exception) {
                deliverSimpleError(callback, exception);
                return;
            } finally {
                credentialRepository = null;
                secureNoteRepository = null;
                vaultCountsRepository = null;
            }

            deliverSimpleSuccess(callback);
        });
    }

    public boolean isVaultOpen() {

        return databaseManager.isOpen();
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

        executeWork(() -> {

            try {

                databaseManager.close();

            } finally {

                credentialRepository = null;
                secureNoteRepository = null;
                vaultCountsRepository = null;
            }
        });

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
                    try { databaseManager.close(); }
                    finally {
                        vaultGeneration.incrementAndGet();
                        credentialRepository = null;
                        secureNoteRepository = null;
                        vaultCountsRepository = null;
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
                java.util.concurrent.TimeUnit.MILLISECONDS) || databaseManager.isOpen()) {
            throw new java.io.IOException("Vault database worker did not close.");
        }
    }

}

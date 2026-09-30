package com.safekey.app.data.service;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.repository.CredentialRepository;
import com.safekey.app.data.repository.SecureNoteRepository;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VaultDataService {

    private final SafeKeyDatabase databaseManager;
    private final ExecutorService executorService;
    private final Handler mainHandler;

    private CredentialRepository credentialRepository;
    private SecureNoteRepository secureNoteRepository;

    public VaultDataService(
            Context context
    ) {

        this(
                new SafeKeyDatabase(
                        context.getApplicationContext()
                )
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
    }

    public void openVault(
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

        try {

            executorService.execute(() -> {

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

                    credentialRepository =
                            openedCredentialRepository;

                    secureNoteRepository =
                            openedSecureNoteRepository;

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

        executorService.execute(() -> {

            try {

                databaseManager.close();

                credentialRepository = null;
                secureNoteRepository = null;

            } catch (Exception exception) {

                deliverSimpleError(
                        callback,
                        exception
                );

                return;
            }

            deliverSimpleSuccess(
                    callback
            );
        });
    }

    public boolean isVaultOpen() {

        return databaseManager.isOpen();
    }

    public void addCredential(
            Credential credential,
            ResultCallback<Long> callback
    ) {

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

    public void updateSecureNote(
            SecureNote note,
            ResultCallback<Integer> callback
    ) {

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

        executorService.execute(() -> {

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

    private void deliverSimpleSuccess(
            SimpleCallback callback
    ) {

        mainHandler.post(
                callback::onSuccess
        );
    }

    private void deliverSimpleError(
            SimpleCallback callback,
            Exception exception
    ) {

        mainHandler.post(
                () -> callback.onError(
                        exception
                )
        );
    }

    private <T> void deliverResultSuccess(
            ResultCallback<T> callback,
            T result
    ) {

        mainHandler.post(
                () -> callback.onSuccess(
                        result
                )
        );
    }

    private <T> void deliverResultError(
            ResultCallback<T> callback,
            Exception exception
    ) {

        mainHandler.post(
                () -> callback.onError(
                        exception
                )
        );
    }

    /*
     * Queue database cleanup before shutting down
     * the executor.
     */
    public synchronized void shutdown() {

        if (executorService.isShutdown()) {

            return;
        }

        executorService.execute(() -> {

            try {

                databaseManager.close();

            } finally {

                credentialRepository = null;
                secureNoteRepository = null;
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
}
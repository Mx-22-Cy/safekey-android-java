package com.safekey.app.data.service;

import android.content.Context;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.repository.CredentialRepository;
import com.safekey.app.data.repository.SecureNoteRepository;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VaultDataService {

    private final SafeKeyDatabase databaseManager;
    private final ExecutorService executorService;

    private CredentialRepository credentialRepository;
    private SecureNoteRepository secureNoteRepository;

    public VaultDataService(Context context) {
        databaseManager =
                new SafeKeyDatabase(
                        context.getApplicationContext()
                );

        executorService =
                Executors.newSingleThreadExecutor();
    }

    public void openVault(
            String databasePassword,
            SimpleCallback callback
    ) {
        executorService.execute(() -> {
            try {
                SQLiteDatabase database =
                        databaseManager.open(
                                databasePassword
                        );

                credentialRepository =
                        new CredentialRepository(
                                database
                        );

                secureNoteRepository =
                        new SecureNoteRepository(
                                database
                        );

                callback.onSuccess();

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void closeVault(
            SimpleCallback callback
    ) {
        executorService.execute(() -> {
            try {
                databaseManager.close();

                credentialRepository = null;
                secureNoteRepository = null;

                callback.onSuccess();

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public boolean isVaultOpen() {
        return databaseManager.isOpen();
    }

    // =========================================================
    // CREDENTIALS
    // =========================================================

    public void addCredential(
            Credential credential,
            ResultCallback<Long> callback
    ) {
        executorService.execute(() -> {
            try {
                long id =
                        requireCredentialRepository()
                                .insert(credential);

                callback.onSuccess(id);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void getCredentials(
            ResultCallback<List<Credential>> callback
    ) {
        executorService.execute(() -> {
            try {
                List<Credential> credentials =
                        requireCredentialRepository()
                                .getAll();

                callback.onSuccess(credentials);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void updateCredential(
            Credential credential,
            ResultCallback<Integer> callback
    ) {
        executorService.execute(() -> {
            try {
                int rows =
                        requireCredentialRepository()
                                .update(credential);

                callback.onSuccess(rows);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void deleteCredential(
            long id,
            ResultCallback<Integer> callback
    ) {
        executorService.execute(() -> {
            try {
                int rows =
                        requireCredentialRepository()
                                .delete(id);

                callback.onSuccess(rows);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void searchCredentials(
            String query,
            ResultCallback<List<Credential>> callback
    ) {
        executorService.execute(() -> {
            try {
                List<Credential> results =
                        requireCredentialRepository()
                                .search(query);

                callback.onSuccess(results);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void setCredentialFavorite(
            long id,
            boolean favorite,
            ResultCallback<Integer> callback
    ) {
        executorService.execute(() -> {
            try {
                int rows =
                        requireCredentialRepository()
                                .setFavorite(
                                        id,
                                        favorite
                                );

                callback.onSuccess(rows);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    // =========================================================
    // SECURE NOTES
    // =========================================================

    public void addSecureNote(
            SecureNote note,
            ResultCallback<Long> callback
    ) {
        executorService.execute(() -> {
            try {
                long id =
                        requireSecureNoteRepository()
                                .insert(note);

                callback.onSuccess(id);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void getSecureNotes(
            ResultCallback<List<SecureNote>> callback
    ) {
        executorService.execute(() -> {
            try {
                List<SecureNote> notes =
                        requireSecureNoteRepository()
                                .getAll();

                callback.onSuccess(notes);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void updateSecureNote(
            SecureNote note,
            ResultCallback<Integer> callback
    ) {
        executorService.execute(() -> {
            try {
                int rows =
                        requireSecureNoteRepository()
                                .update(note);

                callback.onSuccess(rows);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void deleteSecureNote(
            long id,
            ResultCallback<Integer> callback
    ) {
        executorService.execute(() -> {
            try {
                int rows =
                        requireSecureNoteRepository()
                                .delete(id);

                callback.onSuccess(rows);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public void searchSecureNotes(
            String query,
            ResultCallback<List<SecureNote>> callback
    ) {
        executorService.execute(() -> {
            try {
                List<SecureNote> results =
                        requireSecureNoteRepository()
                                .search(query);

                callback.onSuccess(results);

            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    // =========================================================
    // INTERNAL HELPERS
    // =========================================================

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

    public void shutdown() {
        executorService.shutdown();
    }

    // =========================================================
    // CALLBACKS
    // =========================================================

    public interface SimpleCallback {

        void onSuccess();

        void onError(Exception exception);
    }

    public interface ResultCallback<T> {

        void onSuccess(T result);

        void onError(Exception exception);
    }
}
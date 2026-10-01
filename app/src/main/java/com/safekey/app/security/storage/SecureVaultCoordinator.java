package com.safekey.app.security.storage;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.List;

public final class SecureVaultCoordinator {

    private static final String DATABASE_KEY_CONTEXT =
            "safekey:database-key-envelope:v1";

    private final VaultDataService vaultDataService;
    private final VaultKeyEnvelopeStore envelopeStore;
    private final Argon2idMasterKeyDeriver keyDeriver;
    private final AesGcmCipher cipher;
    private final SecureRandom secureRandom;
    private final ExecutorService securityExecutor;
    private final Handler mainHandler;

    public SecureVaultCoordinator(
            Context context
    ) {
        Objects.requireNonNull(
                context,
                "context"
        );

        Context applicationContext =
                context.getApplicationContext();

        vaultDataService =
                new VaultDataService(
                        applicationContext
                );

        envelopeStore =
                new VaultKeyEnvelopeStore(
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

    public boolean hasVault() {
        return envelopeStore.hasEnvelope();
    }

    public boolean isVaultOpen() {
        return vaultDataService.isVaultOpen();
    }

    public void getCredential(
            long id,
            VaultDataService.ResultCallback<Credential> callback
    ) {
        vaultDataService.getCredential(
                id,
                callback
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

    public void updateCredential(
            Credential credential,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.updateCredential(
                credential,
                callback
        );
    }

    public void deleteCredential(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.deleteCredential(
                id,
                callback
        );
    }

    public void setCredentialFavorite(
            long id,
            boolean favorite,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.setCredentialFavorite(
                id,
                favorite,
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

    public void getSecureNotes(
            VaultDataService.ResultCallback<List<SecureNote>> callback
    ) {
        vaultDataService.getSecureNotes(
                callback
        );
    }

    public void createVault(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(
                callback,
                "callback"
        );

        char[] passwordCopy =
                copyAndValidatePassword(
                        masterPassword
                );

        try {
            securityExecutor.execute(
                    () ->
                            createVaultInBackground(
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

    private void createVaultInBackground(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        byte[] salt = null;
        byte[] derivedMasterKey = null;
        byte[] databaseKey = null;

        boolean envelopeSaved =
                false;

        try {
            if (envelopeStore.hasEnvelope()) {
                throw new IllegalStateException(
                        "A vault has already been created."
                );
            }

            salt =
                    keyDeriver.generateSalt();

            derivedMasterKey =
                    keyDeriver.deriveKey(
                            masterPassword,
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

            final byte[] keyForOpening =
                    databaseKey;

            vaultDataService.openVault(
                    keyForOpening,
                    new VaultDataService.SimpleCallback() {

                        @Override
                        public void onSuccess() {
                            callback.onSuccess();
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {
                            clearEnvelopeAfterCreationFailure(
                                    exception
                            );

                            callback.onError(
                                    exception
                            );
                        }
                    }
            );

        } catch (Exception exception) {
            if (envelopeSaved) {
                clearEnvelopeAfterCreationFailure(
                        exception
                );
            }

            deliverError(
                    callback,
                    exception
            );

        } finally {
            clear(
                    masterPassword
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

    public void unlockVault(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(
                callback,
                "callback"
        );

        char[] passwordCopy =
                copyAndValidatePassword(
                        masterPassword
                );

        try {
            securityExecutor.execute(
                    () ->
                            unlockVaultInBackground(
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

    private void unlockVaultInBackground(
            char[] masterPassword,
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
                        "No vault has been created."
                );
            }

            salt =
                    envelope.getSalt();

            derivedMasterKey =
                    keyDeriver.deriveKey(
                            masterPassword,
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
                    masterPassword
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

    public void closeVault(
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

    public void shutdown() {
        if (securityExecutor.isShutdown()) {
            return;
        }

        securityExecutor.execute(
                vaultDataService::shutdown
        );

        securityExecutor.shutdown();
    }

    private void clearEnvelopeAfterCreationFailure(
            Exception originalError
    ) {
        try {
            envelopeStore.clear();

        } catch (RuntimeException clearingError) {
            originalError.addSuppressed(
                    clearingError
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
            char[] masterPassword
    ) {
        if (masterPassword == null) {
            throw new IllegalArgumentException(
                    "Master password cannot be null."
            );
        }

        if (masterPassword.length == 0) {
            throw new IllegalArgumentException(
                    "Master password cannot be empty."
            );
        }

        return Arrays.copyOf(
                masterPassword,
                masterPassword.length
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

package com.safekey.app.security.storage;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.fragment.app.FragmentActivity;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.biometric.BiometricAuthenticator;
import com.safekey.app.security.biometric.BiometricVaultKeyManager;
import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.data.model.VaultCounts;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    public BiometricAuthenticator.Availability getBiometricAvailability(
            FragmentActivity activity
    ) {

        requireActivity(
                activity
        );

        return new BiometricVaultKeyManager(
                activity
        ).getAvailability();
    }

    public boolean isBiometricUnlockConfigured(
            FragmentActivity activity
    ) throws Exception {

        requireActivity(
                activity
        );

        return new BiometricVaultKeyManager(
                activity
        ).isConfigured();
    }

    public void enableBiometricUnlock(
            FragmentActivity activity,
            char[] masterPassword,
            String title,
            String subtitle,
            BiometricSetupCallback callback
    ) {

        requireActivity(
                activity
        );

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
                            enableBiometricUnlockInBackground(
                                    activity,
                                    passwordCopy,
                                    title,
                                    subtitle,
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

    private void enableBiometricUnlockInBackground(
            FragmentActivity activity,
            char[] masterPassword,
            String title,
            String subtitle,
            BiometricSetupCallback callback
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

            final byte[] keyForBiometric =
                    Arrays.copyOf(
                            databaseKey,
                            databaseKey.length
                    );

            boolean posted =
                    mainHandler.post(
                            () ->
                                    startBiometricEnrollment(
                                            activity,
                                            keyForBiometric,
                                            title,
                                            subtitle,
                                            callback
                                    )
                    );

            if (!posted) {

                clear(
                        keyForBiometric
                );

                throw new IllegalStateException(
                        "Unable to start biometric enrollment."
                );
            }

        } catch (Exception exception) {

            deliverBiometricSetupError(
                    callback,
                    "Unable to verify the master password or prepare biometric unlock."
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

    private void startBiometricEnrollment(
            FragmentActivity activity,
            byte[] databaseKey,
            String title,
            String subtitle,
            BiometricSetupCallback callback
    ) {

        try {

            BiometricVaultKeyManager biometricManager =
                    new BiometricVaultKeyManager(
                            activity
                    );

            biometricManager.enableBiometricUnlock(
                    databaseKey,
                    title,
                    subtitle,
                    new BiometricVaultKeyManager.SetupCallback() {

                        @Override
                        public void onEnabled() {

                            callback.onEnabled();
                        }

                        @Override
                        public void onError(
                                String message
                        ) {

                            callback.onError(
                                    message
                            );
                        }

                        @Override
                        public void onFailed() {

                            callback.onFailed();
                        }
                    }
            );

        } catch (RuntimeException exception) {

            callback.onError(
                    "Unable to prepare biometric unlock."
            );

        } finally {

            clear(
                    databaseKey
            );
        }
    }

    public void unlockVaultWithBiometrics(
            FragmentActivity activity,
            String title,
            String subtitle,
            BiometricUnlockCallback callback
    ) {

        requireActivity(
                activity
        );

        Objects.requireNonNull(
                callback,
                "callback"
        );

        boolean posted =
                mainHandler.post(
                        () -> {

                            try {

                                BiometricVaultKeyManager biometricManager =
                                        new BiometricVaultKeyManager(
                                                activity
                                        );

                                biometricManager.unlockWithBiometrics(
                                        title,
                                        subtitle,
                                        new BiometricVaultKeyManager.UnlockCallback() {

                                            @Override
                                            public void onUnlocked(
                                                    byte[] vaultKey
                                            ) {

                                                openVaultAfterBiometricAuthentication(
                                                        vaultKey,
                                                        callback
                                                );
                                            }

                                            @Override
                                            public void onError(
                                                    String message
                                            ) {

                                                callback.onError(
                                                        message
                                                );
                                            }

                                            @Override
                                            public void onFailed() {

                                                callback.onFailed();
                                            }
                                        }
                                );

                            } catch (RuntimeException exception) {

                                callback.onError(
                                        "Unable to prepare biometric authentication."
                                );
                            }
                        }
                );

        if (!posted) {

            callback.onError(
                    "Unable to start biometric authentication."
            );
        }
    }

    private void openVaultAfterBiometricAuthentication(
            byte[] vaultKey,
            BiometricUnlockCallback callback
    ) {

        if (vaultKey == null) {

            callback.onError(
                    "Biometric authentication returned no vault key."
            );

            return;
        }

        try {

            vaultDataService.openVault(
                    vaultKey,
                    new VaultDataService.SimpleCallback() {

                        @Override
                        public void onSuccess() {

                            callback.onSuccess();
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {

                            callback.onError(
                                    "Biometric authentication succeeded, but the vault could not be opened."
                            );
                        }
                    }
            );

        } catch (RuntimeException exception) {

            callback.onError(
                    "Biometric authentication succeeded, but the vault could not be opened."
            );

        } finally {

            clear(
                    vaultKey
            );
        }
    }

    public void disableBiometricUnlock(
            FragmentActivity activity,
            VaultDataService.SimpleCallback callback
    ) {

        requireActivity(
                activity
        );

        Objects.requireNonNull(
                callback,
                "callback"
        );

        boolean posted =
                mainHandler.post(
                        () -> {

                            try {

                                BiometricVaultKeyManager biometricManager =
                                        new BiometricVaultKeyManager(
                                                activity
                                        );

                                biometricManager.disableBiometricUnlock();

                                callback.onSuccess();

                            } catch (Exception exception) {

                                callback.onError(
                                        exception
                                );
                            }
                        }
                );

        if (!posted) {

            callback.onError(
                    new IllegalStateException(
                            "Unable to disable biometric unlock."
                    )
            );
        }
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

    public void getVaultCounts(
            VaultDataService.ResultCallback<VaultCounts> callback
    ) {
        vaultDataService.getVaultCounts(
                Objects.requireNonNull(callback, "callback")
        );
    }

    public void getCredentials(
            VaultDataService.ResultCallback<List<Credential>> callback
    ) {

        vaultDataService.getCredentials(
                callback
        );
    }

    public void getSecureNote(
            long id,
            VaultDataService.ResultCallback<SecureNote> callback
    ) {

        vaultDataService.getSecureNotes(
                new VaultDataService.ResultCallback<List<SecureNote>>() {

                    @Override
                    public void onSuccess(
                            List<SecureNote> notes
                    ) {

                        SecureNote matchingNote =
                                null;

                        if (notes != null) {

                            for (SecureNote note : notes) {

                                if (note.getId() == id) {

                                    matchingNote =
                                            note;

                                    break;
                                }
                            }
                        }

                        callback.onSuccess(
                                matchingNote
                        );
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        callback.onError(
                                exception
                        );
                    }
                }
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

    public void updateSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Integer> callback
    ) {

        vaultDataService.updateSecureNote(
                note,
                callback
        );
    }

    public void deleteSecureNote(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {

        vaultDataService.deleteSecureNote(
                id,
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

    private void deliverBiometricSetupError(
            BiometricSetupCallback callback,
            String message
    ) {

        mainHandler.post(
                () ->
                        callback.onError(
                                message
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

    private static FragmentActivity requireActivity(
            FragmentActivity activity
    ) {

        return Objects.requireNonNull(
                activity,
                "activity"
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

    public interface BiometricSetupCallback {

        void onEnabled();

        void onError(
                String message
        );

        void onFailed();
    }

    public interface BiometricUnlockCallback {

        void onSuccess();

        void onError(
                String message
        );

        void onFailed();
    }
}
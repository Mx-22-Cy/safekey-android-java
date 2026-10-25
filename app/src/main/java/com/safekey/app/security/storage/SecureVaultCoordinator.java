package com.safekey.app.security.storage;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import androidx.fragment.app.FragmentActivity;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordValidationResult;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.VaultSessionManager;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.biometric.BiometricAuthenticator;
import com.safekey.app.security.biometric.BiometricVaultKeyManager;
import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.security.totp.VaultUnlockGate;

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
    private final VaultUnlockFlow unlockFlow;
    private final BiometricUnlockSource biometricUnlockSource;

    public SecureVaultCoordinator(Context context) {
        this(context, null, null);
    }

    // Test injection keeps the real password/SQLCipher path and substitutes
    // only the TOTP clock/store or the biometric prompt's authenticated result.
    SecureVaultCoordinator(
            Context context,
            VaultUnlockGate suppliedGate,
            BiometricUnlockSource suppliedBiometricSource
    ) {
        Objects.requireNonNull(context, "context");

        Context applicationContext = context.getApplicationContext();

        vaultDataService = new VaultDataService(applicationContext);
        envelopeStore = new VaultKeyEnvelopeStore(applicationContext);
        keyDeriver = new Argon2idMasterKeyDeriver();
        cipher = new AesGcmCipher();
        secureRandom = new SecureRandom();
        securityExecutor = Executors.newSingleThreadExecutor();
        mainHandler = new Handler(Looper.getMainLooper());

        VaultUnlockGate gate = suppliedGate != null
                ? suppliedGate
                : new VaultUnlockGate(
                new TotpSecretStore(applicationContext),
                System::currentTimeMillis,
                SystemClock::elapsedRealtime
        );

        unlockFlow = new VaultUnlockFlow(
                gate,
                securityExecutor,
                mainHandler,
                new VaultUnlockFlow.VaultAccess() {
                    @Override
                    public void open(
                            byte[] key,
                            VaultDataService.SimpleCallback callback
                    ) {
                        vaultDataService.openVault(key, callback);
                    }

                    @Override
                    public void close(VaultDataService.SimpleCallback callback) {
                        vaultDataService.closeVault(callback);
                    }
                }
        );

        biometricUnlockSource = suppliedBiometricSource != null
                ? suppliedBiometricSource
                : (activity, title, subtitle, callback) ->
                new BiometricVaultKeyManager(activity)
                        .unlockWithBiometrics(
                                title,
                                subtitle,
                                callback
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
        requireActivity(activity);
        return new BiometricVaultKeyManager(activity).getAvailability();
    }

    public boolean isBiometricUnlockConfigured(
            FragmentActivity activity
    ) throws Exception {
        requireActivity(activity);
        return new BiometricVaultKeyManager(activity).isConfigured();
    }

    public void enableBiometricUnlock(
            FragmentActivity activity,
            char[] masterPassword,
            String title,
            String subtitle,
            BiometricSetupCallback callback
    ) {
        requireActivity(activity);
        Objects.requireNonNull(callback, "callback");

        char[] passwordCopy = copyAndValidatePassword(masterPassword);

        try {
            securityExecutor.execute(() ->
                    enableBiometricUnlockInBackground(
                            activity,
                            passwordCopy,
                            title,
                            subtitle,
                            callback
                    )
            );
        } catch (RuntimeException schedulingError) {
            clear(passwordCopy);
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
            VaultKeyEnvelope envelope = envelopeStore.load();

            if (envelope == null) {
                throw new IllegalStateException(
                        "No vault has been created."
                );
            }

            salt = envelope.getSalt();
            derivedMasterKey = keyDeriver.deriveKey(masterPassword, salt);

            databaseKey = cipher.decrypt(
                    envelope.getWrappedDatabaseKey(),
                    derivedMasterKey,
                    databaseKeyContext()
            );

            final byte[] keyForBiometric =
                    Arrays.copyOf(databaseKey, databaseKey.length);

            boolean posted = mainHandler.post(() ->
                    startBiometricEnrollment(
                            activity,
                            keyForBiometric,
                            title,
                            subtitle,
                            callback
                    )
            );

            if (!posted) {
                clear(keyForBiometric);
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
            clear(masterPassword);
            clear(salt);
            clear(derivedMasterKey);
            clear(databaseKey);
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
                    new BiometricVaultKeyManager(activity);

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
                        public void onError(String message) {
                            callback.onError(message);
                        }

                        @Override
                        public void onFailed() {
                            callback.onFailed();
                        }
                    }
            );
        } catch (RuntimeException exception) {
            callback.onError("Unable to prepare biometric unlock.");
        } finally {
            clear(databaseKey);
        }
    }

    public VaultUnlockFlow.Request unlockVaultWithBiometrics(
            FragmentActivity activity,
            String title,
            String subtitle,
            BiometricUnlockCallback callback
    ) {
        requireActivity(activity);
        Objects.requireNonNull(callback, "callback");

        VaultUnlockFlow.Request request =
                unlockFlow.begin(new VaultUnlockFlow.Listener() {
                    @Override
                    public void onSuccess() {
                        callback.onSuccess();
                    }

                    @Override
                    public void onError(Exception error) {
                        callback.onError(
                                error.getMessage() != null
                                        ? error.getMessage()
                                        : "Unable to unlock the vault."
                        );
                    }

                    @Override
                    public void onTotpRequired(VaultUnlockFlow.Request pending) {
                        if (callback instanceof TotpBiometricUnlockCallback) {
                            ((TotpBiometricUnlockCallback) callback)
                                    .onTotpRequired(pending);
                        } else {
                            unlockFlow.fail(
                                    pending,
                                    new IllegalStateException(
                                            "Authenticator code required."
                                    )
                            );
                        }
                    }

                    @Override
                    public void onPrimaryFailed() {
                        callback.onFailed();
                    }

                    @Override
                    public boolean requiresSessionClaim() {
                        return callback instanceof TotpBiometricUnlockCallback;
                    }
                });

        boolean posted = mainHandler.post(() -> {
            if (!request.isActive()) {
                return;
            }

            try {
                biometricUnlockSource.unlock(
                        activity,
                        title,
                        subtitle,
                        new BiometricVaultKeyManager.UnlockCallback() {
                            @Override
                            public void onUnlocked(byte[] vaultKey) {
                                try {
                                    unlockFlow.acceptPrimary(request, vaultKey);
                                } finally {
                                    clear(vaultKey);
                                }
                            }

                            @Override
                            public void onError(String message) {
                                unlockFlow.fail(
                                        request,
                                        new IllegalStateException(message)
                                );
                            }

                            @Override
                            public void onFailed() {
                                unlockFlow.primaryFailed(request);
                            }
                        }
                );
            } catch (RuntimeException error) {
                unlockFlow.fail(request, error);
            }
        });

        if (!posted) {
            unlockFlow.fail(
                    request,
                    new IllegalStateException(
                            "Unable to start biometric authentication."
                    )
            );
        }

        return request;
    }

    public void disableBiometricUnlock(
            FragmentActivity activity,
            VaultDataService.SimpleCallback callback
    ) {
        requireActivity(activity);
        Objects.requireNonNull(callback, "callback");

        boolean posted = mainHandler.post(() -> {
            try {
                BiometricVaultKeyManager biometricManager =
                        new BiometricVaultKeyManager(activity);

                biometricManager.disableBiometricUnlock();
                callback.onSuccess();
            } catch (Exception exception) {
                callback.onError(exception);
            }
        });

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
        vaultDataService.getCredential(id, callback);
    }

    public void addCredential(
            Credential credential,
            VaultDataService.ResultCallback<Long> callback
    ) {
        vaultDataService.addCredential(credential, callback);
    }

    public void updateCredential(
            Credential credential,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.updateCredential(credential, callback);
    }

    public void deleteCredential(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.deleteCredential(id, callback);
    }

    public void setCredentialFavorite(
            long id,
            boolean favorite,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.setCredentialFavorite(id, favorite, callback);
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
        vaultDataService.getCredentials(callback);
    }

    public void getSecureNote(
            long id,
            VaultDataService.ResultCallback<SecureNote> callback
    ) {
        vaultDataService.getSecureNotes(
                new VaultDataService.ResultCallback<List<SecureNote>>() {
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
                }
        );
    }

    public void addSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Long> callback
    ) {
        vaultDataService.addSecureNote(note, callback);
    }

    public void updateSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.updateSecureNote(note, callback);
    }

    public void deleteSecureNote(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.deleteSecureNote(id, callback);
    }

    public void getSecureNotes(
            VaultDataService.ResultCallback<List<SecureNote>> callback
    ) {
        vaultDataService.getSecureNotes(callback);
    }

    /** Enrollment UI uses the same cancellable handoff/session claim as sign-in. */
    public VaultUnlockFlow.Request createVaultForEnrollment(
            char[] masterPassword,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");
        requireNewPassword(masterPassword);
        requireEnrollmentStatus(checkStatus);
        char[] copy = masterPassword.clone();
        VaultUnlockFlow.Request request = null;
        try {
            request = unlockFlow.begin(new VaultUnlockFlow.Listener() {
                @Override public void onSuccess() { callback.onSuccess(); }
                @Override public void onError(Exception error) { callback.onError(error); }
                @Override public boolean requiresSessionClaim() { return true; }
                @Override public void onTotpRequired(VaultUnlockFlow.Request pending) {
                    unlockFlow.fail(pending, new IllegalStateException(
                            "Existing authenticator state requires sign-in."));
                }
            });
            VaultUnlockFlow.Request scheduled = request;
            securityExecutor.execute(() -> createEnrollmentInBackground(
                    copy, checkStatus, scheduled));
            return request;
        } catch (RuntimeException error) {
            clear(copy);
            if (request != null) { request.close(); }
            throw error;
        }
    }

    private void createEnrollmentInBackground(
            char[] password,
            MasterPasswordCheckStatus checkStatus,
            VaultUnlockFlow.Request request
    ) {
        byte[] salt = null;
        byte[] masterKey = null;
        byte[] databaseKey = null;
        try {
            if (!request.isActive()) { return; }
            if (envelopeStore.hasEnvelope()) {
                throw new IllegalStateException("A vault has already been created.");
            }
            salt = keyDeriver.generateSalt();
            masterKey = keyDeriver.deriveKey(password, salt);
            databaseKey = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
            secureRandom.nextBytes(databaseKey);
            VaultKeyEnvelope envelope = new VaultKeyEnvelope(salt,
                    cipher.encrypt(databaseKey, masterKey, databaseKeyContext()));
            if (!request.isActive()) { return; }
            envelopeStore.save(envelope, checkStatus);
            // A saved envelope is retained if the UI leaves: future sign-in can
            // open this vault. Cancellation still prevents a session claim.
            unlockFlow.acceptPrimary(request, databaseKey);
        } catch (Exception error) {
            unlockFlow.fail(request, error);
        } finally {
            clear(password);
            clear(salt);
            clear(masterKey);
            clear(databaseKey);
        }
    }

    /**
     * Low-level envelope replacement. UI callers screen the proposed complete
     * password first and obtain explicit consent before passing PENDING.
     * The database key stays the same, preserving credentials, TOTP and biometrics.
     */
    public MasterPasswordChangeRequest changeMasterPassword(
            char[] currentPassword,
            char[] newPassword,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");
        requireNewPassword(newPassword);
        requireEnrollmentStatus(checkStatus);
        if (currentPassword == null || currentPassword.length == 0) {
            throw new IllegalArgumentException("Current password is required.");
        }
        if (Arrays.equals(currentPassword, newPassword)) {
            throw new IllegalArgumentException("Choose a different master password.");
        }
        VaultSessionManager session = SafeKeySession.getManager();
        long authentication = session.getAuthenticationGeneration();
        if (authentication < 0L || !isVaultOpen()) {
            throw new IllegalStateException("An authenticated vault session is required.");
        }
        MasterPasswordChangeRequest request =
                new MasterPasswordChangeRequest(currentPassword, newPassword);
        try {
            securityExecutor.execute(() -> changeMasterPasswordInBackground(
                    request, authentication, checkStatus, callback));
            return request;
        } catch (RuntimeException error) {
            request.close();
            throw error;
        }
    }

    private void changeMasterPasswordInBackground(
            MasterPasswordChangeRequest request,
            long authentication,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback
    ) {
        char[][] passwords = request.takePasswords();
        if (passwords == null) { return; }
        byte[] oldSalt = null;
        byte[] oldMasterKey = null;
        byte[] databaseKey = null;
        byte[] newSalt = null;
        byte[] newMasterKey = null;
        try {
            if (request.isCancelled()) { return; }
            VaultKeyEnvelope original = envelopeStore.load();
            if (original == null) {
                throw new IllegalStateException("No vault has been created.");
            }
            oldSalt = original.getSalt();
            oldMasterKey = keyDeriver.deriveKey(passwords[0], oldSalt);
            databaseKey = cipher.decrypt(original.getWrappedDatabaseKey(),
                    oldMasterKey, databaseKeyContext());
            if (request.isCancelled()) { return; }
            newSalt = keyDeriver.generateSalt();
            newMasterKey = keyDeriver.deriveKey(passwords[1], newSalt);
            VaultKeyEnvelope replacement = new VaultKeyEnvelope(newSalt,
                    cipher.encrypt(databaseKey, newMasterKey, databaseKeyContext()));
            // Commit on the UI thread: unlock-flow callbacks can hold their
            // own lock while consulting the session manager. A security worker
            // must not hold the session lock and call back into that flow.
            // Only salt/ciphertext cross this boundary, never a raw key/password.
            if (!mainHandler.post(() -> {
                if (request.isCancelled()) { return; }
                try {
                    boolean[] committed = {false};
                    SafeKeySession.getManager().runIfCurrentAuthentication(authentication, () ->
                            committed[0] = request.commit(() -> {
                                if (!isVaultOpen() || !envelopeStore.replaceIfMatches(
                                        original, replacement, checkStatus)) {
                                    throw new IllegalStateException("Vault state changed; sign in again.");
                                }
                            }));
                    if (committed[0] && !request.isCancelled()) { callback.onSuccess(); }
                } catch (RuntimeException error) {
                    if (!request.isCancelled()
                            && SafeKeySession.getManager().getAuthenticationGeneration()
                            == authentication) { callback.onError(error); }
                }
            })) { request.close(); }
        } catch (Exception error) {
            mainHandler.post(() -> {
                if (!request.isCancelled()
                        && SafeKeySession.getManager().getAuthenticationGeneration()
                        == authentication) {
                    callback.onError(error);
                }
            });
        } finally {
            clear(passwords[0]);
            clear(passwords[1]);
            clear(oldSalt);
            clear(oldMasterKey);
            clear(databaseKey);
            clear(newSalt);
            clear(newMasterKey);
        }
    }

    private static void requireNewPassword(char[] password) {
        if (MasterPasswordPolicy.validate(password) != MasterPasswordValidationResult.VALID) {
            throw new IllegalArgumentException("The proposed master password was rejected.");
        }
    }

    private static void requireEnrollmentStatus(MasterPasswordCheckStatus status) {
        if (status != MasterPasswordCheckStatus.CHECKED
                && status != MasterPasswordCheckStatus.PENDING) {
            throw new IllegalArgumentException("The proposed password cannot be accepted.");
        }
    }

    public void createVault(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");

        char[] passwordCopy = copyAndValidatePassword(masterPassword);

        try {
            securityExecutor.execute(() ->
                    createVaultInBackground(passwordCopy, callback)
            );
        } catch (RuntimeException schedulingError) {
            clear(passwordCopy);
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
        boolean envelopeSaved = false;

        try {
            if (envelopeStore.hasEnvelope()) {
                throw new IllegalStateException(
                        "A vault has already been created."
                );
            }

            salt = keyDeriver.generateSalt();
            derivedMasterKey = keyDeriver.deriveKey(masterPassword, salt);

            databaseKey =
                    new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
            secureRandom.nextBytes(databaseKey);

            String wrappedDatabaseKey = cipher.encrypt(
                    databaseKey,
                    derivedMasterKey,
                    databaseKeyContext()
            );

            VaultKeyEnvelope envelope =
                    new VaultKeyEnvelope(salt, wrappedDatabaseKey);

            envelopeStore.save(envelope);
            envelopeSaved = true;

            vaultDataService.openVault(
                    databaseKey,
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            callback.onSuccess();
                        }

                        @Override
                        public void onError(Exception exception) {
                            clearEnvelopeAfterCreationFailure(exception);
                            callback.onError(exception);
                        }
                    }
            );
        } catch (Exception exception) {
            if (envelopeSaved) {
                clearEnvelopeAfterCreationFailure(exception);
            }

            deliverError(callback, exception);
        } finally {
            clear(masterPassword);
            clear(salt);
            clear(derivedMasterKey);
            clear(databaseKey);
        }
    }

    public VaultUnlockFlow.Request unlockVault(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");

        char[] passwordCopy = copyAndValidatePassword(masterPassword);
        VaultUnlockFlow.Request request = null;

        try {
            request = unlockFlow.begin(new VaultUnlockFlow.Listener() {
                @Override
                public void onSuccess() {
                    callback.onSuccess();
                }

                @Override
                public void onError(Exception error) {
                    callback.onError(error);
                }

                @Override
                public boolean requiresSessionClaim() {
                    return callback instanceof TotpUnlockCallback;
                }

                @Override
                public void onTotpRequired(VaultUnlockFlow.Request pending) {
                    if (callback instanceof TotpUnlockCallback) {
                        ((TotpUnlockCallback) callback).onTotpRequired(pending);
                    } else {
                        unlockFlow.fail(
                                pending,
                                new IllegalStateException(
                                        "Authenticator code required."
                                )
                        );
                    }
                }
            });

            VaultUnlockFlow.Request scheduled = request;

            securityExecutor.execute(() ->
                    unlockVaultInBackground(passwordCopy, scheduled)
            );

            return request;
        } catch (RuntimeException error) {
            clear(passwordCopy);

            if (request != null) {
                request.close();
            }

            throw error;
        }
    }

    private void unlockVaultInBackground(
            char[] masterPassword,
            VaultUnlockFlow.Request request
    ) {
        byte[] salt = null;
        byte[] derivedMasterKey = null;
        byte[] databaseKey = null;

        try {
            if (!request.isActive()) {
                return;
            }

            VaultKeyEnvelope envelope = envelopeStore.load();

            if (envelope == null) {
                throw new IllegalStateException(
                        "No vault has been created."
                );
            }

            salt = envelope.getSalt();
            derivedMasterKey = keyDeriver.deriveKey(masterPassword, salt);

            databaseKey = cipher.decrypt(
                    envelope.getWrappedDatabaseKey(),
                    derivedMasterKey,
                    databaseKeyContext()
            );

            unlockFlow.acceptPrimary(request, databaseKey);
        } catch (Exception error) {
            unlockFlow.fail(request, error);
        } finally {
            clear(masterPassword);
            clear(salt);
            clear(derivedMasterKey);
            clear(databaseKey);
        }
    }

    public void closeVault(VaultDataService.SimpleCallback callback) {
        unlockFlow.closeVault(callback);
    }

    public void shutdown() {
        unlockFlow.shutdown();

        if (securityExecutor.isShutdown()) {
            return;
        }

        securityExecutor.execute(vaultDataService::shutdown);
        securityExecutor.shutdown();
    }

    private void clearEnvelopeAfterCreationFailure(Exception originalError) {
        try {
            envelopeStore.clear();
        } catch (RuntimeException clearingError) {
            originalError.addSuppressed(clearingError);
        }
    }

    private void deliverError(
            VaultDataService.SimpleCallback callback,
            Exception exception
    ) {
        mainHandler.post(() -> callback.onError(exception));
    }

    private void deliverBiometricSetupError(
            BiometricSetupCallback callback,
            String message
    ) {
        mainHandler.post(() -> callback.onError(message));
    }

    private static char[] copyAndValidatePassword(char[] masterPassword) {
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

        return Arrays.copyOf(masterPassword, masterPassword.length);
    }

    private static FragmentActivity requireActivity(FragmentActivity activity) {
        return Objects.requireNonNull(activity, "activity");
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

    public interface BiometricSetupCallback {
        void onEnabled();
        void onError(String message);
        void onFailed();
    }

    public interface BiometricUnlockCallback {
        void onSuccess();
        void onError(String message);
        void onFailed();
    }

    public interface TotpUnlockCallback
            extends VaultDataService.SimpleCallback {
        void onTotpRequired(VaultUnlockFlow.Request request);
    }

    public interface TotpBiometricUnlockCallback
            extends BiometricUnlockCallback {
        void onTotpRequired(VaultUnlockFlow.Request request);
    }

    interface BiometricUnlockSource {
        void unlock(
                FragmentActivity activity,
                String title,
                String subtitle,
                BiometricVaultKeyManager.UnlockCallback callback
        );
    }
}

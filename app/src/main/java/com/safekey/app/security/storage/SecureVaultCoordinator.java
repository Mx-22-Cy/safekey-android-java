package com.safekey.app.security.storage;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWorkGate;
import com.safekey.app.security.panic.PanicPasswordSeparation;
import com.safekey.app.security.panic.AndroidPanicPasswordSeparation;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import androidx.fragment.app.FragmentActivity;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordValidationResult;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.session.logic.VaultSessionManager;
import com.safekey.app.data.model.Credential;
import com.safekey.app.breach.PasswordBreachResult;
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
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;

public final class SecureVaultCoordinator {

    private static final String DATABASE_KEY_CONTEXT =
            "safekey:database-key-envelope:v1";

    private final PanicRuntimeScope runtimeScope;
    private final VaultDataService vaultDataService;
    private final VaultKeyEnvelopeStore envelopeStore;
    private final PanicPasswordSeparation passwordSeparation;
    private final Argon2idMasterKeyDeriver keyDeriver;
    private final AesGcmCipher cipher;
    private final SecureRandom secureRandom;
    private final RecoveryKeyProtector recoveryKeyProtector;
    private final ExecutorService securityExecutor;
    private final Handler mainHandler;
    private final VaultUnlockFlow unlockFlow;
    private final BiometricUnlockSource biometricUnlockSource;
    private final Function<FragmentActivity, BiometricVaultKeyManager> biometricManagerFactory;

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
        this(context, suppliedGate, suppliedBiometricSource, BiometricVaultKeyManager::new);
    }

    // Configuration tests control the prompt while using real password and envelope storage.
    SecureVaultCoordinator(
            Context context,
            VaultUnlockGate suppliedGate,
            BiometricUnlockSource suppliedBiometricSource,
            Function<FragmentActivity, BiometricVaultKeyManager> biometricManagerFactory
    ) {
        Objects.requireNonNull(context, "context");
        this.biometricManagerFactory = Objects.requireNonNull(
                biometricManagerFactory, "biometricManagerFactory");

        Context applicationContext = context.getApplicationContext();
        runtimeScope = PanicRuntimeScope.capture(applicationContext);

        vaultDataService = new VaultDataService(applicationContext);
        envelopeStore = new VaultKeyEnvelopeStore(applicationContext);
        passwordSeparation = AndroidPanicPasswordSeparation.create(applicationContext, runtimeScope);
        keyDeriver = new Argon2idMasterKeyDeriver();
        cipher = new AesGcmCipher();
        secureRandom = new SecureRandom();
        recoveryKeyProtector = new RecoveryKeyProtector(keyDeriver, cipher, secureRandom);
        securityExecutor = Executors.newSingleThreadExecutor();
        runtimeScope.registerExecutor(securityExecutor);
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
                },
                runtimeScope
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

    public boolean belongsToPanicRuntime(PanicRuntimeScope expected) { return runtimeScope == expected; }

    public VaultUnlockFlow.CompletedAuthentication getCompletedAuthentication() {
        return unlockFlow.getCompletedAuthentication();
    }

    public boolean runIfCurrentCompletedAuthentication(
            VaultUnlockFlow.CompletedAuthentication expected, Runnable action) {
        return unlockFlow.runIfCurrentCompletedAuthentication(expected, action);
    }

    public boolean isVaultOpen() {
        return vaultDataService.isVaultOpen();
    }

    /** Re-verifies the master password on the enrollment coordinator's worker. */
    public void verifyMasterPasswordForTotpEnrollment(char[] masterPassword) throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Verify the master password on the enrollment worker.");
        }
        char[] passwordCopy = copyAndValidatePassword(masterPassword);
        byte[] salt = null;
        byte[] masterKey = null;
        byte[] databaseKey = null;
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            VaultKeyEnvelope envelope = envelopeStore.load();
            if (envelope == null) {
                throw new IllegalStateException("No vault has been created.");
            }
            salt = envelope.getSalt();
            masterKey = keyDeriver.deriveKey(passwordCopy, salt);
            databaseKey = cipher.decrypt(
                    envelope.getWrappedDatabaseKey(), masterKey, databaseKeyContext());
            if (databaseKey.length != SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES) {
                throw new GeneralSecurityException("Invalid protected vault key.");
            }
        } finally {
            clear(passwordCopy);
            clear(salt);
            clear(masterKey);
            clear(databaseKey);
        }
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

    private BiometricVaultKeyManager.ConfigurationGuard captureRealBiometricSession(
            FragmentActivity activity
    ) {
        requireActivity(activity);
        if (!(activity.getApplication() instanceof SafeKeyApplication)) {
            throw new IllegalStateException("An authenticated REAL vault session is required.");
        }
        SafeKeyApplication application = (SafeKeyApplication) activity.getApplication();
        VaultSessionManager session = SafeKeySession.getManager();
        long authentication = session.getAuthenticationGeneration();
        VaultOperations[] activeVault = new VaultOperations[1];
        session.runIfCurrentAuthentication(authentication,
                () -> activeVault[0] = currentRealVaultOperations(application, activity));
        VaultOperations initiatingVault = activeVault[0];
        if (initiatingVault == null) {
            throw new IllegalStateException("An authenticated REAL vault session is required.");
        }

        return action -> {
            boolean[] executed = {false};
            Exception[] failure = new Exception[1];
            session.runIfCurrentAuthentication(authentication, () -> {
                // A new vault activation gets a new operations object. A vault switch
                // first locks the initiating session, which uses this same session lock.
                if (currentRealVaultOperations(application, activity) != initiatingVault) {
                    return;
                }
                executed[0] = true;
                try {
                    action.run();
                } catch (Exception error) {
                    failure[0] = error;
                }
            });
            if (failure[0] != null) {
                throw failure[0];
            }
            return executed[0];
        };
    }

    private VaultOperations currentRealVaultOperations(
            SafeKeyApplication application,
            FragmentActivity activity
    ) {
        if (activity.isFinishing() || activity.isDestroyed()
                || application.getPanicRuntimeScope() != runtimeScope
                || application.getActiveVault() != SafeKeyApplication.ActiveVault.REAL) {
            return null;
        }
        try {
            return application.getActiveVaultOperations();
        } catch (IllegalStateException noActiveVault) {
            return null;
        }
    }

    private void enableBiometricUnlockWhileRunning(
            FragmentActivity activity,
            char[] masterPassword,
            String title,
            String subtitle,
            BiometricVaultKeyManager.ConfigurationGuard guard,
            BiometricSetupCallback callback
    ) {
        requireActivity(activity);
        Objects.requireNonNull(callback, "callback");

        char[] passwordCopy = copyAndValidatePassword(masterPassword);

        try {
            executeSecurity(() ->
                    enableBiometricUnlockInBackground(
                            activity,
                            passwordCopy,
                            title,
                            subtitle,
                            guard,
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
            BiometricVaultKeyManager.ConfigurationGuard guard,
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

            final PanicRuntimeScope.PendingOperation handoff;
            try {
                handoff = runtimeScope.pending(() -> clear(keyForBiometric), () -> {});
            } catch (RuntimeException stopped) {
                clear(keyForBiometric);
                throw stopped;
            }
            boolean posted = false;
            try {
                posted = runtimeScope.deliver(mainHandler, () -> {
                    try {
                        if (handoff.isCurrent()) {
                            startBiometricEnrollment(
                                    activity, keyForBiometric, title, subtitle, guard, callback);
                        }
                    } finally { handoff.close(); }
                });
            } finally {
                if (!posted) { handoff.close(); }
            }

            if (!posted) {
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
            BiometricVaultKeyManager.ConfigurationGuard guard,
            BiometricSetupCallback callback
    ) {
        try {
            BiometricVaultKeyManager biometricManager =
                    biometricManagerFactory.apply(activity);
            BiometricVaultKeyManager.SetupCallback setupCallback =
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
                    };

            if (guard == null) {
                biometricManager.enableBiometricUnlock(databaseKey, title, subtitle, setupCallback);
            } else {
                biometricManager.enableBiometricUnlock(
                        databaseKey, title, subtitle, guard, setupCallback);
            }
        } catch (RuntimeException exception) {
            callback.onError("Unable to prepare biometric unlock.");
        } finally {
            clear(databaseKey);
        }
    }

    private VaultUnlockFlow.Request unlockVaultWithBiometricsWhileRunning(
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

        boolean posted = runtimeScope.deliver(mainHandler, () -> {
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
        disableBiometricUnlock(activity, null, callback);
    }

    /** Disables biometrics only while the REAL vault session that requested it remains active. */
    public void disableBiometricUnlockForRealSession(
            FragmentActivity activity,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");
        disableBiometricUnlock(activity, captureRealBiometricSession(activity), callback);
    }

    private void disableBiometricUnlock(
            FragmentActivity activity,
            BiometricVaultKeyManager.ConfigurationGuard guard,
            VaultDataService.SimpleCallback callback
    ) {
        requireActivity(activity);
        Objects.requireNonNull(callback, "callback");

        boolean posted = runtimeScope.deliver(mainHandler, () -> {
            if (runtimeScope.isStopped()) { return; }
            try {
                BiometricVaultKeyManager biometricManager =
                        biometricManagerFactory.apply(activity);

                if (guard == null) {
                    biometricManager.disableBiometricUnlock();
                } else {
                    biometricManager.disableBiometricUnlock(guard);
                }
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

    /**
     * Reads the display name from the real encrypted vault.
     */
    public void getVaultDisplayName(
            VaultDataService.ResultCallback<String> callback
    ) {
        vaultDataService.getVaultDisplayName(
                Objects.requireNonNull(callback, "callback")
        );
    }

    /**
     * Updates the display name in the real encrypted vault.
     */
    public void updateVaultDisplayName(
            String displayName,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        vaultDataService.updateVaultDisplayName(
                displayName,
                Objects.requireNonNull(callback, "callback")
        );
    }
    public void getVaultCounts(
            VaultDataService.ResultCallback<VaultCounts> callback
    ) {
        vaultDataService.getVaultCounts(
                Objects.requireNonNull(callback, "callback")
        );
    }

    public long getVaultGeneration() {
        return vaultDataService.getVaultGeneration();
    }

    public void updateCredentialBreachStatus(
            long generation, long id, String expectedPassword,
            PasswordBreachResult.Status status,
            VaultDataService.ResultCallback<PasswordBreachResult.Status> callback
    ) {
        vaultDataService.updateCredentialBreachStatus(
                generation, id, expectedPassword, status, callback);
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
    private VaultUnlockFlow.Request createVaultForEnrollmentWhileRunning(
            char[] masterPassword,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback,
            char[] recoveryKey
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
            executeSecurity(() -> createEnrollmentInBackground(
                    copy, checkStatus, scheduled, recoveryKey));
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
            VaultUnlockFlow.Request request,
            char[] recoveryKey
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
            VaultKeyEnvelope recoveryEnvelope = recoveryKey == null
                    ? null : recoveryKeyProtector.wrap(recoveryKey, databaseKey);
            try (PanicPasswordSeparation.Permit separation = passwordSeparation.prepare(
                    PanicPasswordSeparation.Role.MASTER, password)) {
                if (!request.isActive()) { return; }
                separation.commit(() -> {
                    if (envelopeStore.hasEnvelope()) { throw new IllegalStateException("A vault has already been created."); }
                    if (recoveryEnvelope == null) {
                        envelopeStore.save(envelope, checkStatus);
                    } else {
                        envelopeStore.saveForEnrollmentWithRecovery(envelope, checkStatus, recoveryEnvelope);
                    }
                });
            }
            // A saved envelope is retained if the UI leaves: future sign-in can
            // open this vault. Cancellation still prevents a session claim.
            unlockFlow.acceptPrimary(request, databaseKey);
        } catch (Exception error) {
            unlockFlow.fail(request, error);
        } finally {
            clear(password);
            clear(recoveryKey);
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
    private MasterPasswordChangeRequest changeMasterPasswordWhileRunning(
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
                new MasterPasswordChangeRequest(currentPassword, newPassword, runtimeScope);
        try {
            executeSecurity(() -> changeMasterPasswordInBackground(
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
            PanicPasswordSeparation.Permit separation = passwordSeparation.prepare(
                    PanicPasswordSeparation.Role.MASTER, passwords[1]);
            // Commit on the UI thread: unlock-flow callbacks can hold their
            // own lock while consulting the session manager. A security worker
            // must not hold the session lock and call back into that flow.
            // Only salt/ciphertext cross this boundary, never a raw key/password.
            if (!runtimeScope.deliver(mainHandler, () -> {
                if (request.isCancelled() || runtimeScope.isStopped()) { separation.close(); request.close(); return; }
                try {
                    boolean[] committed = {false};
                    SafeKeySession.getManager().runIfCurrentAuthentication(authentication, () ->
                            committed[0] = request.commit(() -> separation.commit(() -> {
                                if (!isVaultOpen() || !envelopeStore.replaceIfMatches(
                                        original, replacement, checkStatus)) {
                                    throw new IllegalStateException("Vault state changed; sign in again.");
                                }
                            })));
                    if (committed[0] && !request.isCancelled()) { callback.onSuccess(); }
                } catch (RuntimeException error) {
                    if (!request.isCancelled()
                            && SafeKeySession.getManager().getAuthenticationGeneration()
                            == authentication) { callback.onError(error); }
                } finally { separation.close(); }
            })) { separation.close(); request.close(); }
        } catch (Exception error) {
            runtimeScope.deliver(mainHandler, () -> {
                if (!request.isCancelled() && !runtimeScope.isStopped()
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

    private void createVaultWhileRunning(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");

        char[] passwordCopy = copyAndValidatePassword(masterPassword);

        try {
            executeSecurity(() ->
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

            try (PanicPasswordSeparation.Permit separation = passwordSeparation.prepare(
                    PanicPasswordSeparation.Role.MASTER, masterPassword)) {
                separation.commit(() -> {
                    if (envelopeStore.hasEnvelope()) { throw new IllegalStateException("A vault has already been created."); }
                    envelopeStore.save(envelope);
                });
            }
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

    private VaultUnlockFlow.Request unlockVaultWhileRunning(
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

            executeSecurity(() ->
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

        executeSecurity(vaultDataService::shutdown);
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
        runtimeScope.deliver(mainHandler, () -> { if (!runtimeScope.isStopped()) { callback.onError(exception); } });
    }

    private void deliverBiometricSetupError(
            BiometricSetupCallback callback,
            String message
    ) {
        runtimeScope.deliver(mainHandler, () -> { if (!runtimeScope.isStopped()) { callback.onError(message); } });
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

    public EnrollmentRecoveryKey prepareEnrollmentRecoveryKey() {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            if (envelopeStore.hasEnvelope()) {
                throw new IllegalStateException("A vault has already been created.");
            }
            return new EnrollmentRecoveryKey(this, recoveryKeyProtector.generateRecoveryKey());
        }
    }

    /** Call after the user confirms saving the displayed key. This consumes the handle. */
    public VaultUnlockFlow.Request createVaultForEnrollmentWithRecovery(
            char[] masterPassword,
            MasterPasswordCheckStatus checkStatus,
            EnrollmentRecoveryKey confirmedKey,
            VaultDataService.SimpleCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            char[] key = Objects.requireNonNull(confirmedKey, "confirmedKey").consume(this);
            boolean submitted = false;
            try {
                VaultUnlockFlow.Request request = createVaultForEnrollmentWhileRunning(
                        masterPassword, checkStatus, callback, key);
                submitted = true;
                return request;
            } finally {
                if (!submitted) {
                    clear(key);
                }
            }
        }
    }

    public static final class EnrollmentRecoveryKey implements AutoCloseable {
        private final SecureVaultCoordinator owner;
        private final PanicRuntimeScope.Registration cancellation;
        private char[] key;
        private boolean displayCopyTaken;

        private EnrollmentRecoveryKey(SecureVaultCoordinator owner, char[] key) {
            this.owner = owner;
            this.key = key;
            cancellation = owner.runtimeScope.onStop(this::close);
        }

        /** The UI owns the returned copy and must clear it when finished displaying it. */
        public synchronized char[] takeDisplayCopy() {
            if (key == null || displayCopyTaken || owner.runtimeScope.isStopped()) {
                throw new IllegalStateException("Recovery key is unavailable for display.");
            }
            char[] copy = key.clone();
            displayCopyTaken = true;
            return copy;
        }

        private synchronized char[] consume(SecureVaultCoordinator expectedOwner) {
            if (owner != expectedOwner || key == null || !displayCopyTaken
                    || owner.runtimeScope.isStopped()) {
                throw new IllegalStateException("Recovery key is unavailable for enrollment.");
            }
            char[] result = key;
            key = null;
            cancellation.close();
            return result;
        }

        @Override
        public synchronized void close() {
            clear(key);
            key = null;
            if (cancellation != null) {
                cancellation.close();
            }
        }
    }

    public VaultUnlockFlow.Request createVaultForEnrollment(
            char[] masterPassword,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return createVaultForEnrollmentWhileRunning(masterPassword, checkStatus, callback, null);
        }
    }


    /** Call from the locked recovery screen after vault authentication readiness. */
    public MasterPasswordChangeRequest resetMasterPasswordWithRecovery(
            char[] recoveryKey,
            char[] newPassword,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            Objects.requireNonNull(callback, "callback");
            requireNewPassword(newPassword);
            requireEnrollmentStatus(checkStatus);
            if (recoveryKey == null || recoveryKey.length == 0) {
                throw new IllegalArgumentException("Recovery key is required.");
            }
            if (SafeKeySession.getManager().getState() != SessionState.LOCKED || isVaultOpen()) {
                throw new IllegalStateException("Lock the vault before resetting its password.");
            }

            MasterPasswordChangeRequest request =
                    new MasterPasswordChangeRequest(recoveryKey, newPassword, runtimeScope);
            try {
                executeSecurity(() -> resetMasterPasswordInBackground(request, checkStatus, callback));
                return request;
            } catch (RuntimeException error) {
                request.close();
                throw error;
            }
        }
    }

    private void resetMasterPasswordInBackground(
            MasterPasswordChangeRequest request,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback
    ) {
        char[][] secrets = request.takePasswords();
        if (secrets == null) { return; }

        byte[] databaseKey = null;
        byte[] salt = null;
        byte[] newMasterKey = null;
        Exception failure = null;
        try {
            if (request.isCancelled() || runtimeScope.isStopped()) {
                request.close();
                return;
            }

            VaultKeyEnvelope original = envelopeStore.load();
            VaultKeyEnvelope recovery = envelopeStore.loadRecoveryEnvelope();
            if (original == null || recovery == null) {
                throw new IllegalStateException("Recovery is unavailable for this vault.");
            }

            databaseKey = recoveryKeyProtector.unwrap(secrets[0], recovery);
            if (databaseKey.length != SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES) {
                throw new IllegalStateException("Invalid recovered database key.");
            }
            if (request.isCancelled() || runtimeScope.isStopped()) {
                request.close();
                return;
            }

            salt = keyDeriver.generateSalt();
            newMasterKey = keyDeriver.deriveKey(secrets[1], salt);
            VaultKeyEnvelope replacement = new VaultKeyEnvelope(salt,
                    cipher.encrypt(databaseKey, newMasterKey, databaseKeyContext()));

            try (PanicPasswordSeparation.Permit separation = passwordSeparation.prepare(
                    PanicPasswordSeparation.Role.MASTER, secrets[1])) {
                VaultSessionManager session = SafeKeySession.getManager();
                boolean locked = session.runWhileLocked(() -> {
                    // Session cleanup can enter the unlock flow while holding the session lock.
                    if (!unlockFlow.isIdleForRecovery() || isVaultOpen()) {
                        throw new IllegalStateException("Vault authentication is in progress.");
                    }
                    request.commit(() -> separation.commit(() -> {
                        if (!envelopeStore.replaceMasterEnvelopeAfterRecovery(
                                original, recovery, replacement, checkStatus)) {
                            throw new IllegalStateException("Vault state changed during recovery.");
                        }
                    }));
                });
                if (!locked) {
                    throw new IllegalStateException("Vault state changed during recovery.");
                }
            }
        } catch (Exception error) {
            failure = error;
        } finally {
            clear(secrets[0]);
            clear(secrets[1]);
            clear(databaseKey);
            clear(salt);
            clear(newMasterKey);
        }

        deliverRecoveryResetResult(request, callback, failure);
    }

    private void deliverRecoveryResetResult(
            MasterPasswordChangeRequest request,
            VaultDataService.SimpleCallback callback,
            Exception failure
    ) {
        if (request.isCancelled() || runtimeScope.isStopped()) {
            request.close();
            return;
        }

        boolean posted = false;
        try {
            posted = runtimeScope.deliver(mainHandler, () -> {
                try {
                    if (request.isCancelled()) { return; }
                    if (failure == null) {
                        callback.onSuccess();
                    } else {
                        callback.onError(failure);
                    }
                } finally {
                    request.close();
                }
            });
        } finally {
            if (!posted) { request.close(); }
        }
    }

    public MasterPasswordChangeRequest changeMasterPassword(
            char[] currentPassword,
            char[] newPassword,
            MasterPasswordCheckStatus checkStatus,
            VaultDataService.SimpleCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return changeMasterPasswordWhileRunning(currentPassword, newPassword, checkStatus, callback);
        }
    }


    public void createVault(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            createVaultWhileRunning(masterPassword, callback);
        }
    }


    public VaultUnlockFlow.Request unlockVault(
            char[] masterPassword,
            VaultDataService.SimpleCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return unlockVaultWhileRunning(masterPassword, callback);
        }
    }


    public void enableBiometricUnlock(
            FragmentActivity activity,
            char[] masterPassword,
            String title,
            String subtitle,
            BiometricSetupCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            enableBiometricUnlockWhileRunning(
                    activity, masterPassword, title, subtitle, null, callback);
        }
    }

    /** Starts biometric enrollment from Settings with the current REAL vault session. */
    public void enableBiometricUnlockForRealSession(
            FragmentActivity activity,
            char[] masterPassword,
            String title,
            String subtitle,
            BiometricSetupCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            BiometricVaultKeyManager.ConfigurationGuard guard = captureRealBiometricSession(activity);
            enableBiometricUnlockWhileRunning(
                    activity, masterPassword, title, subtitle, guard, callback);
        }
    }


    public VaultUnlockFlow.Request unlockVaultWithBiometrics(
            FragmentActivity activity,
            String title,
            String subtitle,
            BiometricUnlockCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return unlockVaultWithBiometricsWhileRunning(activity, title, subtitle, callback);
        }
    }


    private void executeSecurity(Runnable work) {
        runtimeScope.execute(securityExecutor, work);
    }

}

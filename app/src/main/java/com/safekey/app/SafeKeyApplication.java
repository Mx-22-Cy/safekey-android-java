
package com.safekey.app;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.safekey.app.auth.MasterPasswordHealth;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.DecoyVaultStorage;
import com.safekey.app.security.storage.RealVaultOperations;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.SessionBoundVaultOperations;
import com.safekey.app.security.storage.VaultOperations;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class SafeKeyApplication extends Application {

    private static final String TAG = "SafeKeyApplication";

    public enum ActiveVault {
        NONE,
        REAL,
        DECOY
    }

    private SecureVaultCoordinator secureVaultCoordinator;
    private DecoyVaultCoordinator decoyVaultCoordinator;
    private VaultOperations realVaultOperations;
    private MasterPasswordHealth masterPasswordHealth;

    private final Handler mainHandler =
            new Handler(Looper.getMainLooper());

    private ActiveVault activeVault = ActiveVault.NONE;
    private VaultOperations activeVaultOperations;

    private long sessionGeneration = 0L;
    private long cleanupGeneration = 0L;

    private boolean cleanupInProgress;
    private boolean cleanupFailed;
    private int pendingCloses;

    private final List<VaultDataService.SimpleCallback>
            authenticationWaiters = new ArrayList<>();

    @Override
    public void onCreate() {
        super.onCreate();

        // The secondary encrypted database must always exist.
        DecoyVaultStorage.ensureDatabaseFile(this);

        secureVaultCoordinator =
                new SecureVaultCoordinator(this);

        decoyVaultCoordinator =
                new DecoyVaultCoordinator(this);

        realVaultOperations =
                new RealVaultOperations(
                        secureVaultCoordinator
                );

        // T45: Master-password security health.
        masterPasswordHealth =
                new MasterPasswordHealth(this);

        registerSessionCleanup();
    }

    public MasterPasswordHealth getMasterPasswordHealth() {
        return masterPasswordHealth;
    }

    public SecureVaultCoordinator getSecureVaultCoordinator() {
        return secureVaultCoordinator;
    }

    public DecoyVaultCoordinator getDecoyVaultCoordinator() {
        return decoyVaultCoordinator;
    }

    public ActiveVault getActiveVault() {
        if (SafeKeySession.getState() != SessionState.UNLOCKED) {
            return ActiveVault.NONE;
        }

        synchronized (this) {
            return activeVault;
        }
    }

    public void activateRealVault() {
        activateVault(ActiveVault.REAL);
    }

    public void activateDecoyVault() {
        activateVault(ActiveVault.DECOY);
    }

    private void activateVault(ActiveVault selection) {
        if (SafeKeySession.getState() != SessionState.UNLOCKED) {
            throw new IllegalStateException(
                    "Authentication is required before vault activation."
            );
        }

        synchronized (this) {
            if (cleanupInProgress || cleanupFailed) {
                throw new IllegalStateException(
                        "Vault cleanup has not completed successfully."
                );
            }

            if (activeVault != ActiveVault.NONE) {
                throw new IllegalStateException(
                        "A vault is already active."
                );
            }

            if (!isExclusivelyOpen(selection)) {
                throw new IllegalStateException(
                        "The selected vault is not exclusively open."
                );
            }

            final long generation = ++sessionGeneration;

            VaultOperations delegate =
                    selection == ActiveVault.REAL
                            ? realVaultOperations
                            : decoyVaultCoordinator;

            activeVaultOperations =
                    new SessionBoundVaultOperations(
                            delegate,
                            new SessionBoundVaultOperations.SessionGuard() {

                                @Override
                                public boolean isCurrent() {
                                    return isSessionCurrent(
                                            selection,
                                            generation
                                    );
                                }

                                @Override
                                public boolean runIfCurrent(
                                        Runnable action
                                ) {
                                    if (SafeKeySession.getState()
                                            != SessionState.UNLOCKED) {
                                        return false;
                                    }

                                    synchronized (SafeKeyApplication.this) {
                                        if (!matchesActiveSelection(
                                                selection,
                                                generation
                                        )) {
                                            return false;
                                        }

                                        action.run();
                                        return true;
                                    }
                                }
                            }
                    );

            activeVault = selection;
        }
    }

    private boolean isSessionCurrent(
            ActiveVault selection,
            long generation
    ) {
        if (SafeKeySession.getState() != SessionState.UNLOCKED) {
            return false;
        }

        synchronized (this) {
            return matchesActiveSelection(
                    selection,
                    generation
            );
        }
    }

    private boolean matchesActiveSelection(
            ActiveVault selection,
            long generation
    ) {
        return !cleanupInProgress
                && !cleanupFailed
                && activeVault == selection
                && sessionGeneration == generation
                && isExclusivelyOpen(selection);
    }

    private boolean isExclusivelyOpen(
            ActiveVault selection
    ) {
        if (selection == ActiveVault.REAL) {
            return secureVaultCoordinator.isVaultOpen()
                    && !decoyVaultCoordinator.isDecoyVaultOpen();
        }

        if (selection == ActiveVault.DECOY) {
            return decoyVaultCoordinator.isDecoyVaultOpen()
                    && !secureVaultCoordinator.isVaultOpen();
        }

        return false;
    }

    public VaultOperations getActiveVaultOperations() {
        if (SafeKeySession.getState() != SessionState.UNLOCKED) {
            throw new IllegalStateException(
                    "The vault session is locked."
            );
        }

        synchronized (this) {
            if (activeVaultOperations == null
                    || cleanupInProgress
                    || cleanupFailed
                    || !isExclusivelyOpen(activeVault)) {
                throw new IllegalStateException(
                        "No authenticated vault is available."
                );
            }

            return activeVaultOperations;
        }
    }

    /**
     * Call before starting another vault authentication.
     *
     * Authentication must not proceed until previous
     * database close operations have finished.
     */
    public void prepareForVaultAuthentication(
            VaultDataService.SimpleCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");

        if (SafeKeySession.getState() != SessionState.LOCKED) {
            deliverError(
                    callback,
                    new IllegalStateException(
                            "The previous session must be locked."
                    )
            );
            return;
        }

        long readinessGeneration;

        synchronized (this) {
            readinessGeneration = cleanupGeneration;

            if (cleanupInProgress) {
                authenticationWaiters.add(callback);
                return;
            }

            if (cleanupFailed
                    || secureVaultCoordinator.isVaultOpen()
                    || decoyVaultCoordinator.isDecoyVaultOpen()) {
                deliverError(
                        callback,
                        new IllegalStateException(
                                "Vault connections are not safely closed."
                        )
                );
                return;
            }
        }

        deliverSuccess(callback, readinessGeneration);
    }

    /**
     * Register cleanup for both vaults when the session locks.
     */
    public void registerSessionCleanup() {
        SafeKeySession.registerSensitiveDataCleanup(
                this::clearSessionAndCloseVaults
        );
    }

    private void clearSessionAndCloseVaults() {

        // T45: Stop pending master-password health checks.
        masterPasswordHealth.cancelRecheck();

        final long cleanupId;

        synchronized (this) {
            activeVault = ActiveVault.NONE;
            activeVaultOperations = null;

            sessionGeneration++;

            cleanupInProgress = true;
            cleanupFailed = false;
            pendingCloses = 2;

            cleanupId = ++cleanupGeneration;
        }

        // Close the primary Real Vault.
        try {
            secureVaultCoordinator.closeVault(
                    new VaultDataService.SimpleCallback() {

                        @Override
                        public void onSuccess() {
                            finishVaultClose(cleanupId, null);
                        }

                        @Override
                        public void onError(Exception exception) {
                            Log.e(
                                    TAG,
                                    "Failed to close real vault.",
                                    exception
                            );

                            finishVaultClose(
                                    cleanupId,
                                    exception
                            );
                        }
                    }
            );
        } catch (RuntimeException exception) {
            Log.e(
                    TAG,
                    "Failed to schedule real vault close.",
                    exception
            );

            finishVaultClose(cleanupId, exception);
        }

        // Close the independent Decoy Vault.
        try {
            decoyVaultCoordinator.closeDecoyVault(
                    new VaultDataService.SimpleCallback() {

                        @Override
                        public void onSuccess() {
                            finishVaultClose(cleanupId, null);
                        }

                        @Override
                        public void onError(Exception exception) {
                            Log.e(
                                    TAG,
                                    "Failed to close Decoy vault.",
                                    exception
                            );

                            finishVaultClose(
                                    cleanupId,
                                    exception
                            );
                        }
                    }
            );
        } catch (RuntimeException exception) {
            Log.e(
                    TAG,
                    "Failed to schedule Decoy vault close.",
                    exception
            );

            finishVaultClose(cleanupId, exception);
        }
    }

    private void finishVaultClose(
            long cleanupId,
            Exception exception
    ) {
        List<VaultDataService.SimpleCallback> waiters;
        boolean failed;

        synchronized (this) {
            if (cleanupId != cleanupGeneration) {
                return;
            }

            if (exception != null) {
                cleanupFailed = true;
            }

            pendingCloses--;

            if (pendingCloses != 0) {
                return;
            }

            cleanupInProgress = false;

            if (secureVaultCoordinator.isVaultOpen()
                    || decoyVaultCoordinator.isDecoyVaultOpen()) {
                cleanupFailed = true;
            }

            failed = cleanupFailed;

            waiters =
                    new ArrayList<>(authenticationWaiters);

            authenticationWaiters.clear();
        }

        for (VaultDataService.SimpleCallback waiter : waiters) {
            if (failed) {
                deliverError(
                        waiter,
                        new IllegalStateException(
                                "Vault cleanup failed."
                        )
                );
            } else {
                deliverSuccess(waiter, cleanupId);
            }
        }
    }

    private void deliverSuccess(
            VaultDataService.SimpleCallback callback,
            long expectedCleanupGeneration
    ) {
        mainHandler.post(
                () -> {
                    // Read session state before taking the app lock.
                    // This avoids recreating the session/cleanup lock cycle.
                    boolean sessionLocked =
                            SafeKeySession.getState() == SessionState.LOCKED;

                    boolean ready;

                    synchronized (this) {
                        ready =
                                sessionLocked
                                        && cleanupGeneration == expectedCleanupGeneration
                                        && !cleanupInProgress
                                        && !cleanupFailed
                                        && pendingCloses == 0
                                        && !secureVaultCoordinator.isVaultOpen()
                                        && !decoyVaultCoordinator.isDecoyVaultOpen();
                    }

                    if (!ready) {
                        callback.onError(
                                new IllegalStateException(
                                        "Authentication readiness expired."
                                )
                        );
                        return;
                    }

                    callback.onSuccess();
                }
        );
    }

    private void deliverError(
            VaultDataService.SimpleCallback callback,
            Exception exception
    ) {
        mainHandler.post(
                () -> callback.onError(exception)
        );
    }
}

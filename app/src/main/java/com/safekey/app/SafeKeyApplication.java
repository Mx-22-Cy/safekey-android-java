package com.safekey.app;

import com.safekey.app.security.panic.PanicRuntimeScope;

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

public final class SafeKeyApplication extends Application implements PanicRuntimeScope.Owner {

    private volatile PanicRuntimeScope panicRuntimeScope = new PanicRuntimeScope();
    private com.safekey.app.security.panic.PanicStartupGate startupGate;
    private boolean startupNavigationRequired;
    private boolean runtimeInitializationAttempted;

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
    private com.safekey.app.security.panic.PanicBackend panicBackend;

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
        registerSessionCleanup();
        registerPanicScreenCancellation();
        beginStartup();
    }

    private void beginStartup() {
        startupGate = new com.safekey.app.security.panic.PanicStartupGate(
                new com.safekey.app.security.panic.PanicStartupGate.Recovery() {
                    @Override public boolean isPending() throws Exception {
                        return new com.safekey.app.security.panic.PanicWipeJournal(
                                SafeKeyApplication.this).isPending();
                    }
                    @Override public void recover() throws Exception {
                        com.safekey.app.security.panic.PanicWipeJournal journal =
                                new com.safekey.app.security.panic.PanicWipeJournal(SafeKeyApplication.this);
                        com.safekey.app.security.panic.PanicWipeCoordinator wipe =
                                new com.safekey.app.security.panic.PanicWipeCoordinator(
                                        panicRuntimeScope.getWorkGate(), journal,
                                        getPanicShutdownRuntime(),
                                        com.safekey.app.security.panic.PanicWipeTargets.forSafeKey(
                                                SafeKeyApplication.this));
                        if (!wipe.resumeIfPending()) {
                            throw new java.io.IOException("Pending cleanup authorization is missing.");
                        }
                    }
                }, new com.safekey.app.security.panic.PanicStartupGate.Runtime() {
                    @Override public void block() { panicRuntimeScope.getWorkGate().blockNewWork(); }
                    @Override public void initialize(boolean recovered) { initializeVaultRuntime(recovered); }
                }, action -> new Thread(action, "safekey-panic-startup").start(), action -> {
                    if (!mainHandler.post(action)) {
                        throw new IllegalStateException("Startup UI dispatcher is unavailable.");
                    }
                });
        startupGate.start();
    }

    private void initializeVaultRuntime(boolean recovered) {
        runtimeInitializationAttempted = true;
        if (recovered || panicRuntimeScope.isStopped()) {
            // Every object from the stopped scope remains permanently stopped.
            panicRuntimeScope = new PanicRuntimeScope();
            startupNavigationRequired = true;
        }
        DecoyVaultStorage.ensureDatabaseFile(this);
        secureVaultCoordinator = new SecureVaultCoordinator(this);
        decoyVaultCoordinator = new DecoyVaultCoordinator(this);
        realVaultOperations = new RealVaultOperations(secureVaultCoordinator);
        masterPasswordHealth = new MasterPasswordHealth(this);
        panicBackend = new com.safekey.app.security.panic.PanicBackend(
                this, secureVaultCoordinator, decoyVaultCoordinator, getPanicShutdownRuntime());
        synchronized (this) {
            activeVault = ActiveVault.NONE;
            activeVaultOperations = null;
            sessionGeneration++;
            cleanupGeneration++;
            cleanupInProgress = false;
            cleanupFailed = false;
            pendingCloses = 0;
            authenticationWaiters.clear();
        }
    }

    public com.safekey.app.security.panic.PanicStartupGate getStartupGate() { return startupGate; }

    public boolean isStartupRuntimeAvailable() {
        return startupGate != null
                && startupGate.getState() == com.safekey.app.security.panic.PanicStartupGate.State.READY
                && !panicRuntimeScope.isStopped();
    }

    public boolean canCreateRuntimeScreen() {
        return isStartupRuntimeAvailable() && !startupNavigationRequired;
    }

    public boolean canRetryStartupRecovery() {
        return startupGate != null
                && startupGate.getState() == com.safekey.app.security.panic.PanicStartupGate.State.FAILED
                && !runtimeInitializationAttempted;
    }

    public void retryStartupRecovery() {
        if (Looper.myLooper() != Looper.getMainLooper() || !canRetryStartupRecovery()) {
            throw new IllegalStateException("Startup recovery cannot be retried here.");
        }
        beginStartup();
    }

    public void completeStartupNavigation() {
        requireRuntimeReady();
        startupNavigationRequired = false;
    }

    private void requireRuntimeReady() {
        if (!isStartupRuntimeAvailable()) {
            throw new IllegalStateException("SafeKey startup has not completed.");
        }
    }

    public com.safekey.app.security.panic.PanicBackend getPanicBackend() {
        requireRuntimeReady();
        return panicBackend;
    }

    /** Hind's Sign In controller calls this on main after PANIC_WIPED, before fresh-setup navigation. */
    public void continueAfterPanicWipe(com.safekey.app.security.panic.PanicBackend completedBackend) {
        if (Looper.myLooper() != Looper.getMainLooper()
                || completedBackend == null || completedBackend != panicBackend
                || !completedBackend.wasWipeCompleted()
                || !panicRuntimeScope.isStopped() || !panicRuntimeScope.areResourcesClosed()) {
            throw new IllegalStateException("A completed Panic wipe is required before restarting setup.");
        }
        beginStartup();
    }

    public MasterPasswordHealth getMasterPasswordHealth() {
        requireRuntimeReady();
        return masterPasswordHealth;
    }

    public SecureVaultCoordinator getSecureVaultCoordinator() {
        requireRuntimeReady();
        return secureVaultCoordinator;
    }

    public DecoyVaultCoordinator getDecoyVaultCoordinator() {
        requireRuntimeReady();
        return decoyVaultCoordinator;
    }

    public ActiveVault getActiveVault() {
        if (!isStartupRuntimeAvailable() || SafeKeySession.getState() != SessionState.UNLOCKED) {
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
        if (!isStartupRuntimeAvailable() || SafeKeySession.getState() != SessionState.UNLOCKED) {
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
        if (!isStartupRuntimeAvailable() || SafeKeySession.getState() != SessionState.UNLOCKED) {
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
        return isStartupRuntimeAvailable()
                && !cleanupInProgress
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
        if (!isStartupRuntimeAvailable() || SafeKeySession.getState() != SessionState.UNLOCKED) {
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
        if (!isStartupRuntimeAvailable()) {
            deliverError(callback, new IllegalStateException("Vault runtime is unavailable."));
            return;
        }

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
     * Explicitly cleans up a canceled authentication attempt.
     *
     * The session may already be locked during Sign In, so a normal
     * SafeKeySession.lock() call would not trigger vault cleanup.
     *
     * The application coordinates closing both vaults and invalidating
     * pending operations before another authentication can proceed.
     */
    public void cancelPendingVaultAuthentication() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException(
                    "Authentication cancellation must run on the main thread."
            );
        }

        if (!isStartupRuntimeAvailable()
                || panicRuntimeScope.isStopped()) {
            return;
        }

        if (SafeKeySession.getState() != SessionState.LOCKED) {
            throw new IllegalStateException(
                    "Authentication cancellation requires a locked session."
            );
        }

        synchronized (this) {
            if (cleanupInProgress) {
                return;
            }
        }

        clearSessionAndCloseVaults();
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
        if (!isStartupRuntimeAvailable()) {
            synchronized (this) {
                activeVault = ActiveVault.NONE;
                activeVaultOperations = null;
                sessionGeneration++;
                cleanupGeneration++;
                cleanupInProgress = false;
                cleanupFailed = true;
                pendingCloses = 0;
                authenticationWaiters.clear();
            }
            if (masterPasswordHealth != null) { masterPasswordHealth.cancelRecheck(); }
            return;
        }


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
                                        && isStartupRuntimeAvailable()
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

    @Override public PanicRuntimeScope getPanicRuntimeScope() { return panicRuntimeScope; }

    /** Terminal shutdown adapter, also valid before cold-start vault initialization. */
    public com.safekey.app.security.panic.PanicWipeCoordinator.Runtime getPanicShutdownRuntime() {
        return new com.safekey.app.security.panic.PanicAndroidRuntime(
                panicRuntimeScope, mainHandler, () -> {
                    SafeKeySession.lock();
                    // Also invalidate readiness when the session was already locked.
                    clearSessionAndCloseVaults();
                });
    }

    private void registerPanicScreenCancellation() {
        java.util.Map<android.app.Activity, PanicRuntimeScope.Registration> screens =
                new java.util.IdentityHashMap<>();
        registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(android.app.Activity activity, android.os.Bundle state) {
                if (activity instanceof PanicStartupActivity || !canCreateRuntimeScreen()) { return; }
                screens.put(activity, com.safekey.app.security.panic.PanicSensitiveUi.bind(activity, () -> {}));
            }
            @Override public void onActivityDestroyed(android.app.Activity activity) {
                PanicRuntimeScope.Registration registration = screens.remove(activity);
                if (registration != null) { registration.close(); }
            }
            @Override public void onActivityStarted(android.app.Activity activity) { }
            @Override public void onActivityResumed(android.app.Activity activity) { }
            @Override public void onActivityPaused(android.app.Activity activity) { }
            @Override public void onActivityStopped(android.app.Activity activity) { }
            @Override public void onActivitySaveInstanceState(android.app.Activity activity, android.os.Bundle state) { }
        });
    }

}

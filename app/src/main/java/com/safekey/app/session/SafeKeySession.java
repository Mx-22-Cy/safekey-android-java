package com.safekey.app.session;

import android.os.SystemClock;

import com.safekey.app.session.logic.SessionState;
import com.safekey.app.session.logic.VaultSessionManager;

import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * Android-side holder for the shared vault session state.
 *
 * <p>The shared session intentionally starts in the LOCKED state.
 * Production code must call unlockAfterAuthentication() only after
 * authentication succeeds and the required vault key material is
 * available.</p>
 *
 * <p>A sensitive-data cleanup action may be registered by the
 * authentication/storage integration. The action runs whenever the
 * session changes from UNLOCKED to LOCKED.</p>
 */
public final class SafeKeySession {

    private static final Runnable NO_OP_CLEANUP =
            () -> {
                // No sensitive resources are currently registered.
            };

    private static Runnable sensitiveDataCleanup =
            NO_OP_CLEANUP;

    private static final LongSupplier SYSTEM_CLOCK =
            SystemClock::elapsedRealtime;

    private static volatile LongSupplier monotonicTimeMillis =
            SYSTEM_CLOCK;
    private static final VaultSessionManager SESSION_MANAGER =
            new VaultSessionManager(
                    () -> monotonicTimeMillis.getAsLong(),
                    SafeKeySession::clearSensitiveData
            );

    private SafeKeySession() {
        // Utility holder.
    }

    public static VaultSessionManager getManager() {
        return SESSION_MANAGER;
    }

    public static SessionState getState() {
        return SESSION_MANAGER.getState();
    }

    public static boolean recordActivity() {
        return SESSION_MANAGER.recordActivity();
    }

    public static void unlockAfterAuthentication() {
        SESSION_MANAGER.unlockAfterAuthentication();
    }

    public static void lock() {
        SESSION_MANAGER.lock();
    }

    public static synchronized void registerSensitiveDataCleanup(
            Runnable cleanup
    ) {
        sensitiveDataCleanup =
                Objects.requireNonNull(
                        cleanup,
                        "cleanup"
                );
    }

    public static synchronized void unregisterSensitiveDataCleanup() {
        sensitiveDataCleanup =
                NO_OP_CLEANUP;
    }

    static void setClockForTesting(LongSupplier clock) {
        monotonicTimeMillis =
                Objects.requireNonNull(clock, "clock");
    }

    static void resetClockForTesting() {
        monotonicTimeMillis = SYSTEM_CLOCK;
    }
    private static void clearSensitiveData() {
        Runnable cleanup;

        synchronized (SafeKeySession.class) {
            cleanup =
                    sensitiveDataCleanup;
        }

        cleanup.run();
    }
}

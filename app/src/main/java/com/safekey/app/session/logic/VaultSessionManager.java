package com.safekey.app.session.logic;

import java.util.Objects;
import java.util.function.LongSupplier;

public final class VaultSessionManager {

    public static final long DEFAULT_INACTIVITY_TIMEOUT_MILLIS =
            5 * 60 * 1000L;

    private final LongSupplier monotonicTimeMillis;
    private final long inactivityTimeoutMillis;
    private final SessionLockHandler lockHandler;

    private SessionState state =
            SessionState.LOCKED;

    private long authenticationGeneration;

    private long lastActivityMillis =
            -1L;

    public VaultSessionManager(
            LongSupplier monotonicTimeMillis,
            SessionLockHandler lockHandler
    ) {
        this(
                monotonicTimeMillis,
                DEFAULT_INACTIVITY_TIMEOUT_MILLIS,
                lockHandler
        );
    }

    public VaultSessionManager(
            LongSupplier monotonicTimeMillis,
            long inactivityTimeoutMillis,
            SessionLockHandler lockHandler
    ) {
        this.monotonicTimeMillis =
                Objects.requireNonNull(
                        monotonicTimeMillis,
                        "monotonicTimeMillis"
                );

        this.lockHandler =
                Objects.requireNonNull(
                        lockHandler,
                        "lockHandler"
                );

        if (inactivityTimeoutMillis <= 0L) {
            throw new IllegalArgumentException(
                    "inactivityTimeoutMillis must be greater than zero"
            );
        }

        this.inactivityTimeoutMillis =
                inactivityTimeoutMillis;
    }

    public synchronized void unlockAfterAuthentication() {
        authenticationGeneration++;
        state =
                SessionState.UNLOCKED;

        lastActivityMillis =
                monotonicTimeMillis.getAsLong();
    }

    /** Returns -1 for a locked/expired session; each authentication is distinct. */
    public synchronized long getAuthenticationGeneration() {
        return getState() == SessionState.UNLOCKED ? authenticationGeneration : -1L;
    }

    /** Atomically guards a short commit against lock, expiry, and reauthentication. */
    public synchronized boolean runIfCurrentAuthentication(long generation, Runnable action) {
        Objects.requireNonNull(action, "action");
        if (generation < 0L || getAuthenticationGeneration() != generation) {
            return false;
        }
        action.run();
        return true;
    }

    /** Guard a short commit without evaluating timeout or invoking cleanup. */
    public synchronized boolean runWhileLocked(Runnable action) {
        Objects.requireNonNull(action, "action");
        if (state != SessionState.LOCKED) {
            return false;
        }
        action.run();
        return true;
    }

    public synchronized SessionState getState() {
        if (state == SessionState.UNLOCKED) {
            lockIfTimedOut(
                    monotonicTimeMillis.getAsLong()
            );
        }

        return state;
    }

    public synchronized boolean recordActivity() {
        if (state != SessionState.UNLOCKED) {
            return false;
        }

        long nowMillis =
                monotonicTimeMillis.getAsLong();

        lockIfTimedOut(nowMillis);

        if (state != SessionState.UNLOCKED) {
            return false;
        }

        lastActivityMillis =
                nowMillis;

        return true;
    }

    public synchronized long getRemainingInactivityMillis() {
        if (state != SessionState.UNLOCKED) {
            return 0L;
        }

        long nowMillis =
                monotonicTimeMillis.getAsLong();

        lockIfTimedOut(
                nowMillis
        );

        if (state != SessionState.UNLOCKED) {
            return 0L;
        }

        return inactivityTimeoutMillis
                - (nowMillis - lastActivityMillis);
    }

    public synchronized void lock() {
        transitionToLocked();
    }

    private void lockIfTimedOut(
            long nowMillis
    ) {
        long elapsedMillis =
                nowMillis - lastActivityMillis;

        if (elapsedMillis < 0L
                || elapsedMillis >= inactivityTimeoutMillis) {
            transitionToLocked();
        }
    }

    private void transitionToLocked() {
        if (state == SessionState.LOCKED) {
            return;
        }

        state =
                SessionState.LOCKED;

        lastActivityMillis =
                -1L;

        lockHandler.onSessionLocked();
    }
}

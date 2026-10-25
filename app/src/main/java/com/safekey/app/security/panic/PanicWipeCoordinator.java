package com.safekey.app.security.panic;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Synchronous backend: call from a dedicated worker, never Android's main
 * thread. Application startup must recover a pending wipe before creating
 * vaults, opening storage or delivering an authentication success.
 */
public final class PanicWipeCoordinator {
    public interface Journal {
        boolean isPending() throws Exception;
        void markPending() throws Exception;
        void clearPending() throws Exception;
    }

    public interface Runtime {
        /** Invalidate authentication/session claims and clear displayed data. */
        void lockAndClearSession() throws Exception;

        /**
         * Cancel pending work, clear in-memory keys and synchronously close all
         * connections. Returning after merely QUEUING close is insufficient.
         */
        void closeResources() throws Exception;
        boolean areResourcesClosed() throws Exception;
    }

    public interface Target {
        String name();
        void erase() throws Exception;
        void verifyAbsent() throws Exception;
    }

    private final PanicWorkGate gate;
    private final Journal journal;
    private final Runtime runtime;
    private final List<Target> targets;
    private final long drainTimeoutMillis;

    public PanicWipeCoordinator(PanicWorkGate gate, Journal journal,
                                Runtime runtime, List<Target> targets) {
        this(gate, journal, runtime, targets, 30_000L);
    }

    PanicWipeCoordinator(PanicWorkGate gate, Journal journal,
                         Runtime runtime, List<Target> targets,
                         long drainTimeoutMillis) {
        this.gate = Objects.requireNonNull(gate, "gate");
        this.journal = Objects.requireNonNull(journal, "journal");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        if (targets == null || targets.isEmpty() || drainTimeoutMillis <= 0) {
            throw new IllegalArgumentException("A complete wipe plan is required.");
        }
        ArrayList<Target> copy = new ArrayList<>(targets);
        for (Target target : copy) {
            Objects.requireNonNull(target, "target");
        }
        this.targets = Collections.unmodifiableList(copy);
        this.drainTimeoutMillis = drainTimeoutMillis;
    }

    public synchronized boolean isRecoveryRequired() throws Exception {
        try {
            boolean pending = journal.isPending();
            if (pending) { gate.blockNewWork(); }
            return pending;
        } catch (Exception error) {
            gate.blockNewWork();
            try {
                runtime.lockAndClearSession();
            } catch (Exception lockError) {
                error.addSuppressed(lockError);
            }
            throw error;
        }
    }

    boolean usesGate(PanicWorkGate supplied) { return gate == supplied; }

    /** A durable previous trigger is authorization to finish after restart. */
    public synchronized boolean resumeIfPending() throws Exception {
        if (!isRecoveryRequired()) {
            return false;
        }
        wipe();
        return true;
    }

    /** Destructive primitive: call only after a verified Panic trigger. */
    public synchronized void wipe() throws Exception {
        gate.blockNewWork();

        // Arm recovery before any deletion. If arming fails, storage is kept.
        // Still attempt to lock the session even when writing the marker fails.
        Exception preparationError = null;
        try {
            runtime.lockAndClearSession();
        } catch (Exception error) {
            preparationError = error;
        }
        try {
            journal.markPending();
            if (!journal.isPending()) {
                throw new IOException("Panic recovery marker was not saved.");
            }
        } catch (Exception error) {
            if (preparationError != null) {
                error.addSuppressed(preparationError);
            }
            throw error;
        }
        if (preparationError != null) {
            throw preparationError;
        }

        try {
            gate.awaitIdle(drainTimeoutMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        }
        runtime.closeResources();
        if (!runtime.areResourcesClosed()) {
            throw new IOException("Vault connections are still open.");
        }

        IOException failure = new IOException("Panic cleanup is incomplete.");
        for (Target target : targets) {
            try {
                target.erase();
            } catch (Exception error) {
                failure.addSuppressed(targetFailure(target, "erase", error));
            }
        }
        // A successful delete return value is not proof of complete cleanup.
        for (Target target : targets) {
            try {
                target.verifyAbsent();
            } catch (Exception error) {
                failure.addSuppressed(targetFailure(target, "verify", error));
            }
        }
        if (failure.getSuppressed().length != 0) {
            throw failure;
        }
        journal.clearPending();
        if (journal.isPending()) {
            throw new IOException("Panic recovery marker could not be cleared.");
        }
        // Never reactivate an old runtime or accept its queued callbacks.
    }

    private static IOException targetFailure(Target target, String stage,
                                             Exception cause) {
        return new IOException("Panic " + stage + " failed: " + target.name(), cause);
    }
}

package com.safekey.app.security.panic;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.LongSupplier;

/** Role separation only. Existing coordinator/session authorization is still required. */
public final class PanicPasswordSeparation {
    public enum Role { MASTER, DECOY, PANIC }

    private final PanicWorkGate gate;
    private final PanicSignInService.Credentials credentials;
    private final LongSupplier elapsedMillis;
    private final long lifetimeMillis;

    PanicPasswordSeparation(PanicWorkGate gate, PanicSignInService.Credentials credentials,
                            LongSupplier elapsedMillis, long lifetimeMillis) {
        this.gate = Objects.requireNonNull(gate, "gate");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.elapsedMillis = Objects.requireNonNull(elapsedMillis, "elapsedMillis");
        if (lifetimeMillis <= 0) { throw new IllegalArgumentException("Invalid separation permit lifetime."); }
        this.lifetimeMillis = lifetimeMillis;
    }

    /** Perform KDF work off main; the returned permit contains no plaintext password or key. */
    public Permit prepare(Role proposedRole, char[] candidate) throws Exception {
        Objects.requireNonNull(proposedRole, "proposedRole");
        try (PanicWorkGate.Operation operation = gate.begin()) {
            char[] copy = candidate == null ? null : candidate.clone();
            try {
                if (copy == null || copy.length == 0
                        || copy.length > com.safekey.app.auth.logic.MasterPasswordPolicy.MAX_LENGTH * 2) {
                    throw new IllegalArgumentException("Invalid proposed password length.");
                }
                long started = elapsedMillis.getAsLong();
                PanicSignInService.Snapshot snapshot = credentials.capture();
                boolean[] matches = new boolean[3];
                GeneralSecurityException failure = new GeneralSecurityException("Unable to check password separation.");
                try { matches[0] = snapshot.matchesMaster(copy); } catch (Exception error) { failure.addSuppressed(error); }
                try { matches[1] = snapshot.matchesDecoy(copy); } catch (Exception error) { failure.addSuppressed(error); }
                try { matches[2] = snapshot.matchesPanic(copy); } catch (Exception error) { failure.addSuppressed(error); }
                if (failure.getSuppressed().length != 0) { throw failure; }
                int own = proposedRole.ordinal();
                for (int i = 0; i < matches.length; i++) {
                    if (i != own && matches[i]) {
                        throw new IllegalArgumentException("Choose a password different from the other vault password roles.");
                    }
                }
                if (!operation.ticket().isCurrent()) { throw stale(); }
                return new Permit(operation.ticket(), snapshot, started);
            } finally { if (copy != null) { Arrays.fill(copy, '\0'); } }
        }
    }

    /** Single-use generation guard. The protected action must perform the actual synchronous save. */
    public final class Permit implements AutoCloseable {
        private final PanicWorkGate.Ticket ticket;
        private final PanicSignInService.Snapshot snapshot;
        private final long started;
        private boolean used;
        private boolean closed;

        private Permit(PanicWorkGate.Ticket ticket, PanicSignInService.Snapshot snapshot, long started) {
            this.ticket = ticket; this.snapshot = snapshot; this.started = started;
        }

        /** No password work here. Serializes the final configuration check and save under one lock. */
        public void commit(Runnable action) {
            Objects.requireNonNull(action, "action");
            synchronized (this) {
                requireCurrent();
                if (used) { throw stale(); }
                used = true;
            }
            try {
                // Do not hold a permit monitor while waiting for the shared configuration lock.
                snapshot.commitIfCurrent(() -> {
                    synchronized (Permit.this) { requireCurrent(); action.run(); }
                });
            } catch (RuntimeException error) { throw error; }
            catch (Exception error) { throw new IllegalStateException("Password configuration is unavailable.", error); }
        }

        private void requireCurrent() {
            long age = elapsedMillis.getAsLong() - started;
            if (closed || !ticket.isCurrent() || age < 0L || age >= lifetimeMillis) { throw stale(); }
        }

        @Override public synchronized void close() { closed = true; }
    }

    private static CancellationException stale() {
        return new CancellationException("Password configuration changed. Check the proposed password again.");
    }
}

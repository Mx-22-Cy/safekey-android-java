package com.safekey.app.security.panic;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.LongSupplier;

/** Single-use authorization; the Android adapter supplies actual session/credential proof. */
public final class PanicEnrollmentAuthority implements PanicPasswordService.EnrollmentAuthority {
    interface SessionProof { void commitIfCurrent(PanicPasswordService.Commit action) throws Exception; }
    interface Sessions { SessionProof capture() throws Exception; }
    interface CredentialProof {
        boolean matchesMaster(char[] password) throws Exception;
        boolean matchesDecoy(char[] password) throws Exception;
        void commitIfCurrent(PanicPasswordService.Commit action) throws Exception;
    }
    interface Credentials { CredentialProof capture() throws Exception; }

    private final PanicWorkGate gate;
    private final Sessions sessions;
    private final Credentials credentials;
    private final LongSupplier elapsedMillis;
    private final long lifetimeMillis;

    PanicEnrollmentAuthority(PanicWorkGate gate, Sessions sessions, Credentials credentials,
                             LongSupplier elapsedMillis, long lifetimeMillis) {
        this.gate = Objects.requireNonNull(gate, "gate");
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.elapsedMillis = Objects.requireNonNull(elapsedMillis, "elapsedMillis");
        if (lifetimeMillis <= 0) { throw new IllegalArgumentException("Invalid grant lifetime."); }
        this.lifetimeMillis = lifetimeMillis;
    }

    @Override public PanicPasswordService.Grant authenticate(char[] master, char[] decoy) throws Exception {
        char[] masterCopy = null;
        char[] decoyCopy = null;
        try (PanicWorkGate.Operation operation = gate.begin()) {
            try {
                long started = elapsedMillis.getAsLong();
                masterCopy = Objects.requireNonNull(master, "master").clone();
                decoyCopy = Objects.requireNonNull(decoy, "decoy").clone();
                SessionProof session = sessions.capture();
                CredentialProof proof = credentials.capture();
                boolean masterMatches = proof.matchesMaster(masterCopy);
                boolean decoyMatches = proof.matchesDecoy(decoyCopy);
                if (!masterMatches || !decoyMatches) {
                    throw new GeneralSecurityException("Unable to authorize Panic enrollment.");
                }
                if (!operation.ticket().isCurrent()) { throw stale(); }
                return new Grant(operation.ticket(), session, proof, started);
            } finally {
                if (masterCopy != null) { Arrays.fill(masterCopy, '\0'); }
                if (decoyCopy != null) { Arrays.fill(decoyCopy, '\0'); }
            }
        }
    }

    private final class Grant implements PanicPasswordService.Grant {
        private final PanicWorkGate.Ticket ticket;
        private final SessionProof session;
        private final CredentialProof proof;
        private final long started;
        private boolean used;
        private boolean closed;

        Grant(PanicWorkGate.Ticket ticket, SessionProof session, CredentialProof proof, long started) {
            this.ticket = ticket; this.session = session; this.proof = proof; this.started = started;
        }

        @Override public void commitIfCurrent(PanicPasswordService.Commit commit) throws Exception {
            Objects.requireNonNull(commit, "commit");
            synchronized (this) {
                requireCurrent();
                if (used) { throw stale(); }
                used = true;
            }
            // No grant or persistence monitor is held while waiting for the UI dispatcher.
            session.commitIfCurrent(() -> proof.commitIfCurrent(() -> {
                synchronized (Grant.this) {
                    requireCurrent();
                    commit.run();
                }
            }));
        }

        private void requireCurrent() {
            long age = elapsedMillis.getAsLong() - started;
            if (closed || !ticket.isCurrent() || age < 0 || age >= lifetimeMillis) { throw stale(); }
        }

        @Override public synchronized void close() { closed = true; }
    }

    private static CancellationException stale() {
        return new CancellationException("Panic enrollment authorization expired.");
    }
}

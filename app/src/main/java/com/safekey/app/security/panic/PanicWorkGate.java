package com.safekey.app.security.panic;

import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * One gate per vault runtime. Every task that can open a database, write an
 * envelope, enroll biometrics/TOTP or retain key material must own an Operation
 * until its background work finishes. A queued callback keeps a Ticket.
 *
 * Blocking is permanent for this runtime. A fresh runtime may be constructed
 * only after pending wipe recovery has completed. This gate does not replace
 * the application's atomic, generation-bound session claim.
 */
public final class PanicWorkGate {
    private boolean blocked;
    private long generation;
    private int activeOperations;

    public synchronized Operation begin() {
        if (blocked) {
            throw new CancellationException("Vault runtime is stopped.");
        }
        activeOperations++;
        return new Operation(this, new Ticket(this, generation));
    }

    public synchronized void blockNewWork() {
        if (!blocked) {
            blocked = true;
            generation++;
        }
    }

    public synchronized boolean isBlocked() {
        return blocked;
    }

    /** Background-thread barrier. Never delete storage if this fails. */
    public synchronized void awaitIdle(long timeout, TimeUnit unit)
            throws InterruptedException, TimeoutException {
        Objects.requireNonNull(unit, "unit");
        if (!blocked || timeout <= 0) {
            throw new IllegalStateException("Block work before waiting.");
        }
        long remaining = unit.toNanos(timeout);
        long started = System.nanoTime();
        while (activeOperations != 0) {
            if (remaining <= 0) {
                throw new TimeoutException("Vault work did not stop.");
            }
            TimeUnit.NANOSECONDS.timedWait(this, remaining);
            remaining = unit.toNanos(timeout) - (System.nanoTime() - started);
        }
    }

    private synchronized boolean isCurrent(long ticketGeneration) {
        return !blocked && generation == ticketGeneration;
    }

    public static final class Ticket {
        private final PanicWorkGate gate;
        private final long generation;

        private Ticket(PanicWorkGate gate, long generation) {
            this.gate = gate;
            this.generation = generation;
        }

        /** Preflight for queued callbacks, not an atomic session claim. */
        public boolean isCurrent() {
            return gate.isCurrent(generation);
        }
    }

    public static final class Operation implements AutoCloseable {
        private final PanicWorkGate gate;
        private final Ticket ticket;
        private boolean closed;

        private Operation(PanicWorkGate gate, Ticket ticket) {
            this.gate = gate;
            this.ticket = ticket;
        }

        public Ticket ticket() {
            return ticket;
        }

        @Override
        public void close() {
            synchronized (gate) {
                if (!closed) {
                    closed = true;
                    gate.activeOperations--;
                    gate.notifyAll();
                }
            }
        }
    }
}

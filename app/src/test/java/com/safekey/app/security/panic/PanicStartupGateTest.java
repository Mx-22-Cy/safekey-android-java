package com.safekey.app.security.panic;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

import static org.junit.Assert.*;

public class PanicStartupGateTest {
    private static final class Queue implements Executor {
        final ArrayDeque<Runnable> work = new ArrayDeque<>();
        @Override public void execute(Runnable action) { work.add(action); }
        void runNext() { work.remove().run(); }
    }

    private static final class Fixture implements PanicStartupGate.Recovery, PanicStartupGate.Runtime {
        final Queue worker = new Queue();
        final Queue main = new Queue();
        final PanicStartupGate gate = new PanicStartupGate(this, this, worker, main);
        boolean pending;
        boolean blocked;
        boolean initialized;
        boolean initializedAfterRecovery;
        boolean leaveMarker;
        int probes;
        int cleanups;
        IOException probeFailure;
        IOException cleanupFailure;
        IOException initializationFailure;

        @Override public boolean isPending() throws IOException {
            probes++;
            if (probeFailure != null) { throw probeFailure; }
            return pending;
        }
        @Override public void recover() throws IOException {
            assertTrue(blocked);
            assertFalse(initialized);
            cleanups++;
            if (cleanupFailure != null) { throw cleanupFailure; }
            if (!leaveMarker) { pending = false; }
        }
        @Override public void block() { blocked = true; }
        @Override public void initialize(boolean recovered) throws IOException {
            assertFalse(pending);
            if (initializationFailure != null) { throw initializationFailure; }
            initialized = true;
            initializedAfterRecovery = recovered;
        }
    }

    @Test public void missingMarkerInitializesWithoutRunningCleanup() {
        Fixture f = new Fixture();
        f.gate.start();
        assertEquals(PanicStartupGate.State.READY, f.gate.getState());
        assertTrue(f.initialized);
        assertFalse(f.blocked);
        assertFalse(f.gate.wasRecovered());
        assertEquals(0, f.cleanups);
        assertTrue(f.worker.work.isEmpty());
    }

    @Test public void pendingMarkerBlocksUntilCleanupAndUiInitializationComplete() {
        Fixture f = new Fixture(); f.pending = true;
        f.gate.start();
        assertEquals(PanicStartupGate.State.RECOVERING, f.gate.getState());
        assertTrue(f.blocked);
        assertFalse(f.initialized);
        f.worker.runNext();
        assertEquals(PanicStartupGate.State.RECOVERING, f.gate.getState());
        assertFalse(f.initialized);
        f.main.runNext();
        assertEquals(PanicStartupGate.State.READY, f.gate.getState());
        assertTrue(f.initializedAfterRecovery);
        assertTrue(f.gate.wasRecovered());
        assertEquals(1, f.cleanups);
    }

    @Test public void unreadableMarkerDoesNotAuthorizeCleanupOrInitialization() {
        Fixture f = new Fixture(); f.probeFailure = new IOException("probe");
        f.gate.start();
        assertEquals(PanicStartupGate.State.FAILED, f.gate.getState());
        assertTrue(f.blocked);
        assertFalse(f.initialized);
        assertEquals(0, f.cleanups);
        assertSame(f.probeFailure, f.gate.getFailure());
    }

    @Test public void failedCleanupRetainsBlockedStateAndDoesNotInitialize() {
        Fixture f = new Fixture(); f.pending = true; f.cleanupFailure = new IOException("cleanup");
        f.gate.start(); f.worker.runNext(); f.main.runNext();
        assertEquals(PanicStartupGate.State.FAILED, f.gate.getState());
        assertTrue(f.pending);
        assertTrue(f.blocked);
        assertFalse(f.initialized);
        assertSame(f.cleanupFailure, f.gate.getFailure());
    }

    @Test public void remainingMarkerPreventsInitializationEvenWhenRecoveryReturns() {
        Fixture f = new Fixture(); f.pending = true; f.leaveMarker = true;
        f.gate.start(); f.worker.runNext(); f.main.runNext();
        assertEquals(PanicStartupGate.State.FAILED, f.gate.getState());
        assertFalse(f.initialized);
        assertTrue(f.pending);
    }

    @Test public void failedFreshRuntimeInitializationNeverPublishesReadiness() {
        Fixture f = new Fixture(); f.pending = true; f.initializationFailure = new IOException("init");
        f.gate.start(); f.worker.runNext(); f.main.runNext();
        assertEquals(PanicStartupGate.State.FAILED, f.gate.getState());
        assertTrue(f.blocked);
        assertFalse(f.initialized);
        assertFalse(f.gate.wasRecovered());
    }

    @Test public void rejectedRecoveryWorkerLeavesInitializationUnavailable() {
        Fixture f = new Fixture(); f.pending = true;
        PanicStartupGate gate = new PanicStartupGate(f, f,
                action -> { throw new RejectedExecutionException("worker"); }, f.main);
        gate.start();
        assertEquals(PanicStartupGate.State.FAILED, gate.getState());
        assertTrue(f.pending);
        assertFalse(f.initialized);
    }

    @Test public void rejectedUiDispatchNeverInitializesOnTheWorker() {
        Fixture f = new Fixture(); f.pending = true;
        PanicStartupGate gate = new PanicStartupGate(f, f, f.worker,
                action -> { throw new RejectedExecutionException("main"); });
        gate.start(); f.worker.runNext();
        assertEquals(PanicStartupGate.State.FAILED, gate.getState());
        assertTrue(f.blocked);
        assertFalse(f.initialized);
    }

    @Test public void secondStartCannotInitializeOrRecoverAgain() {
        Fixture f = new Fixture(); f.gate.start();
        try { f.gate.start(); fail("Repeated startup accepted."); }
        catch (IllegalStateException expected) { }
        assertEquals(1, f.probes);
        assertEquals(PanicStartupGate.State.READY, f.gate.getState());
    }

    @Test public void removedAndFailingObserversCannotChangeStartupOutcome() throws Exception {
        Fixture f = new Fixture();
        int[] removed = {0};
        AutoCloseable observer = f.gate.observe(() -> removed[0]++);
        observer.close();
        f.gate.observe(() -> { throw new IllegalStateException("observer"); });
        f.gate.start();
        assertEquals(0, removed[0]);
        assertEquals(PanicStartupGate.State.READY, f.gate.getState());
    }
}

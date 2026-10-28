package com.safekey.app.security.panic;

import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static com.safekey.app.security.panic.PanicTestSupport.*;
import static org.junit.Assert.*;

public class PanicWipeCoordinatorTest {
    @Test public void successfulWipeLocksClosesErasesVerifiesThenClearsMarker() throws Exception {
        Fixture f = new Fixture();
        PanicWorkGate.Operation previous = f.gate.begin();
        PanicWorkGate.Ticket ticket = previous.ticket();
        previous.close();
        f.coordinator(1_000).wipe();
        assertEquals(Arrays.asList("lock", "mark", "close", "erase real", "erase decoy",
                "verify real", "verify decoy", "clear marker"), f.events);
        assertFalse(f.runtime.unlocked);
        assertFalse(f.real.present);
        assertFalse(f.decoy.present);
        assertFalse(f.journal.pending);
        assertFalse(ticket.isCurrent());
        expect(CancellationException.class, f.gate::begin);
    }

    @Test public void deleteFailureDoesNotSkipOtherTargetsAndCanBeResumed() throws Exception {
        Fixture f = new Fixture();
        f.real.failErase = true;
        IOException error = expect(IOException.class, () -> f.coordinator(1_000).wipe());
        assertEquals(2, error.getSuppressed().length);
        assertEquals(1, f.decoy.eraseCalls);
        assertEquals(1, f.real.verifyCalls);
        assertEquals(1, f.decoy.verifyCalls);
        assertFalse(f.decoy.present);
        assertTrue(f.journal.pending);
        f.real.failErase = false;
        assertTrue(f.coordinator(1_000).resumeIfPending());
        assertFalse(f.real.present);
        assertFalse(f.journal.pending);
    }

    @Test public void successfulDeleteReturnCannotHideRemainingArtifacts() throws Exception {
        Fixture f = new Fixture();
        f.real.leavePresent = true;
        expect(IOException.class, () -> f.coordinator(1_000).wipe());
        assertTrue(f.journal.pending);
        assertTrue(f.real.present);
        assertFalse(f.decoy.present);
    }

    @Test public void drainTimeoutKeepsFilesAndMarkerThenRetryFinishes() throws Exception {
        Fixture f = new Fixture();
        PanicWorkGate.Operation pending = f.gate.begin();
        try {
            expect(TimeoutException.class, () -> f.coordinator(5).wipe());
            assertTrue(f.real.present);
            assertTrue(f.decoy.present);
            assertTrue(f.journal.pending);
            assertFalse(f.runtime.closed);
            assertFalse(pending.ticket().isCurrent());
        } finally { pending.close(); }
        f.coordinator(1_000).resumeIfPending();
        assertFalse(f.real.present);
        assertFalse(f.journal.pending);
    }

    @Test public void enrollmentWriteAlreadyInFlightCannotRecreateStorageAfterWipe() throws Exception {
        Fixture f = new Fixture();
        PanicWorkGate.Operation pending = f.gate.begin();
        CountDownLatch markerWritten = new CountDownLatch(1);
        PanicWipeCoordinator.Journal journal = new PanicWipeCoordinator.Journal() {
            @Override public boolean isPending() { return f.journal.pending; }
            @Override public void markPending() throws Exception {
                f.journal.markPending(); markerWritten.countDown();
            }
            @Override public void clearPending() throws Exception { f.journal.clearPending(); }
        };
        PanicWipeCoordinator coordinator = new PanicWipeCoordinator(f.gate, journal, f.runtime,
                Arrays.asList(f.real, f.decoy), 5_000);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<?> wipe = executor.submit(() -> {
                try { coordinator.wipe(); } catch (Exception error) { throw new AssertionError(error); }
            });
            assertTrue(markerWritten.await(2, TimeUnit.SECONDS));
            assertFalse(wipe.isDone());
            // The accepted pre-wipe task still writes, but the barrier prevents
            // deletion until this operation releases its resources.
            f.real.present = true;
            f.decoy.present = true;
            pending.close();
            wipe.get(5, TimeUnit.SECONDS);
            assertFalse(f.real.present);
            assertFalse(f.decoy.present);
            assertFalse(pending.ticket().isCurrent());
            expect(CancellationException.class, f.gate::begin);
        } finally { pending.close(); executor.shutdownNow(); }
    }

    @Test public void failedConnectionClosePreventsDeletingOpenDatabases() throws Exception {
        Fixture f = new Fixture();
        f.runtime.failClose = true;
        expect(Exception.class, () -> f.coordinator(1_000).wipe());
        assertTrue(f.journal.pending);
        assertEquals(0, f.real.eraseCalls);
        f.runtime.failClose = false;
        assertTrue(f.coordinator(1_000).resumeIfPending());
    }

    @Test public void queuedCloseWithoutVerifiedClosureCannotStartDeleting() throws Exception {
        Fixture f = new Fixture();
        PanicWipeCoordinator.Runtime incompleteClose = new PanicWipeCoordinator.Runtime() {
            @Override public void lockAndClearSession() throws Exception { f.runtime.lockAndClearSession(); }
            @Override public void closeResources() { /* Merely queued by an invalid adapter. */ }
            @Override public boolean areResourcesClosed() { return false; }
        };
        PanicWipeCoordinator coordinator = new PanicWipeCoordinator(f.gate, f.journal,
                incompleteClose, Arrays.asList(f.real, f.decoy));
        expect(IOException.class, coordinator::wipe);
        assertTrue(f.journal.pending);
        assertEquals(0, f.real.eraseCalls);
        assertEquals(0, f.decoy.eraseCalls);
    }

    @Test public void failedSessionCleanupLeavesRecoveryArmed() throws Exception {
        Fixture f = new Fixture();
        f.runtime.failLock = true;
        expect(Exception.class, () -> f.coordinator(1_000).wipe());
        assertTrue(f.journal.pending);
        assertTrue(f.gate.isBlocked());
        assertEquals(0, f.real.eraseCalls);
    }

    @Test public void markerWriteFailureStillLocksButDoesNotStartDeletion() throws Exception {
        Fixture f = new Fixture();
        f.journal.failWrite = true;
        expect(Exception.class, () -> f.coordinator(1_000).wipe());
        assertFalse(f.runtime.unlocked);
        assertTrue(f.gate.isBlocked());
        assertEquals(0, f.real.eraseCalls);
        assertEquals(0, f.decoy.eraseCalls);
    }

    @Test public void unreadableMarkerBlocksStartupInsteadOfAllowingAuthentication() throws Exception {
        Fixture f = new Fixture();
        f.journal.failRead = true;
        expect(Exception.class, () -> f.coordinator(1_000).resumeIfPending());
        assertTrue(f.gate.isBlocked());
        assertFalse(f.runtime.unlocked);
        assertEquals(0, f.real.eraseCalls);
    }

    @Test public void noPendingWipeDoesNotTouchVaultOrSession() throws Exception {
        Fixture f = new Fixture();
        assertFalse(f.coordinator(1_000).resumeIfPending());
        assertTrue(f.runtime.unlocked);
        assertFalse(f.gate.isBlocked());
        assertTrue(f.events.isEmpty());
    }

    @Test public void markerClearFailureIsReportedAndRecoveryCanRetry() throws Exception {
        Fixture f = new Fixture();
        f.journal.failClear = true;
        expect(Exception.class, () -> f.coordinator(1_000).wipe());
        assertTrue(f.journal.pending);
        assertFalse(f.real.present);
        f.journal.failClear = false;
        assertTrue(f.coordinator(1_000).resumeIfPending());
        assertFalse(f.journal.pending);
    }

    @Test public void interruptionRetainsMarkerAndInterruptStatus() throws Exception {
        Fixture f = new Fixture();
        PanicWorkGate.Operation pending = f.gate.begin();
        try {
            Thread.currentThread().interrupt();
            expect(InterruptedException.class, () -> f.coordinator(1_000).wipe());
            assertTrue(Thread.currentThread().isInterrupted());
            assertTrue(f.journal.pending);
            assertEquals(0, f.real.eraseCalls);
        } finally { Thread.interrupted(); pending.close(); }
    }

    @Test public void repeatedOperationCloseCannotBypassAnotherPendingOperation() throws Exception {
        PanicWorkGate gate = new PanicWorkGate();
        PanicWorkGate.Operation first = gate.begin();
        PanicWorkGate.Operation second = gate.begin();
        first.close(); first.close();
        gate.blockNewWork();
        try {
            expect(TimeoutException.class, () -> gate.awaitIdle(5, TimeUnit.MILLISECONDS));
        } finally { second.close(); }
        gate.awaitIdle(1, TimeUnit.SECONDS);
    }
}

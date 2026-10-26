package com.safekey.app.security.panic;

import org.junit.Test;

import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.safekey.app.security.panic.PanicTestSupport.*;
import static org.junit.Assert.*;

public class PanicPasswordServiceTest {
    @Test public void verificationCopyIsClearedBeforeCleanupStarts() throws Exception {
        enroll();
        PanicWipeCoordinator.Runtime observed = new PanicWipeCoordinator.Runtime() {
            @Override public void lockAndClearSession() throws Exception {
                assertCleared(crypto.capturedPassword);
                f.runtime.lockAndClearSession();
            }
            @Override public void closeResources() throws Exception { f.runtime.closeResources(); }
            @Override public boolean areResourcesClosed() { return f.runtime.areResourcesClosed(); }
        };
        PanicWipeCoordinator wipe = new PanicWipeCoordinator(f.gate, f.journal, observed,
                Arrays.asList(f.real, f.decoy));
        PanicPasswordService checked = new PanicPasswordService(f.gate, store, crypto, wipe);
        assertTrue(checked.checkAndWipe(chars(PANIC)));
    }

    private final Fixture f = new Fixture();
    private final MemoryStore store = new MemoryStore();
    private final MemoryCrypto crypto = new MemoryCrypto();
    private final Authority authority = new Authority();
    private final PanicPasswordService service = new PanicPasswordService(f.gate, store, crypto,
            new PanicWipeCoordinator(f.gate, f.journal, f.runtime, Arrays.asList(f.real, f.decoy,
                    new PanicWipeCoordinator.Target() {
                        @Override public String name() { return "Panic proof"; }
                        @Override public void erase() { store.record = null; }
                        @Override public void verifyAbsent() { assertNull(store.record); }
                    })));

    @Test public void wrongPasswordDoesNotChangeVaultFilesSessionOrPanicProof() throws Exception {
        enroll();
        PanicPasswordCrypto.Record original = store.record;
        assertFalse(service.checkAndWipe(chars("A wrong candidate password")));
        assertTrue(store.record == original);
        assertTrue(f.runtime.unlocked);
        assertTrue(f.real.present);
        assertTrue(f.decoy.present);
        assertFalse(f.gate.isBlocked());
        assertFalse(f.journal.pending);
        assertCleared(crypto.capturedPassword);
    }

    @Test public void verifiedPanicPasswordWipesAndNeverCreatesUnlockedSession() throws Exception {
        enroll();
        assertTrue(service.checkAndWipe(chars(PANIC)));
        assertNull(store.record);
        assertFalse(f.real.present);
        assertFalse(f.decoy.present);
        assertFalse(f.runtime.unlocked);
        assertTrue(f.gate.isBlocked());
        assertFalse(f.journal.pending);
    }

    @Test public void missingPanicProofDoesNotWipe() throws Exception {
        assertFalse(service.checkAndWipe(chars(PANIC)));
        assertTrue(f.real.present);
        assertTrue(f.runtime.unlocked);
    }

    @Test public void roleCollisionCheckRecognizesPanicPasswordWithoutWiping() throws Exception {
        enroll();
        PanicPasswordCrypto.Record original = store.record;
        assertTrue(service.isReservedPassword(chars(PANIC)));
        assertFalse(service.isReservedPassword(chars(MASTER)));
        assertFalse(service.isReservedPassword(chars(DECOY)));
        assertTrue(store.record == original);
        assertTrue(f.runtime.unlocked);
        assertTrue(f.real.present);
        assertTrue(f.decoy.present);
        assertFalse(f.journal.pending);
        assertFalse(f.gate.isBlocked());
        assertCleared(crypto.capturedPassword);
    }

    @Test public void duplicateRolePasswordsCannotBeEnrolled() throws Exception {
        expect(IllegalArgumentException.class, () -> service.enroll(chars(MASTER), chars(MASTER),
                chars(PANIC), chars(PANIC), authority));
        assertEquals(0, store.saves);
        assertNull(authority.capturedMaster);
    }

    @Test public void wrongMasterOrDecoyReauthenticationCannotReplaceProof() throws Exception {
        enroll();
        PanicPasswordCrypto.Record original = store.record;
        expect(SecurityException.class, () -> service.enroll(chars("Incorrect master password"),
                chars(DECOY), chars(PANIC), chars(PANIC), authority));
        expect(SecurityException.class, () -> service.enroll(chars(MASTER),
                chars("Incorrect decoy password"), chars(PANIC), chars(PANIC), authority));
        assertTrue(original == store.record);
        assertEquals(1, store.saves);
    }

    @Test public void staleSessionDuringDerivationCannotSaveEnrollment() throws Exception {
        crypto.beforeCreate = () -> authority.generation++;
        expect(SecurityException.class, this::enroll);
        assertEquals(0, store.saves);
        assertTrue(authority.closed);
        assertCleared(crypto.capturedPassword);
    }

    @Test public void panicDuringDerivationPreventsLateProofPersistence() throws Exception {
        crypto.beforeCreate = f.gate::blockNewWork;
        expect(CancellationException.class, this::enroll);
        assertEquals(0, store.saves);
        assertTrue(authority.closed);
    }

    @Test public void temporaryCopiesAreClearedButCallerArraysAreUnchanged() throws Exception {
        char[] master = chars(MASTER);
        char[] decoy = chars(DECOY);
        char[] panic = chars(PANIC);
        char[] confirmation = chars(PANIC);
        service.enroll(master, decoy, panic, confirmation, authority);
        assertCleared(authority.capturedMaster);
        assertCleared(authority.capturedDecoy);
        assertCleared(crypto.capturedPassword);
        assertArrayEquals(chars(MASTER), master);
        assertArrayEquals(chars(DECOY), decoy);
        assertArrayEquals(chars(PANIC), panic);
        assertArrayEquals(chars(PANIC), confirmation);
        assertTrue(authority.closed);
    }

    @Test public void previouslyArmedWipeResumesWithoutReusingPasswordProof() throws Exception {
        enroll();
        f.journal.pending = true;
        assertTrue(service.checkAndWipe(chars("not the Panic password")));
        assertFalse(f.real.present);
        assertNull(store.record);
        assertFalse(f.journal.pending);
    }

    @Test public void unreadableProofCannotBeTreatedAsUnconfigured() throws Exception {
        store.unreadable = true;
        expect(Exception.class, () -> service.checkAndWipe(chars(PANIC)));
        assertTrue(f.real.present);
        assertTrue(f.decoy.present);
        assertFalse(f.journal.pending);
    }

    @Test public void concurrentWipeCancelsEnrollmentAndWaitsForItsWorker() throws Exception {
        CountDownLatch deriving = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch armed = new CountDownLatch(1);
        crypto.beforeCreate = () -> {
            deriving.countDown();
            if (!release.await(5, TimeUnit.SECONDS)) { throw new AssertionError("Derivation not released."); }
        };
        PanicWipeCoordinator.Journal observed = new PanicWipeCoordinator.Journal() {
            @Override public boolean isPending() { return f.journal.pending; }
            @Override public void markPending() throws Exception { f.journal.markPending(); armed.countDown(); }
            @Override public void clearPending() throws Exception { f.journal.clearPending(); }
        };
        PanicWipeCoordinator coordinator = new PanicWipeCoordinator(f.gate, observed, f.runtime,
                Arrays.asList(f.real, f.decoy), 5_000);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> enrollment = executor.submit(() -> {
                try { enroll(); } catch (Exception error) { throw new IllegalStateException(error); }
            });
            assertTrue(deriving.await(2, TimeUnit.SECONDS));
            Future<?> wipeResult = executor.submit(() -> {
                try { coordinator.wipe(); } catch (Exception error) { throw new AssertionError(error); }
            });
            assertTrue(armed.await(2, TimeUnit.SECONDS));
            assertFalse(wipeResult.isDone());
            release.countDown();
            ExecutionException failure = expect(ExecutionException.class,
                    () -> enrollment.get(5, TimeUnit.SECONDS));
            assertTrue(failure.getCause().getCause() instanceof CancellationException);
            wipeResult.get(5, TimeUnit.SECONDS);
            assertEquals(0, store.saves);
            assertFalse(f.real.present);
            assertFalse(f.decoy.present);
            assertFalse(f.journal.pending);
        } finally { release.countDown(); executor.shutdownNow(); }
    }

    private void enroll() throws Exception {
        service.enroll(chars(MASTER), chars(DECOY), chars(PANIC), chars(PANIC), authority);
    }
}

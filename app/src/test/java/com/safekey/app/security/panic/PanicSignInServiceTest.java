package com.safekey.app.security.panic;

import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.CancellationException;

import static org.junit.Assert.*;

public class PanicSignInServiceTest {
    private static final class Fixture {
        final PanicWorkGate gate = new PanicWorkGate();
        final boolean[] matches = new boolean[3];
        final int[] checks = new int[3];
        final Exception[] errors = new Exception[3];
        final Input input = new Input();
        long version;
        boolean pending;
        boolean resourcesClosed;
        boolean failErase;
        boolean failMarkerRead;
        boolean failMarkerWrite;
        int erases;
        Runnable afterCheck = () -> { };
        final PanicWipeCoordinator wipe = new PanicWipeCoordinator(gate,
                new PanicWipeCoordinator.Journal() {
                    @Override public boolean isPending() throws Exception {
                        if (failMarkerRead) { throw new IOException("Unreadable marker."); }
                        return pending;
                    }
                    @Override public void markPending() throws Exception {
                        if (failMarkerWrite) { throw new IOException("Marker write failed."); }
                        pending = true;
                    }
                    @Override public void clearPending() { pending = false; }
                }, new PanicWipeCoordinator.Runtime() {
                    @Override public void lockAndClearSession() { }
                    @Override public void closeResources() { resourcesClosed = true; }
                    @Override public boolean areResourcesClosed() { return resourcesClosed; }
                }, Collections.singletonList(new PanicWipeCoordinator.Target() {
                    @Override public String name() { return "isolated target"; }
                    @Override public void erase() throws Exception {
                        assertTrue(resourcesClosed); assertTrue(input.closed);
                        assertArrayEquals(new char[input.taken.length], input.taken);
                        assertAllChecks();
                        if (failErase) { throw new IOException("Delete failed."); }
                        erases++;
                    }
                    @Override public void verifyAbsent() throws Exception {
                        if (failErase) { throw new IOException("Target remains."); }
                    }
                }));
        final PanicSignInService service = new PanicSignInService(gate, () -> {
            long expected = version;
            return new PanicSignInService.Snapshot() {
                private boolean check(int role, char[] candidate) throws Exception {
                    assertTrue(candidate == input.taken);
                    checks[role]++; afterCheck.run();
                    if (errors[role] != null) { throw errors[role]; }
                    return matches[role];
                }
                @Override public boolean matchesMaster(char[] candidate) throws Exception { return check(0, candidate); }
                @Override public boolean matchesDecoy(char[] candidate) throws Exception { return check(1, candidate); }
                @Override public boolean matchesPanic(char[] candidate) throws Exception { return check(2, candidate); }
                @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
                    if (expected != version) { throw new CancellationException("Changed configuration."); }
                    action.run();
                }
            };
        }, wipe);
        PanicSignInService.Result run() throws Exception { return service.run(input); }
        void assertAllChecks() { for (int count : checks) { assertEquals(1, count); } }
        void assertCleared() { assertArrayEquals(new char[input.taken.length], input.taken); }
    }

    private static final class Input implements PanicSignInService.Submission {
        char[] caller = "a privately copied sign-in password".toCharArray();
        char[] taken;
        boolean closed;
        boolean used;
        @Override public char[] takePassword() {
            if (closed || used) { throw new CancellationException("Closed/reused input."); }
            used = true; taken = caller == null ? null : caller.clone(); return taken;
        }
        @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
            if (closed) { throw new CancellationException("Cancelled input."); }
            action.run();
        }
        @Override public void close() { closed = true; }
    }

    private static void rejects(PanicPasswordService.Commit action) throws Exception {
        try { action.run(); fail("Unsafe sign-in operation was accepted."); }
        catch (CancellationException | GeneralSecurityException | IOException | IllegalArgumentException expected) { }
    }

    @Test public void incorrectPasswordChecksEveryRoleAndDeletesNothing() throws Exception {
        Fixture f = new Fixture();
        assertEquals(PanicSignInService.Result.NO_MATCH, f.run());
        f.assertAllChecks(); f.assertCleared(); assertEquals(0, f.erases); assertFalse(f.pending);
    }

    @Test public void masterMatchStillChecksEveryRoleWithoutWiping() throws Exception {
        Fixture f = new Fixture(); f.matches[0] = true;
        assertEquals(PanicSignInService.Result.MASTER, f.run()); f.assertAllChecks(); assertEquals(0, f.erases);
    }

    @Test public void decoyMatchStillChecksEveryRoleWithoutWiping() throws Exception {
        Fixture f = new Fixture(); f.matches[1] = true;
        assertEquals(PanicSignInService.Result.DECOY, f.run()); f.assertAllChecks(); assertEquals(0, f.erases);
    }

    @Test public void panicWipesOnlyAfterChecksInputClearingAndClosure() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true;
        assertEquals(PanicSignInService.Result.PANIC_WIPED, f.run());
        assertEquals(1, f.erases); assertFalse(f.pending); rejects(() -> f.gate.begin());
    }

    @Test public void masterStorageErrorDoesNotSkipLaterChecksOrAuthorizePanic() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.errors[0] = new IOException();
        rejects(f::run); f.assertAllChecks(); f.assertCleared(); assertEquals(0, f.erases); assertFalse(f.pending);
    }

    @Test public void decoyCryptoErrorDoesNotSkipPanicCheck() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.errors[1] = new GeneralSecurityException();
        rejects(f::run); f.assertAllChecks(); assertEquals(0, f.erases);
    }

    @Test public void corruptPanicProofPreventsMasterRouteAsWellAsWipe() throws Exception {
        Fixture f = new Fixture(); f.matches[0] = true; f.errors[2] = new IOException();
        rejects(f::run); f.assertAllChecks(); assertEquals(0, f.erases);
    }

    @Test public void allRoleErrorsAreCollectedBeforeRejecting() throws Exception {
        Fixture f = new Fixture(); Arrays.fill(f.errors, new IOException());
        try { f.run(); fail("Role errors were ignored."); }
        catch (GeneralSecurityException error) { assertEquals(3, error.getSuppressed().length); }
        f.assertAllChecks(); assertEquals(0, f.erases);
    }

    @Test public void everyAmbiguousCombinationIsRejectedWithoutWipe() throws Exception {
        for (int mask : new int[]{3, 5, 6, 7}) {
            Fixture f = new Fixture();
            for (int i = 0; i < 3; i++) { f.matches[i] = (mask & (1 << i)) != 0; }
            rejects(f::run); f.assertAllChecks(); assertEquals(0, f.erases); assertFalse(f.pending);
        }
    }

    @Test public void changedCredentialConfigurationRejectsVerifiedPanic() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.afterCheck = () -> f.version++;
        rejects(f::run); f.assertAllChecks(); assertEquals(0, f.erases);
    }

    @Test public void stoppedRuntimeDuringChecksRejectsVerifiedPanic() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.afterCheck = f.gate::blockNewWork;
        rejects(f::run); f.assertAllChecks(); f.assertCleared(); assertEquals(0, f.erases);
    }

    @Test public void cancellationDuringChecksRejectsVerifiedPanic() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.afterCheck = f.input::close;
        rejects(f::run); f.assertAllChecks(); f.assertCleared(); assertEquals(0, f.erases);
    }

    @Test public void cancelledUnstartedSubmissionCannotWipe() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.input.close();
        rejects(f::run); assertEquals(0, f.erases); assertArrayEquals(new int[3], f.checks);
    }

    @Test public void inputIsSingleUseAndCallerOwnedArrayIsUntouched() throws Exception {
        Fixture f = new Fixture(); char[] expected = f.input.caller.clone();
        f.run(); rejects(f::run); assertArrayEquals(expected, f.input.caller); f.assertCleared();
    }

    @Test public void pendingRecoveryIsNotFreshPasswordAuthorization() throws Exception {
        Fixture f = new Fixture(); f.pending = true; f.matches[2] = true;
        rejects(f::run); assertTrue(f.input.closed); assertEquals(0, f.erases);
        assertArrayEquals(new int[3], f.checks); assertTrue(f.pending);
    }

    @Test public void unreadableRecoveryMarkerBlocksRoutingWithoutDeleting() throws Exception {
        Fixture f = new Fixture(); f.failMarkerRead = true;
        rejects(f::run); assertTrue(f.input.closed); assertEquals(0, f.erases); rejects(() -> f.gate.begin());
    }

    @Test public void failedWipeNeverReturnsPanicWipedAndRetainsMarker() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.failErase = true;
        rejects(f::run); assertTrue(f.pending); f.assertCleared(); rejects(() -> f.gate.begin());
    }

    @Test public void failedMarkerWriteDoesNotDeleteTargets() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true; f.failMarkerWrite = true;
        rejects(f::run); assertEquals(0, f.erases); rejects(() -> f.gate.begin());
    }

    @Test public void invalidInputNeverChecksRolesOrDeletes() throws Exception {
        for (char[] candidate : new char[][]{null, new char[0], new char[257]}) {
            Fixture f = new Fixture(); f.input.caller = candidate;
            rejects(f::run); assertEquals(0, f.erases); assertTrue(f.input.closed);
            assertArrayEquals(new int[3], f.checks);
        }
    }

    @Test public void serviceRejectsAnUnrelatedWipeGate() throws Exception {
        Fixture f = new Fixture();
        rejects(() -> new PanicSignInService(new PanicWorkGate(), () -> null, f.wipe));
    }
}

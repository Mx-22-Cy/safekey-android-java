package com.safekey.app.security.panic;

import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class PanicPasswordSeparationTest {
    private static final class Fixture {
        final PanicWorkGate gate = new PanicWorkGate();
        final Object lock = new Object();
        final boolean[] matches = new boolean[3];
        final int[] checks = new int[3];
        final Exception[] errors = new Exception[3];
        long version;
        long now;
        int saves;
        char[] checkedCopy;
        Runnable hook = () -> { };
        boolean failFinalRead;
        final PanicPasswordSeparation guard = new PanicPasswordSeparation(gate, () -> {
            long expected = version;
            return new PanicSignInService.Snapshot() {
                private boolean check(int role, char[] candidate) throws Exception {
                    checks[role]++; checkedCopy = candidate; hook.run();
                    if (errors[role] != null) { throw errors[role]; }
                    return matches[role];
                }
                @Override public boolean matchesMaster(char[] candidate) throws Exception { return check(0, candidate); }
                @Override public boolean matchesDecoy(char[] candidate) throws Exception { return check(1, candidate); }
                @Override public boolean matchesPanic(char[] candidate) throws Exception { return check(2, candidate); }
                @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
                    synchronized (lock) {
                        if (failFinalRead) { throw new IOException("Final read failed."); }
                        if (version != expected) { throw new CancellationException(); }
                        action.run();
                    }
                }
            };
        }, () -> now, 60_000L);
        PanicPasswordSeparation.Permit prepare(PanicPasswordSeparation.Role role) throws Exception {
            return guard.prepare(role, "a proposed unique test password".toCharArray());
        }
        void save() { saves++; version++; }
        void assertAllChecks() { for (int n : checks) { assertEquals(1, n); } }
    }

    private static void rejects(PanicPasswordService.Commit action) throws Exception {
        try { action.run(); fail("Password separation was bypassed."); }
        catch (IllegalArgumentException | IllegalStateException | GeneralSecurityException expected) { }
    }

    @Test public void masterCannotEqualDecoy() throws Exception {
        Fixture f = new Fixture(); f.matches[1] = true;
        rejects(() -> f.prepare(PanicPasswordSeparation.Role.MASTER)); f.assertAllChecks(); assertEquals(0, f.saves);
    }

    @Test public void masterCannotEqualPanic() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true;
        rejects(() -> f.prepare(PanicPasswordSeparation.Role.MASTER)); f.assertAllChecks();
    }

    @Test public void decoyCannotEqualMaster() throws Exception {
        Fixture f = new Fixture(); f.matches[0] = true;
        rejects(() -> f.prepare(PanicPasswordSeparation.Role.DECOY)); f.assertAllChecks();
    }

    @Test public void decoyCannotEqualPanic() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true;
        rejects(() -> f.prepare(PanicPasswordSeparation.Role.DECOY)); f.assertAllChecks();
    }

    @Test public void panicCannotEqualEitherVaultPassword() throws Exception {
        for (int other : new int[]{0, 1}) {
            Fixture f = new Fixture(); f.matches[other] = true;
            rejects(() -> f.prepare(PanicPasswordSeparation.Role.PANIC)); f.assertAllChecks();
        }
    }

    @Test public void currentRoleMatchIsAllowedButOtherRolesRemainDistinct() throws Exception {
        for (PanicPasswordSeparation.Role role : PanicPasswordSeparation.Role.values()) {
            Fixture f = new Fixture(); f.matches[role.ordinal()] = true;
            try (PanicPasswordSeparation.Permit permit = f.prepare(role)) { permit.commit(f::save); }
            f.assertAllChecks(); assertEquals(1, f.saves);
        }
    }

    @Test public void uniquePasswordForEveryRoleCanCommit() throws Exception {
        for (PanicPasswordSeparation.Role role : PanicPasswordSeparation.Role.values()) {
            Fixture f = new Fixture();
            try (PanicPasswordSeparation.Permit permit = f.prepare(role)) { permit.commit(f::save); }
            assertEquals(1, f.saves);
        }
    }

    @Test public void eachStoredRoleErrorPreventsSaveWithoutSkippingOtherChecks() throws Exception {
        for (int role = 0; role < 3; role++) {
            Fixture f = new Fixture(); f.errors[role] = new IOException();
            rejects(() -> f.prepare(PanicPasswordSeparation.Role.MASTER)); f.assertAllChecks(); assertEquals(0, f.saves);
        }
    }

    @Test public void allRoleErrorsAreRetained() throws Exception {
        Fixture f = new Fixture(); Arrays.fill(f.errors, new IOException());
        try { f.prepare(PanicPasswordSeparation.Role.MASTER); fail("Errors ignored."); }
        catch (GeneralSecurityException error) { assertEquals(3, error.getSuppressed().length); }
        f.assertAllChecks();
    }

    @Test public void changedConfigurationBeforeSaveRejectsPermit() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordSeparation.Permit permit = f.prepare(PanicPasswordSeparation.Role.MASTER)) {
            f.version++; rejects(() -> permit.commit(f::save));
        }
        assertEquals(0, f.saves);
    }

    @Test public void simultaneousCrossRoleSavesCannotBothCommitFromOneSnapshot() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordSeparation.Permit first = f.prepare(PanicPasswordSeparation.Role.MASTER);
             PanicPasswordSeparation.Permit second = f.prepare(PanicPasswordSeparation.Role.DECOY)) {
            CountDownLatch start = new CountDownLatch(1); CountDownLatch done = new CountDownLatch(2);
            AtomicInteger rejected = new AtomicInteger();
            for (PanicPasswordSeparation.Permit permit : new PanicPasswordSeparation.Permit[]{first, second}) {
                new Thread(() -> {
                    try { assertTrue(start.await(5, TimeUnit.SECONDS)); permit.commit(f::save); }
                    catch (CancellationException expected) { rejected.incrementAndGet(); }
                    catch (InterruptedException error) { Thread.currentThread().interrupt(); }
                    finally { done.countDown(); }
                }).start();
            }
            start.countDown(); assertTrue(done.await(5, TimeUnit.SECONDS));
            assertEquals(1, f.saves); assertEquals(1, rejected.get());
        }
    }

    @Test public void runtimeStoppedDuringChecksCannotProducePermit() throws Exception {
        Fixture f = new Fixture(); f.hook = f.gate::blockNewWork;
        rejects(() -> f.prepare(PanicPasswordSeparation.Role.DECOY)); f.assertAllChecks();
    }

    @Test public void runtimeStoppedAfterChecksCannotCommit() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordSeparation.Permit permit = f.prepare(PanicPasswordSeparation.Role.MASTER)) {
            f.gate.blockNewWork(); rejects(() -> permit.commit(f::save));
        }
        assertEquals(0, f.saves);
    }

    @Test public void closedPermitCannotCommit() throws Exception {
        Fixture f = new Fixture(); PanicPasswordSeparation.Permit permit = f.prepare(PanicPasswordSeparation.Role.MASTER);
        permit.close(); rejects(() -> permit.commit(f::save)); assertEquals(0, f.saves);
    }

    @Test public void permitCannotBeReusedAfterSuccessfulSave() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordSeparation.Permit permit = f.prepare(PanicPasswordSeparation.Role.MASTER)) {
            permit.commit(f::save); rejects(() -> permit.commit(f::save));
        }
        assertEquals(1, f.saves);
    }

    @Test public void expiredAndReversedClockPermitsCannotSave() throws Exception {
        for (long time : new long[]{60_000L, -1L}) {
            Fixture f = new Fixture();
            try (PanicPasswordSeparation.Permit permit = f.prepare(PanicPasswordSeparation.Role.MASTER)) {
                f.now = time; rejects(() -> permit.commit(f::save));
            }
            assertEquals(0, f.saves);
        }
    }

    @Test public void checkClearsItsPrivateCopyAndLeavesCallerArrayIntact() throws Exception {
        Fixture f = new Fixture(); char[] input = "a proposed password".toCharArray(); char[] expected = input.clone();
        try (PanicPasswordSeparation.Permit ignored = f.guard.prepare(PanicPasswordSeparation.Role.MASTER, input)) {
            assertArrayEquals(expected, input); assertArrayEquals(new char[f.checkedCopy.length], f.checkedCopy);
        }
    }

    @Test public void rejectedCheckAlsoClearsItsPrivateCopy() throws Exception {
        Fixture f = new Fixture(); f.matches[2] = true;
        rejects(() -> f.prepare(PanicPasswordSeparation.Role.MASTER));
        assertArrayEquals(new char[f.checkedCopy.length], f.checkedCopy);
    }

    @Test public void finalStorageFailureCannotReachSaveAndBurnsPermit() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordSeparation.Permit permit = f.prepare(PanicPasswordSeparation.Role.MASTER)) {
            f.failFinalRead = true; rejects(() -> permit.commit(f::save));
            f.failFinalRead = false; rejects(() -> permit.commit(f::save));
        }
        assertEquals(0, f.saves);
    }

    @Test public void invalidCandidateDoesNotReachCredentialChecks() throws Exception {
        for (char[] candidate : new char[][]{null, new char[0], new char[257]}) {
            Fixture f = new Fixture(); rejects(() -> f.guard.prepare(PanicPasswordSeparation.Role.MASTER, candidate));
            for (int count : f.checks) { assertEquals(0, count); }
            assertEquals(0, f.saves);
        }
    }
}

package com.safekey.app.session.logic;

import static org.junit.Assert.*;

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class VaultSessionManagerStorageCommitTest {
    @Test
    public void currentAuthenticationRunsCommitUnderSessionMonitor() {
        AtomicLong clock = new AtomicLong(100L);
        VaultSessionManager session = new VaultSessionManager(clock::get, () -> {});
        session.unlockAfterAuthentication();
        long generation = session.getAuthenticationGeneration();
        assertTrue(session.runIfCurrentAuthenticationForStorageCommit(generation,
                () -> assertTrue(Thread.holdsLock(session))));
    }

    @Test
    public void lockedAuthenticationCannotCommit() {
        VaultSessionManager session = new VaultSessionManager(() -> 0L, () -> {});
        assertFalse(session.runIfCurrentAuthenticationForStorageCommit(-1L,
                () -> fail("Locked authentication committed.")));
    }

    @Test
    public void reauthenticationRejectsTheOriginalGeneration() {
        VaultSessionManager session = new VaultSessionManager(() -> 0L, () -> {});
        session.unlockAfterAuthentication();
        long previous = session.getAuthenticationGeneration();
        session.unlockAfterAuthentication();
        assertFalse(session.runIfCurrentAuthenticationForStorageCommit(previous,
                () -> fail("An old authentication committed.")));
    }

    @Test
    public void exactTimeoutRejectsCommitAndLeavesCleanupToStateCheck() {
        AtomicLong clock = new AtomicLong();
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager session = new VaultSessionManager(clock::get, 1_000L,
                cleanups::incrementAndGet);
        session.unlockAfterAuthentication();
        long generation = session.getAuthenticationGeneration();
        clock.set(1_000L);
        assertFalse(session.runIfCurrentAuthenticationForStorageCommit(generation,
                () -> fail("Expired authentication committed.")));
        assertEquals(0, cleanups.get());
        assertEquals(SessionState.LOCKED, session.getState());
        assertEquals(1, cleanups.get());
    }

    @Test
    public void backwardsClockRejectsCommit() {
        AtomicLong clock = new AtomicLong(100L);
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager session = new VaultSessionManager(clock::get,
                cleanups::incrementAndGet);
        session.unlockAfterAuthentication();
        long generation = session.getAuthenticationGeneration();
        clock.set(99L);
        assertFalse(session.runIfCurrentAuthenticationForStorageCommit(generation,
                () -> fail("A reversed clock authorized storage.")));
        assertEquals(0, cleanups.get());
    }

    @Test
    public void commitDoesNotExtendTheInactivityTimeout() {
        AtomicLong clock = new AtomicLong();
        VaultSessionManager session = new VaultSessionManager(clock::get, 1_000L, () -> {});
        session.unlockAfterAuthentication();
        long generation = session.getAuthenticationGeneration();
        clock.set(999L);
        assertTrue(session.runIfCurrentAuthenticationForStorageCommit(generation, () -> {}));
        clock.set(1_000L);
        assertFalse(session.runIfCurrentAuthenticationForStorageCommit(generation,
                () -> fail("A storage commit refreshed inactivity.")));
    }

    @Test
    public void vaultLockWaitsForAnAuthorizedCommit() throws Exception {
        VaultSessionManager session = new VaultSessionManager(() -> 0L, () -> {});
        session.unlockAfterAuthentication();
        long generation = session.getAuthenticationGeneration();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch locking = new CountDownLatch(1);
        ExecutorService threads = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> commit = threads.submit(() ->
                    session.runIfCurrentAuthenticationForStorageCommit(generation, () -> {
                        entered.countDown();
                        try {
                            assertTrue(release.await(2, TimeUnit.SECONDS));
                        } catch (InterruptedException error) {
                            Thread.currentThread().interrupt();
                            throw new AssertionError(error);
                        }
                    }));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            Future<?> locked = threads.submit(() -> {
                locking.countDown();
                session.lock();
            });
            assertTrue(locking.await(2, TimeUnit.SECONDS));
            try {
                locked.get(100, TimeUnit.MILLISECONDS);
                fail("Lock completed while a storage commit was running.");
            } catch (TimeoutException expected) {
                release.countDown();
            }
            assertTrue(commit.get(2, TimeUnit.SECONDS));
            locked.get(2, TimeUnit.SECONDS);
            assertEquals(SessionState.LOCKED, session.getState());
        } finally {
            release.countDown();
            threads.shutdownNow();
            assertTrue(threads.awaitTermination(2, TimeUnit.SECONDS));
        }
    }
}

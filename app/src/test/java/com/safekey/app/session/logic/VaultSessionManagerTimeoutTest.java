package com.safekey.app.session.logic;

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class VaultSessionManagerTimeoutTest {

    @Test
    public void getter_returnsDefaultAndCustomTimeouts() {
        assertEquals(300_000L,
                new VaultSessionManager(() -> 0L, () -> {})
                        .getInactivityTimeoutMillis());
        assertEquals(1_000L,
                new VaultSessionManager(() -> 0L, 1_000L, () -> {})
                        .getInactivityTimeoutMillis());
    }

    @Test
    public void shortening_evaluatesOriginalLastActivity() {
        AtomicLong now = new AtomicLong();
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager manager = manager(now, cleanups);
        manager.unlockAfterAuthentication();
        now.set(600L);
        manager.setInactivityTimeoutMillis(500L);
        assertEquals(500L, manager.getInactivityTimeoutMillis());
        assertEquals(SessionState.LOCKED, manager.getState());
        assertEquals(1, cleanups.get());
    }

    @Test
    public void shortening_beforeNewDeadline_doesNotRefreshActivity() {
        AtomicLong now = new AtomicLong();
        VaultSessionManager manager = manager(now, new AtomicInteger());
        manager.unlockAfterAuthentication();
        now.set(400L);
        manager.setInactivityTimeoutMillis(700L);
        assertEquals(300L, manager.getRemainingInactivityMillis());
        now.set(700L);
        assertEquals(SessionState.LOCKED, manager.getState());
    }

    @Test
    public void lengthening_beforeOldDeadline_preservesElapsedTimeAndGeneration() {
        AtomicLong now = new AtomicLong();
        VaultSessionManager manager = manager(now, new AtomicInteger());
        manager.unlockAfterAuthentication();
        long generation = manager.getAuthenticationGeneration();
        now.set(400L);
        manager.setInactivityTimeoutMillis(2_000L);
        assertEquals(1_600L, manager.getRemainingInactivityMillis());
        assertEquals(generation, manager.getAuthenticationGeneration());
        assertTrue(manager.runIfCurrentAuthenticationForStorageCommit(
                generation, () -> {}));
    }

    @Test
    public void lengthening_afterOldDeadline_cannotReviveSession() {
        AtomicLong now = new AtomicLong();
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager manager = manager(now, cleanups);
        manager.unlockAfterAuthentication();
        long generation = manager.getAuthenticationGeneration();
        now.set(1_000L);
        manager.setInactivityTimeoutMillis(2_000L);
        assertEquals(2_000L, manager.getInactivityTimeoutMillis());
        assertEquals(SessionState.LOCKED, manager.getState());
        assertEquals(1, cleanups.get());
        assertFalse(manager.runIfCurrentAuthenticationForStorageCommit(
                generation, () -> fail("Expired authentication was revived.")));
    }

    @Test
    public void exactNewDeadline_locksImmediately() {
        AtomicLong now = new AtomicLong();
        VaultSessionManager manager = manager(now, new AtomicInteger());
        manager.unlockAfterAuthentication();
        now.set(500L);
        manager.setInactivityTimeoutMillis(500L);
        assertEquals(SessionState.LOCKED, manager.getState());
    }

    @Test
    public void invalidTimeout_doesNotChangePolicyOrAuthenticate() {
        AtomicLong now = new AtomicLong();
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager manager = manager(now, cleanups);
        manager.unlockAfterAuthentication();
        for (long invalid : new long[]{0L, -1L, Long.MIN_VALUE}) {
            assertThrows(IllegalArgumentException.class,
                    () -> manager.setInactivityTimeoutMillis(invalid));
        }
        assertEquals(1_000L, manager.getInactivityTimeoutMillis());
        assertEquals(SessionState.UNLOCKED, manager.getState());
        assertEquals(0, cleanups.get());
    }

    @Test
    public void backwardsClockDuringPolicyChange_locks() {
        AtomicLong now = new AtomicLong(100L);
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager manager = manager(now, cleanups);
        manager.unlockAfterAuthentication();
        now.set(99L);
        manager.setInactivityTimeoutMillis(2_000L);
        assertEquals(SessionState.LOCKED, manager.getState());
        assertEquals(1, cleanups.get());
    }

    @Test
    public void policyChangeWhileLocked_remainsLockedWithoutCleanup() {
        AtomicLong now = new AtomicLong();
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager manager = manager(now, cleanups);
        manager.setInactivityTimeoutMillis(2_000L);
        assertEquals(SessionState.LOCKED, manager.getState());
        assertEquals(-1L, manager.getAuthenticationGeneration());
        assertEquals(0, cleanups.get());
        manager.unlockAfterAuthentication();
        assertEquals(2_000L, manager.getRemainingInactivityMillis());
    }

    @Test
    public void unchangedPolicy_doesNotRefreshDeadline() {
        AtomicLong now = new AtomicLong();
        VaultSessionManager manager = manager(now, new AtomicInteger());
        manager.unlockAfterAuthentication();
        now.set(400L);
        manager.setInactivityTimeoutMillis(1_000L);
        assertEquals(600L, manager.getRemainingInactivityMillis());
    }

    @Test
    public void shortening_invalidatesAuthenticationEvenIfCleanupThrows() {
        AtomicLong now = new AtomicLong();
        VaultSessionManager manager = new VaultSessionManager(
                now::get, 1_000L, () -> {
                    throw new IllegalStateException("Simulated cleanup failure.");
                });
        manager.unlockAfterAuthentication();
        long generation = manager.getAuthenticationGeneration();
        now.set(600L);
        assertThrows(IllegalStateException.class,
                () -> manager.setInactivityTimeoutMillis(500L));
        assertEquals(SessionState.LOCKED, manager.getState());
        assertEquals(500L, manager.getInactivityTimeoutMillis());
        assertFalse(manager.runIfCurrentAuthenticationForStorageCommit(
                generation, () -> fail("Cleanup failure restored access.")));
    }

    @Test
    public void invalidation_whileAlreadyLocked_runsPendingWorkCleanup() {
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager manager = new VaultSessionManager(
                () -> 0L, cleanups::incrementAndGet);
        manager.invalidateAuthentication();
        assertEquals(SessionState.LOCKED, manager.getState());
        assertEquals(1, cleanups.get());
        manager.lock();
        assertEquals(1, cleanups.get());
    }

    @Test
    public void invalidation_revokesCurrentAuthenticationBeforeCleanup() {
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager[] manager = new VaultSessionManager[1];
        manager[0] = new VaultSessionManager(() -> 0L, () -> {
            assertEquals(SessionState.LOCKED, manager[0].getState());
            cleanups.incrementAndGet();
        });
        manager[0].unlockAfterAuthentication();
        long old = manager[0].getAuthenticationGeneration();
        manager[0].invalidateAuthentication();
        assertEquals(1, cleanups.get());
        assertFalse(manager[0].runIfCurrentAuthentication(old,
                () -> fail("Invalidated authentication was accepted.")));
        manager[0].unlockAfterAuthentication();
        assertTrue(manager[0].getAuthenticationGeneration() > old);
    }

    @Test
    public void timeoutChange_waitsForAuthorizedStorageCommit() throws Exception {
        AtomicLong now = new AtomicLong();
        AtomicInteger cleanups = new AtomicInteger();
        VaultSessionManager manager = manager(now, cleanups);
        manager.unlockAfterAuthentication();
        long generation = manager.getAuthenticationGeneration();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch changing = new CountDownLatch(1);
        ExecutorService threads = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> commit = threads.submit(() ->
                    manager.runIfCurrentAuthenticationForStorageCommit(
                            generation, () -> {
                                entered.countDown();
                                try {
                                    assertTrue(release.await(5, TimeUnit.SECONDS));
                                } catch (InterruptedException error) {
                                    Thread.currentThread().interrupt();
                                    throw new AssertionError(error);
                                }
                            }));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            now.set(600L);
            Future<?> change = threads.submit(() -> {
                changing.countDown();
                manager.setInactivityTimeoutMillis(500L);
            });
            assertTrue(changing.await(5, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class,
                    () -> change.get(100, TimeUnit.MILLISECONDS));
            release.countDown();
            assertTrue(commit.get(5, TimeUnit.SECONDS));
            change.get(5, TimeUnit.SECONDS);
            assertEquals(SessionState.LOCKED, manager.getState());
            assertEquals(1, cleanups.get());
        } finally {
            release.countDown();
            threads.shutdownNow();
            assertTrue(threads.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private static VaultSessionManager manager(
            AtomicLong now, AtomicInteger cleanups) {
        return new VaultSessionManager(now::get, 1_000L,
                cleanups::incrementAndGet);
    }
}

package com.safekey.app.session.logic;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VaultSessionGenerationTest {
    @Test
    public void lockedSessionCannotAuthorizeCommit() {
        VaultSessionManager session = new VaultSessionManager(() -> 0L, () -> { });
        assertEquals(-1L, session.getAuthenticationGeneration());
        assertFalse(session.runIfCurrentAuthentication(-1L,
                () -> { throw new AssertionError("Locked session committed"); }));
    }

    @Test
    public void currentAuthenticationCanCommit() {
        VaultSessionManager session = new VaultSessionManager(() -> 0L, () -> { });
        session.unlockAfterAuthentication();
        AtomicBoolean committed = new AtomicBoolean();
        assertTrue(session.runIfCurrentAuthentication(session.getAuthenticationGeneration(),
                () -> committed.set(true)));
        assertTrue(committed.get());
    }

    @Test
    public void lockInvalidatesPendingCommit() {
        VaultSessionManager session = new VaultSessionManager(() -> 0L, () -> { });
        session.unlockAfterAuthentication();
        long old = session.getAuthenticationGeneration();
        session.lock();
        assertFalse(session.runIfCurrentAuthentication(old,
                () -> { throw new AssertionError("Commit after lock"); }));
    }

    @Test
    public void replacementAuthenticationCannotAuthorizeOlderOperation() {
        VaultSessionManager session = new VaultSessionManager(() -> 0L, () -> { });
        session.unlockAfterAuthentication();
        long old = session.getAuthenticationGeneration();
        session.lock();
        session.unlockAfterAuthentication();
        assertFalse(session.runIfCurrentAuthentication(old,
                () -> { throw new AssertionError("Old operation committed in replacement session"); }));
        assertTrue(session.getAuthenticationGeneration() != old);
    }

    @Test
    public void timeoutIsCheckedAtCommitWithoutNeedingUiPoll() {
        AtomicLong clock = new AtomicLong();
        AtomicBoolean cleaned = new AtomicBoolean();
        VaultSessionManager session = new VaultSessionManager(clock::get, 100L,
                () -> cleaned.set(true));
        session.unlockAfterAuthentication();
        long old = session.getAuthenticationGeneration();
        clock.set(100L);
        assertFalse(session.runIfCurrentAuthentication(old,
                () -> { throw new AssertionError("Commit after expiry"); }));
        assertTrue(cleaned.get());
    }
}

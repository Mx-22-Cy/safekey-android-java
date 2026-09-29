package com.safekey.app.session.logic;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class VaultSessionManagerTest {

    private static final long TIMEOUT_MILLIS =
            1_000L;

    private final FakeTimeSource timeSource =
            new FakeTimeSource(10_000L);

    private final AtomicInteger lockCount =
            new AtomicInteger();

    @Test
    public void getState_newSession_isLocked() {
        VaultSessionManager manager =
                createManager();

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );

        assertEquals(
                0,
                lockCount.get()
        );
    }

    @Test
    public void unlockAfterAuthentication_changesStateToUnlocked() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();

        assertEquals(
                SessionState.UNLOCKED,
                manager.getState()
        );
    }

    @Test
    public void getState_beforeTimeout_remainsUnlocked() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(TIMEOUT_MILLIS - 1L);

        assertEquals(
                SessionState.UNLOCKED,
                manager.getState()
        );
    }

    @Test
    public void getState_atTimeout_locksSession() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(TIMEOUT_MILLIS);

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );

        assertEquals(
                1,
                lockCount.get()
        );
    }

    @Test
    public void getState_afterTimeout_callsHandlerOnlyOnce() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(TIMEOUT_MILLIS);

        manager.getState();
        manager.getState();

        assertEquals(
                1,
                lockCount.get()
        );
    }

    @Test
    public void recordActivity_beforeTimeout_resetsTimer() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(600L);

        assertTrue(
                manager.recordActivity()
        );

        timeSource.advanceBy(TIMEOUT_MILLIS - 1L);

        assertEquals(
                SessionState.UNLOCKED,
                manager.getState()
        );

        timeSource.advanceBy(1L);

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );
    }

    @Test
    public void recordActivity_afterTimeout_returnsFalseAndLocks() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(TIMEOUT_MILLIS);

        assertFalse(
                manager.recordActivity()
        );

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );

        assertEquals(
                1,
                lockCount.get()
        );
    }

    @Test
    public void recordActivity_lockedSession_returnsFalse() {
        VaultSessionManager manager =
                createManager();

        assertFalse(
                manager.recordActivity()
        );

        assertEquals(
                0,
                lockCount.get()
        );
    }

    @Test
    public void lock_unlockedSession_locksAndCallsHandlerOnce() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        manager.lock();
        manager.lock();

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );

        assertEquals(
                1,
                lockCount.get()
        );
    }

    @Test
    public void getState_clockMovesBackward_locksSession() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.setTime(9_999L);

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );

        assertEquals(
                1,
                lockCount.get()
        );
    }

    @Test
    public void getRemainingInactivityMillis_lockedSession_returnsZero() {
        VaultSessionManager manager =
                createManager();

        assertEquals(
                0L,
                manager.getRemainingInactivityMillis()
        );

        assertEquals(
                0,
                lockCount.get()
        );
    }

    @Test
    public void getRemainingInactivityMillis_afterUnlock_returnsFullTimeout() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();

        assertEquals(
                TIMEOUT_MILLIS,
                manager.getRemainingInactivityMillis()
        );
    }

    @Test
    public void getRemainingInactivityMillis_afterElapsedTime_returnsRemainingTime() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(400L);

        assertEquals(
                600L,
                manager.getRemainingInactivityMillis()
        );

        assertEquals(
                SessionState.UNLOCKED,
                manager.getState()
        );
    }

    @Test
    public void getRemainingInactivityMillis_atTimeout_locksAndReturnsZero() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(TIMEOUT_MILLIS);

        assertEquals(
                0L,
                manager.getRemainingInactivityMillis()
        );

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );

        assertEquals(
                1,
                lockCount.get()
        );
    }

    @Test
    public void getRemainingInactivityMillis_afterActivity_usesResetTimer() {
        VaultSessionManager manager =
                createManager();

        manager.unlockAfterAuthentication();
        timeSource.advanceBy(700L);

        assertTrue(
                manager.recordActivity()
        );

        timeSource.advanceBy(250L);

        assertEquals(
                750L,
                manager.getRemainingInactivityMillis()
        );
    }

    @Test
    public void defaultConstructor_usesFiveMinuteTimeout() {
        VaultSessionManager manager =
                new VaultSessionManager(
                        timeSource,
                        () -> lockCount.incrementAndGet()
                );

        manager.unlockAfterAuthentication();

        timeSource.advanceBy(
                VaultSessionManager
                        .DEFAULT_INACTIVITY_TIMEOUT_MILLIS
                        - 1L
        );

        assertEquals(
                SessionState.UNLOCKED,
                manager.getState()
        );

        timeSource.advanceBy(1L);

        assertEquals(
                SessionState.LOCKED,
                manager.getState()
        );
    }

    @Test
    public void constructor_nullTimeSource_throwsException() {
        assertThrows(
                NullPointerException.class,
                () -> new VaultSessionManager(
                        null,
                        TIMEOUT_MILLIS,
                        () -> {
                        }
                )
        );
    }

    @Test
    public void constructor_nullLockHandler_throwsException() {
        assertThrows(
                NullPointerException.class,
                () -> new VaultSessionManager(
                        timeSource,
                        TIMEOUT_MILLIS,
                        null
                )
        );
    }

    @Test
    public void constructor_zeroTimeout_throwsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new VaultSessionManager(
                        timeSource,
                        0L,
                        () -> {
                        }
                )
        );
    }

    @Test
    public void constructor_negativeTimeout_throwsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new VaultSessionManager(
                        timeSource,
                        -1L,
                        () -> {
                        }
                )
        );
    }

    private VaultSessionManager createManager() {
        return new VaultSessionManager(
                timeSource,
                TIMEOUT_MILLIS,
                () -> lockCount.incrementAndGet()
        );
    }

    private static final class FakeTimeSource
            implements LongSupplier {

        private long currentTimeMillis;

        private FakeTimeSource(
                long initialTimeMillis
        ) {
            currentTimeMillis =
                    initialTimeMillis;
        }

        private void advanceBy(
                long milliseconds
        ) {
            currentTimeMillis +=
                    milliseconds;
        }

        private void setTime(
                long timeMillis
        ) {
            currentTimeMillis =
                    timeMillis;
        }

        @Override
        public long getAsLong() {
            return currentTimeMillis;
        }
    }
}

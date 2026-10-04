package com.safekey.app.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.safekey.app.SafeKeyApplication;

import com.safekey.app.session.logic.SessionState;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.atomic.AtomicInteger;

@RunWith(AndroidJUnit4.class)
public class SafeKeySessionInstrumentedTest {

    @Before
    public void setUp() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.lock();
    }

    @After
    public void tearDown() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.lock();

        ((SafeKeyApplication) InstrumentationRegistry
                .getInstrumentation()
                .getTargetContext()
                .getApplicationContext())
                .registerSessionCleanup();
    }

    @Test
    public void lock_unlockedSession_runsRegisteredCleanupOnce() {
        AtomicInteger cleanupCount =
                new AtomicInteger();

        SafeKeySession.registerSensitiveDataCleanup(
                cleanupCount::incrementAndGet
        );

        SafeKeySession.unlockAfterAuthentication();

        SafeKeySession.lock();
        SafeKeySession.lock();

        assertEquals(
                SessionState.LOCKED,
                SafeKeySession.getState()
        );

        assertEquals(
                1,
                cleanupCount.get()
        );
    }

    @Test
    public void unregisterSensitiveDataCleanup_preventsOldCleanupFromRunning() {
        AtomicInteger cleanupCount =
                new AtomicInteger();

        SafeKeySession.registerSensitiveDataCleanup(
                cleanupCount::incrementAndGet
        );

        SafeKeySession.unlockAfterAuthentication();

        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.lock();

        assertEquals(
                0,
                cleanupCount.get()
        );
    }

    @Test
    public void registerSensitiveDataCleanup_nullCleanup_isRejected() {
        NullPointerException exception =
                assertThrows(
                        NullPointerException.class,
                        () ->
                                SafeKeySession
                                        .registerSensitiveDataCleanup(
                                                null
                                        )
                );

        assertEquals(
                "cleanup",
                exception.getMessage()
        );
    }
}

package com.safekey.app.securityui;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.security.totp.TotpEnrollmentService;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Regression tests for the Activity-independent confirmation receipt.
 * These tests deliberately simulate delivery of backend results. They do NOT
 * exercise actual TOTP enrollment or the full Setup -> Verify screen journey.
 */
@RunWith(AndroidJUnit4.class)
public final class T39ConfirmationRetentionInstrumentedTest {
    @Before public void setUp() {
        onMain(TotpConfirmationState::discard);
    }

    @After public void tearDown() {
        onMain(TotpConfirmationState::discard);
    }

    @Test public void enabledResultSurvivesObserverReplacement() {
        AtomicInteger firstCalls = new AtomicInteger();
        AtomicInteger secondCalls = new AtomicInteger();
        AtomicReference<TotpEnrollmentService.Confirmation> received = new AtomicReference<>();
        onMain(() -> {
            TotpConfirmationState.Listener first = (result, remaining, failed) -> firstCalls.incrementAndGet();
            TotpConfirmationState.observe(first);
            TotpConfirmationState.stopObserving(first);
            deliver(TotpEnrollmentService.Confirmation.ENABLED, 5, false);
            assertTrue(TotpConfirmationState.hasResult());
            assertFalse(TotpConfirmationState.isConfirming());
            assertEquals(0, firstCalls.get());
            TotpConfirmationState.Listener second = (result, remaining, failed) -> {
                received.set(result);
                secondCalls.incrementAndGet();
                assertFalse(failed);
            };
            TotpConfirmationState.observe(second);
            assertEquals(1, secondCalls.get());
            assertEquals(TotpEnrollmentService.Confirmation.ENABLED, received.get());
            TotpConfirmationState.consume();
            assertFalse(TotpConfirmationState.hasResult());
            TotpConfirmationState.stopObserving(second);
        });
    }

    @Test public void errorResultSurvivesObserverReplacement() {
        AtomicInteger calls = new AtomicInteger();
        onMain(() -> {
            deliver(null, 0, true);
            TotpConfirmationState.Listener observer = (result, remaining, failed) -> {
                assertTrue(failed);
                assertEquals(null, result);
                calls.incrementAndGet();
            };
            TotpConfirmationState.observe(observer);
            assertEquals(1, calls.get());
            TotpConfirmationState.consume();
            TotpConfirmationState.stopObserving(observer);
        });
    }

    @Test public void consumedResultIsNotReplayed() {
        AtomicInteger calls = new AtomicInteger();
        onMain(() -> {
            deliver(TotpEnrollmentService.Confirmation.INVALID_CODE, 4, false);
            TotpConfirmationState.consume();
            TotpConfirmationState.Listener observer = (result, remaining, failed) -> calls.incrementAndGet();
            TotpConfirmationState.observe(observer);
            assertEquals(0, calls.get());
            TotpConfirmationState.stopObserving(observer);
        });
    }

    private static void onMain(Runnable action) {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(action);
    }

    private static void deliver(TotpEnrollmentService.Confirmation result,
                                int remaining, boolean error) {
        try {
            Method finish = TotpConfirmationState.class.getDeclaredMethod("finish",
                    TotpEnrollmentService.Confirmation.class, int.class, boolean.class);
            finish.setAccessible(true);
            finish.invoke(null, result, remaining, error);
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError("Unable to simulate coordinator callback", exception);
        }
    }
}

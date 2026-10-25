
package com.safekey.app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class SafeKeyApplicationRoutingInstrumentedTest {

    private static final long CALLBACK_TIMEOUT_SECONDS = 30;

    private SafeKeyApplication application;

    @Before
    public void setUp() throws Exception {
        application =
                (SafeKeyApplication)
                        InstrumentationRegistry
                                .getInstrumentation()
                                .getTargetContext()
                                .getApplicationContext();

        application.registerSessionCleanup();

        // Trigger cleanup and wait for both vault connections
        // to finish closing before each test.
        SafeKeySession.unlockAfterAuthentication();
        SafeKeySession.lock();

        awaitAuthenticationReady();
    }

    @After
    public void tearDown() {
        SafeKeySession.lock();
        application.registerSessionCleanup();
    }

    @Test
    public void staleReadinessCallback_afterNewCleanup_isRejected()
            throws Exception {

        CountDownLatch completed = new CountDownLatch(1);

        java.util.concurrent.atomic.AtomicBoolean succeeded =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        AtomicReference<Exception> error =
                new AtomicReference<>();

        InstrumentationRegistry.getInstrumentation()
                .runOnMainSync(() -> {

                    // Queue a readiness success while the session is locked.
                    application.prepareForVaultAuthentication(
                            new VaultDataService.SimpleCallback() {
                                @Override
                                public void onSuccess() {
                                    succeeded.set(true);
                                    completed.countDown();
                                }

                                @Override
                                public void onError(Exception exception) {
                                    error.set(exception);
                                    completed.countDown();
                                }
                            }
                    );

                    // Start a newer cleanup before the queued
                    // readiness callback can execute.
                    SafeKeySession.unlockAfterAuthentication();
                    SafeKeySession.lock();
                });

        assertTrue(
                "Readiness callback did not finish.",
                completed.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertFalse(
                "Stale readiness must not succeed.",
                succeeded.get()
        );

        assertNotNull(
                "Stale readiness must report an error.",
                error.get()
        );

        // Ensure cleanup completes before the next test.
        awaitAuthenticationReady();
    }
    @Test
    public void readinessBlockedOnSessionLock_rejectsConcurrentCleanup()
            throws Exception {

        CountDownLatch monitorHeld = new CountDownLatch(1);
        CountDownLatch allowTransition = new CountDownLatch(1);
        CountDownLatch callbackCompleted = new CountDownLatch(1);

        java.util.concurrent.atomic.AtomicBoolean succeeded =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        AtomicReference<Exception> callbackError =
                new AtomicReference<>();

        AtomicReference<Throwable> workerError =
                new AtomicReference<>();

        Thread holder = new Thread(() -> {
            synchronized (SafeKeySession.getManager()) {
                monitorHeld.countDown();

                try {
                    if (!allowTransition.await(
                            CALLBACK_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS)) {
                        throw new AssertionError(
                                "Timed out waiting for session transition."
                        );
                    }

                    // Begin a newer cleanup while the old
                    // readiness callback waits for this monitor.
                    SafeKeySession.unlockAfterAuthentication();
                    SafeKeySession.lock();

                } catch (Throwable throwable) {
                    workerError.set(throwable);
                }
            }
        }, "readiness-session-lock-holder");

        try {
            InstrumentationRegistry.getInstrumentation()
                    .runOnMainSync(() -> {

                        application.prepareForVaultAuthentication(
                                new VaultDataService.SimpleCallback() {
                                    @Override
                                    public void onSuccess() {
                                        succeeded.set(true);
                                        callbackCompleted.countDown();
                                    }

                                    @Override
                                    public void onError(Exception exception) {
                                        callbackError.set(exception);
                                        callbackCompleted.countDown();
                                    }
                                }
                        );

                        holder.start();

                        try {
                            if (!monitorHeld.await(
                                    CALLBACK_TIMEOUT_SECONDS,
                                    TimeUnit.SECONDS)) {
                                throw new AssertionError(
                                        "Session monitor was not acquired."
                                );
                            }
                        } catch (InterruptedException exception) {
                            Thread.currentThread().interrupt();
                            throw new AssertionError(exception);
                        }
                    });

            // Verify the main thread reached the session-state
            // read and is blocked by the test-controlled monitor.
            Thread mainThread =
                    android.os.Looper.getMainLooper().getThread();

            long deadline =
                    android.os.SystemClock.elapsedRealtime() + 10000L;

            boolean observedBlockedRead = false;

            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                if (mainThread.getState() == Thread.State.BLOCKED) {
                    for (StackTraceElement frame : mainThread.getStackTrace()) {
                        if (frame.getClassName().equals(
                                "com.safekey.app.session.logic.VaultSessionManager")
                                && frame.getMethodName().equals("getState")) {
                            observedBlockedRead = true;
                            break;
                        }
                    }
                }

                if (observedBlockedRead) {
                    break;
                }

                Thread.sleep(10);
            }

            assertTrue(
                    "Readiness did not block at the session-state read.",
                    observedBlockedRead
            );

        } finally {
            allowTransition.countDown();
            holder.join(
                    TimeUnit.SECONDS.toMillis(CALLBACK_TIMEOUT_SECONDS)
            );
        }

        assertFalse("Session worker did not finish.", holder.isAlive());
        assertNull("Session transition failed.", workerError.get());

        assertTrue(
                "Readiness callback did not finish.",
                callbackCompleted.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertFalse(
                "Stale readiness callback must not succeed.",
                succeeded.get()
        );

        assertNotNull(
                "Stale readiness must return an error.",
                callbackError.get()
        );

        awaitAuthenticationReady();
    }
    @Test
    public void application_initializesBothVaultCoordinators() {
        assertNotNull(
                application.getSecureVaultCoordinator()
        );

        assertNotNull(
                application.getDecoyVaultCoordinator()
        );
    }

    @Test
    public void lockedSession_hasNoActiveVault() {
        assertEquals(
                SessionState.LOCKED,
                SafeKeySession.getState()
        );

        assertEquals(
                SafeKeyApplication.ActiveVault.NONE,
                application.getActiveVault()
        );
    }

    @Test
    public void lockedSession_cannotAccessVaultOperations() {
        assertThrows(
                IllegalStateException.class,
                () -> application.getActiveVaultOperations()
        );
    }

    @Test
    public void lockedSession_cannotActivateRealVault() {
        assertThrows(
                IllegalStateException.class,
                () -> application.activateRealVault()
        );
    }

    @Test
    public void lockedSession_cannotActivateDecoyVault() {
        assertThrows(
                IllegalStateException.class,
                () -> application.activateDecoyVault()
        );
    }

    @Test
    public void sessionLock_closesBothVaultConnections()
            throws Exception {

        // Exercise the session cleanup transition.
        SafeKeySession.unlockAfterAuthentication();
        SafeKeySession.lock();

        awaitAuthenticationReady();

        assertEquals(
                SessionState.LOCKED,
                SafeKeySession.getState()
        );

        assertEquals(
                SafeKeyApplication.ActiveVault.NONE,
                application.getActiveVault()
        );

        assertFalse(
                application
                        .getSecureVaultCoordinator()
                        .isVaultOpen()
        );

        assertFalse(
                application
                        .getDecoyVaultCoordinator()
                        .isDecoyVaultOpen()
        );
    }

    @Test
    public void unlockedSession_cannotPrepareNewAuthentication()
            throws Exception {

        SafeKeySession.unlockAfterAuthentication();

        CountDownLatch completed =
                new CountDownLatch(1);

        AtomicReference<Exception> error =
                new AtomicReference<>();

        application.prepareForVaultAuthentication(
                new VaultDataService.SimpleCallback() {

                    @Override
                    public void onSuccess() {
                        completed.countDown();
                    }

                    @Override
                    public void onError(Exception exception) {
                        error.set(exception);
                        completed.countDown();
                    }
                }
        );

        assertTrue(
                completed.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertNotNull(error.get());

        SafeKeySession.lock();
        awaitAuthenticationReady();
    }

    private void awaitAuthenticationReady()
            throws Exception {

        CountDownLatch completed =
                new CountDownLatch(1);

        AtomicReference<Exception> error =
                new AtomicReference<>();

        application.prepareForVaultAuthentication(
                new VaultDataService.SimpleCallback() {

                    @Override
                    public void onSuccess() {
                        completed.countDown();
                    }

                    @Override
                    public void onError(Exception exception) {
                        error.set(exception);
                        completed.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for vault cleanup.",
                completed.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertNull(
                "Vault cleanup must complete successfully.",
                error.get()
        );
    }
}

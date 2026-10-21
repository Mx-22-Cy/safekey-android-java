
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

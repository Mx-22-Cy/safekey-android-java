package com.safekey.app.security.totp;

import static org.junit.Assert.*;

import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.session.SafeKeySession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Dedicated disposable emulator. Existing app data is retained by this fixture. */
@RunWith(AndroidJUnit4.class)
public class TotpEnrollmentCoordinatorInstrumentedTest {
    private static final String TEST_MASTER = "T27DisposableMasterPassword123!";
    private SafeKeyApplication application;
    private TotpEnrollmentCoordinator coordinator;

    @Before
    public void setUp() throws Exception {
        application = (SafeKeyApplication) InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
        long deadline = SystemClock.elapsedRealtime() + 15_000L;
        while (!application.isStartupRuntimeAvailable() && SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(100L);
        }
        assertTrue("SafeKey runtime did not start", application.isStartupRuntimeAvailable());
        coordinator = application.getTotpEnrollmentCoordinator();
        coordinator.cancelPending();
        authenticateRealVault();
    }

    @After
    public void tearDown() {
        if (coordinator != null) {
            coordinator.cancelPending();
        }
        SafeKeySession.lock();
        if (application != null) {
            application.registerSessionCleanup();
        }
    }

    @Test
    public void realSessionCanPrepareAndReuseOneSetupWithoutEnablingTotp() throws Exception {
        SetupCapture capture = begin(TEST_MASTER);
        assertNull(capture.error.get());
        TotpEnrollmentCoordinator.Setup setup = capture.setup.get();
        assertNotNull(setup);
        assertSame(setup, coordinator.getPendingSetup());
        char[] first = setup.copyBase32Secret();
        char[] second = setup.copyBase32Secret();
        try {
            assertEquals(32, first.length);
            assertArrayEquals(first, second);
            assertTrue(setup.getAuthenticatorUri().startsWith("otpauth://totp/SafeKey:Vault?"));
            assertEquals(5, setup.getRemainingAttempts());
            long remaining = setup.getRemainingMillis();
            assertTrue(remaining > 0L && remaining <= 300_000L);
            long deadline = setup.getExpiresAtElapsedRealtimeMillis();
            assertTrue(deadline > SystemClock.elapsedRealtime());
            assertEquals(deadline, coordinator.getPendingSetup().getExpiresAtElapsedRealtimeMillis());
        } finally {
            Arrays.fill(first, '\0');
            Arrays.fill(second, '\0');
            setup.close();
        }
        assertFalse(new TotpSecretStore(application).isConfigured());
    }

    @Test
    public void wrongMasterPasswordCannotRevealSetupData() throws Exception {
        SetupCapture capture = begin("IncorrectDisposableMaster456!");
        assertNull(capture.setup.get());
        assertNotNull(capture.error.get());
        assertNull(coordinator.getPendingSetup());
        assertFalse(new TotpSecretStore(application).isConfigured());
    }

    @Test
    public void lockedSessionCannotBeginEnrollment() {
        SafeKeySession.lock();
        AtomicReference<RuntimeException> failure = new AtomicReference<>();
        char[] password = TEST_MASTER.toCharArray();
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                try {
                    coordinator.begin(password, new SetupCapture());
                } catch (RuntimeException error) {
                    failure.set(error);
                }
            });
        } finally {
            Arrays.fill(password, '\0');
        }
        assertTrue(failure.get() instanceof TotpEnrollmentCoordinator.SessionInvalidException);
        assertNull(coordinator.getPendingSetup());
    }

    @Test
    public void sessionLockCancelsPreparedSetup() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = begin(TEST_MASTER).setup.get();
        assertNotNull(setup);
        SafeKeySession.lock();
        assertFalse(setup.isActive());
        assertNull(coordinator.getPendingSetup());
        try {
            setup.copyBase32Secret();
            fail("Locked Settings exposed its enrollment key.");
        } catch (TotpEnrollmentCoordinator.SessionInvalidException expected) {
            assertFalse(new TotpSecretStore(application).isConfigured());
        }
    }

    @Test
    public void reauthenticationInvalidatesTheOriginalSetup() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = begin(TEST_MASTER).setup.get();
        assertNotNull(setup);
        InstrumentationRegistry.getInstrumentation().runOnMainSync(
                SafeKeySession::unlockAfterAuthentication);
        try {
            setup.copyBase32Secret();
            fail("Reauthentication retained the previous enrollment authorization.");
        } catch (TotpEnrollmentCoordinator.SessionInvalidException expected) {
            assertNull(coordinator.getPendingSetup());
            assertFalse(new TotpSecretStore(application).isConfigured());
        }
    }

    private SetupCapture begin(String master) throws Exception {
        SetupCapture capture = new SetupCapture();
        char[] password = master.toCharArray();
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(
                    () -> coordinator.begin(password, capture));
        } finally {
            Arrays.fill(password, '\0');
        }
        assertTrue("Enrollment callback timed out", capture.done.await(30, TimeUnit.SECONDS));
        return capture;
    }

    private void authenticateRealVault() throws Exception {
        SafeKeySession.lock();
        CountDownLatch ready = new CountDownLatch(1);
        AtomicReference<Exception> readinessError = new AtomicReference<>();
        application.prepareForVaultAuthentication(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { ready.countDown(); }
            @Override public void onError(Exception error) {
                readinessError.set(error);
                ready.countDown();
            }
        });
        assertTrue("Previous vault cleanup timed out", ready.await(30, TimeUnit.SECONDS));
        if (readinessError.get() != null) {
            throw readinessError.get();
        }
        SecureVaultCoordinator vault = application.getSecureVaultCoordinator();
        AtomicReference<VaultUnlockFlow.Request> request = new AtomicReference<>();
        AtomicReference<Exception> error = new AtomicReference<>();
        CountDownLatch opened = new CountDownLatch(1);
        VaultDataService.SimpleCallback completion = new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() {
                try {
                    if (request.get() == null || !request.get().claimSession()) {
                        throw new IllegalStateException("Unable to claim the authenticated REAL vault.");
                    }
                    SafeKeySession.unlockAfterAuthentication();
                    application.activateRealVault();
                } catch (Exception failure) {
                    error.set(failure);
                } finally {
                    opened.countDown();
                }
            }
            @Override public void onError(Exception failure) {
                error.set(failure);
                opened.countDown();
            }
        };
        char[] password = TEST_MASTER.toCharArray();
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                if (vault.hasVault()) {
                    request.set(vault.unlockVault(password, new SecureVaultCoordinator.TotpUnlockCallback() {
                        @Override public void onSuccess() { completion.onSuccess(); }
                        @Override public void onError(Exception failure) { completion.onError(failure); }
                        @Override public void onTotpRequired(VaultUnlockFlow.Request pending) {
                            completion.onError(new IllegalStateException(
                                    "Use a disposable test vault with TOTP unconfigured."));
                        }
                    }));
                } else {
                    request.set(vault.createVaultForEnrollment(password,
                            MasterPasswordCheckStatus.CHECKED, completion));
                }
            });
            assertTrue("REAL vault authentication timed out", opened.await(30, TimeUnit.SECONDS));
            if (error.get() != null) {
                throw new AssertionError("Use a disposable vault with the expected test password.", error.get());
            }
            assertEquals(SafeKeyApplication.ActiveVault.REAL, application.getActiveVault());
        } finally {
            Arrays.fill(password, '\0');
            if (request.get() != null) {
                InstrumentationRegistry.getInstrumentation().runOnMainSync(request.get()::close);
            }
        }
    }

    private static final class SetupCapture implements TotpEnrollmentCoordinator.SetupCallback {
        private final AtomicReference<TotpEnrollmentCoordinator.Setup> setup = new AtomicReference<>();
        private final AtomicReference<Exception> error = new AtomicReference<>();
        private final CountDownLatch done = new CountDownLatch(1);
        @Override public void onReady(TotpEnrollmentCoordinator.Setup setup) {
            this.setup.set(setup);
            done.countDown();
        }
        @Override public void onError(Exception error) {
            this.error.set(error);
            done.countDown();
        }
    }
}

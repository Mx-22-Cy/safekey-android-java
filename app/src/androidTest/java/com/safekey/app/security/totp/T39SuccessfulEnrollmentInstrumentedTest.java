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
public class T39SuccessfulEnrollmentInstrumentedTest {
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

    /**
     * One-time destructive enrollment test. Run only on a fresh disposable emulator.
     * This enables TOTP on the fixture vault and intentionally does not erase it.
     */
    @Test
    public void validTotpCodeEnablesRealVaultProtection() throws Exception {
        assertFalse("Test vault already has TOTP; use a fresh disposable emulator",
                new TotpSecretStore(application).isConfigured());
        SetupCapture capture = begin(TEST_MASTER);
        assertNull("TOTP preparation failed", capture.error.get());
        TotpEnrollmentCoordinator.Setup setup = capture.setup.get();
        assertNotNull("No TOTP setup returned", setup);
        assertTrue("TOTP setup not ready", setup.isReady());

        char[] encoded = setup.copyBase32Secret();
        byte[] secret = null;
        char[] code = null;
        try {
            secret = decodeBase32(encoded);
            assertEquals(20, secret.length);
            String generated = TotpGenerator.generate(secret, System.currentTimeMillis() / 1000L);
            code = generated.toCharArray();
            final char[] suppliedCode = code;
            CountDownLatch confirmed = new CountDownLatch(1);
            AtomicReference<TotpEnrollmentService.Confirmation> result = new AtomicReference<>();
            AtomicReference<Exception> failure = new AtomicReference<>();
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() ->
                    setup.confirm(suppliedCode, new TotpEnrollmentCoordinator.ConfirmationCallback() {
                        @Override public void onResult(
                                TotpEnrollmentService.Confirmation confirmation, int attempts) {
                            result.set(confirmation);
                            confirmed.countDown();
                        }
                        @Override public void onError(Exception error) {
                            failure.set(error);
                            confirmed.countDown();
                        }
                    }));
            assertTrue("TOTP confirmation timed out", confirmed.await(30, TimeUnit.SECONDS));
            assertNull("TOTP confirmation returned an error", failure.get());
            assertEquals(TotpEnrollmentService.Confirmation.ENABLED, result.get());
            assertTrue("TOTP was not stored", new TotpSecretStore(application).isConfigured());
        } finally {
            Arrays.fill(encoded, '\0');
            if (secret != null) Arrays.fill(secret, (byte) 0);
            if (code != null) Arrays.fill(code, '\0');
            setup.close();
        }
    }

    private static byte[] decodeBase32(char[] encoded) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : encoded) {
            int value;
            if (c >= 'A' && c <= 'Z') value = c - 'A';
            else if (c >= '2' && c <= '7') value = c - '2' + 26;
            else throw new IllegalArgumentException("Invalid Base32 test secret");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.write((buffer >>> bits) & 255);
            }
        }
        return out.toByteArray();
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

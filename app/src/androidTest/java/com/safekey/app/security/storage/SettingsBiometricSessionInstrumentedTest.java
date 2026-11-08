package com.safekey.app.security.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.os.SystemClock;

import androidx.fragment.app.FragmentActivity;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.biometric.BiometricAuthenticator;
import com.safekey.app.security.biometric.BiometricVaultKeyManager;
import com.safekey.app.security.keystore.BiometricKeyEnvelopeStore;
import com.safekey.app.session.SafeKeySession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Runs on a disposable AVD with the T27/T38 test vault or fresh app data.
 * A controlled fingerprint result uses the real coordinator, wrapping, and envelope store.
 */
@RunWith(AndroidJUnit4.class)
public class SettingsBiometricSessionInstrumentedTest {

    private static final String TEST_MASTER = "T27DisposableMasterPassword123!";
    private static final String TEST_DECOY = "T27DisposableDecoyPassword456!";
    private static final String SESSION_ENDED = "The REAL vault session is no longer active.";
    private static final long CALLBACK_TIMEOUT_SECONDS = 60;

    private final CountDownLatch promptStarted = new CountDownLatch(1);
    // The prompt is created and completed on the main thread.
    private Consumer<Cipher> fingerprintSuccess;
    private Consumer<String> fingerprintError;
    private SafeKeyApplication application;
    private SecureVaultCoordinator coordinator;
    private BiometricKeyEnvelopeStore envelopeStore;
    private boolean ownsTestEnvelope;

    @Before
    public void setUp() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        application = (SafeKeyApplication) context.getApplicationContext();
        long deadline = SystemClock.elapsedRealtime() + TimeUnit.SECONDS.toMillis(15);
        while (!application.isStartupRuntimeAvailable()
                && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(50);
        }
        assertTrue("SafeKey runtime is unavailable", application.isStartupRuntimeAvailable());
        envelopeStore = new BiometricKeyEnvelopeStore(context);
        assertFalse("Use a disposable test vault without biometric enrollment",
                envelopeStore.hasEnvelope());
        ownsTestEnvelope = true;

        application.registerSessionCleanup();
        onMain(SafeKeySession::lock);
        coordinator = new SecureVaultCoordinator(context, null, null, this::controlledManager);
    }

    @After
    public void tearDown() throws Exception {
        try {
            if (coordinator != null) {
                onMain(() -> {
                    if (fingerprintError != null) {
                        fingerprintError.accept("Test prompt cancelled.");
                        fingerprintError = null;
                        fingerprintSuccess = null;
                    }
                    SafeKeySession.lock();
                });
                awaitSuccess(application::prepareForVaultAuthentication);
            }
        } finally {
            if (coordinator != null) {
                coordinator.shutdown();
            }
            if (ownsTestEnvelope) {
                envelopeStore.clear();
            }
        }
    }

    @Test
    public void lockBeforePromptPreventsEnrollment() throws Exception {
        try (ActivityScenario<SignInActivity> scenario = launchHost()) {
            openRealVault();
            SetupResult result = new SetupResult();
            scenario.onActivity(activity -> {
                requestEnrollment(activity, result);
                // The posted prompt cannot run until this main-thread action returns.
                SafeKeySession.lock();
            });
            result.assertSessionEnded();
            assertEquals("A stale request started the fingerprint prompt", 1L,
                    promptStarted.getCount());
            assertFalse(envelopeStore.hasEnvelope());
        }
    }

    @Test
    public void lateFingerprintAfterLockCannotSaveEnvelope() throws Exception {
        assertLateEnrollmentRejected(() -> {});
    }

    @Test
    public void lateFingerprintAfterNewRealAuthenticationCannotSaveEnvelope() throws Exception {
        assertLateEnrollmentRejected(this::openRealVault);
    }

    @Test
    public void lateFingerprintAfterSwitchToDecoyCannotSaveEnvelope() throws Exception {
        assertLateEnrollmentRejected(this::openDecoyVault);
    }

    @Test
    public void decoySessionCannotRequestBiometricChanges() throws Exception {
        try (ActivityScenario<SignInActivity> scenario = launchHost()) {
            openRealVault();
            onMain(SafeKeySession::lock);
            openDecoyVault();
            scenario.onActivity(activity -> {
                assertThrows(IllegalStateException.class,
                        () -> requestEnrollment(activity, new SetupResult()));
                assertThrows(IllegalStateException.class,
                        () -> coordinator.disableBiometricUnlockForRealSession(
                                activity, new SimpleResult()));
            });
            assertEquals(1L, promptStarted.getCount());
            assertFalse(envelopeStore.hasEnvelope());
        }
    }

    @Test
    public void queuedDisableAfterLockPreservesEnvelope() throws Exception {
        try (ActivityScenario<SignInActivity> scenario = launchHost()) {
            openRealVault();
            SetupResult enrollment = startPrompt(scenario);
            deliverFingerprintSuccess();
            enrollment.await();
            assertTrue("Current REAL session did not enroll biometrics: " + enrollment.error,
                    enrollment.enabled);
            assertTrue(envelopeStore.hasEnvelope());

            SimpleResult disable = new SimpleResult();
            scenario.onActivity(activity -> {
                coordinator.disableBiometricUnlockForRealSession(activity, disable);
                SafeKeySession.lock();
            });
            disable.await();
            assertNotNull("Stale disable was reported as a success", disable.error);
            assertEquals(SESSION_ENDED, disable.error.getMessage());
            assertTrue("Stale disable removed the stored biometric envelope",
                    envelopeStore.hasEnvelope());
        }
    }

    private void assertLateEnrollmentRejected(VaultTransition afterLock) throws Exception {
        try (ActivityScenario<SignInActivity> scenario = launchHost()) {
            openRealVault();
            SetupResult result = startPrompt(scenario);
            onMain(SafeKeySession::lock);
            afterLock.run();
            deliverFingerprintSuccess();
            result.assertSessionEnded();
            assertFalse("Late fingerprint result saved a biometric envelope",
                    envelopeStore.hasEnvelope());
        }
    }

    private void openRealVault() throws Exception {
        awaitSuccess(application::prepareForVaultAuthentication);
        SecureVaultCoordinator real = application.getSecureVaultCoordinator();
        char[] master = TEST_MASTER.toCharArray();
        try {
            if (real.hasVault()) {
                awaitSuccess(callback -> real.unlockVault(master, callback));
            } else {
                awaitSuccess(callback -> real.createVault(master, callback));
            }
        } finally {
            Arrays.fill(master, '\0');
        }
        onMain(() -> {
            SafeKeySession.unlockAfterAuthentication();
            application.activateRealVault();
        });
        assertEquals(SafeKeyApplication.ActiveVault.REAL, application.getActiveVault());
    }

    private void openDecoyVault() throws Exception {
        awaitSuccess(application::prepareForVaultAuthentication);
        DecoyVaultCoordinator decoy = application.getDecoyVaultCoordinator();
        char[] password = TEST_DECOY.toCharArray();
        try {
            if (!decoy.hasDecoyVault()) {
                awaitSuccess(callback -> decoy.createDecoyVault(password, callback));
                awaitSuccess(decoy::closeDecoyVault);
            }
            awaitSuccess(callback -> decoy.unlockDecoyVault(password, callback));
        } finally {
            Arrays.fill(password, '\0');
        }
        onMain(() -> {
            SafeKeySession.unlockAfterAuthentication();
            application.activateDecoyVault();
        });
        assertEquals(SafeKeyApplication.ActiveVault.DECOY, application.getActiveVault());
    }

    private SetupResult startPrompt(ActivityScenario<SignInActivity> scenario) throws Exception {
        SetupResult result = new SetupResult();
        scenario.onActivity(activity -> requestEnrollment(activity, result));
        assertTrue("Fingerprint prompt did not start: " + result.error,
                promptStarted.await(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        return result;
    }

    private void requestEnrollment(FragmentActivity activity, SetupResult result) {
        char[] master = TEST_MASTER.toCharArray();
        try {
            coordinator.enableBiometricUnlockForRealSession(
                    activity, master, "Enable biometric unlock", "Confirm your identity", result);
        } finally {
            Arrays.fill(master, '\0');
        }
    }

    private BiometricVaultKeyManager controlledManager(FragmentActivity activity) {
        return new BiometricVaultKeyManager(activity) {
            @Override
            public BiometricAuthenticator.Availability getAvailability() {
                return BiometricAuthenticator.Availability.AVAILABLE;
            }

            @Override
            protected void authenticateForEnrollment(
                    String title,
                    String subtitle,
                    Consumer<Cipher> onSuccess,
                    Consumer<String> onError,
                    Runnable onFailed
            ) {
                fingerprintSuccess = onSuccess;
                fingerprintError = onError;
                promptStarted.countDown();
            }
        };
    }

    private void deliverFingerprintSuccess() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyGenerator.generateKey(), new GCMParameterSpec(128, iv));
        onMain(() -> {
            Consumer<Cipher> callback = fingerprintSuccess;
            assertNotNull("No pending fingerprint prompt", callback);
            fingerprintSuccess = null;
            fingerprintError = null;
            callback.accept(cipher);
        });
    }

    private static ActivityScenario<SignInActivity> launchHost() {
        return ActivityScenario.launch(SignInActivity.class);
    }

    private static void onMain(Runnable action) {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(action);
    }

    private static void awaitSuccess(AsyncOperation operation) throws Exception {
        SimpleResult result = new SimpleResult();
        operation.start(result);
        result.await();
        if (result.error != null) {
            throw result.error;
        }
    }

    private interface VaultTransition {
        void run() throws Exception;
    }

    private interface AsyncOperation {
        void start(VaultDataService.SimpleCallback callback);
    }

    private static final class SimpleResult implements VaultDataService.SimpleCallback {
        private final CountDownLatch done = new CountDownLatch(1);
        private Exception error;

        @Override public void onSuccess() {
            done.countDown();
        }

        @Override public void onError(Exception exception) {
            error = exception;
            done.countDown();
        }

        private void await() throws InterruptedException {
            assertTrue("Timed out waiting for vault operation",
                    done.await(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }
    }

    private static final class SetupResult implements SecureVaultCoordinator.BiometricSetupCallback {
        private final CountDownLatch done = new CountDownLatch(1);
        private boolean enabled;
        private String error;

        @Override public void onEnabled() {
            enabled = true;
            done.countDown();
        }

        @Override public void onError(String message) {
            error = message;
            done.countDown();
        }

        @Override public void onFailed() {
            // Only terminal results count down the latch.
        }

        private void await() throws InterruptedException {
            assertTrue("Timed out waiting for biometric enrollment",
                    done.await(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }

        private void assertSessionEnded() throws InterruptedException {
            await();
            assertFalse("Stale biometric enrollment was reported as successful", enabled);
            assertEquals(SESSION_ENDED, error);
        }
    }
}

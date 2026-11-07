package com.safekey.app.securityui;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.content.Intent;
import android.widget.EditText;
import android.os.SystemClock;
import android.view.View;
import android.view.WindowManager;
import android.widget.TextView;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * T39 presentation-only checks before authenticated enrollment integration.
 * Run on a dedicated disposable emulator. Does not clear existing vault data.
 *
 * After backend integration, replace the pre-enrollment disabled-state tests
 * with tests that exercise real, session-bound pending enrollment.
 */
@RunWith(AndroidJUnit4.class)
public class T39TotpUiFoundationInstrumentedTest {

    private static final String TEST_MASTER = "T27DisposableMasterPassword123!";
    private static final String TEST_DECOY = "T27DisposableDecoyPassword456!";

    @Test
    public void setupRejectsLockedSession() {
        assertLockedSessionCloses(SetupTotpActivity.class);
    }

    @Test
    public void verifyRejectsLockedSession() {
        assertLockedSessionCloses(VerifyTotpActivity.class);
    }

    @Test
    public void setupScreenshotProtectionAndBackendDependentControls() throws Exception {
        authenticateRealVaultForUiTest();
        try (ActivityScenario<SetupTotpActivity> scenario =
                     ActivityScenario.launch(SetupTotpActivity.class)) {
            scenario.onActivity(activity -> {
                assertSecureWindow(activity.getWindow().getAttributes().flags);
                assertFalse(activity.findViewById(R.id.buttonToggleTotpKey).isEnabled());
                assertFalse(activity.findViewById(R.id.buttonCopyTotpKey).isEnabled());
                assertFalse(activity.findViewById(R.id.buttonContinueTotpSetup).isEnabled());
                assertEquals(View.GONE,
                        activity.findViewById(R.id.groupTotpManualKey).getVisibility());
                assertEquals(View.GONE,
                        activity.findViewById(R.id.imageTotpQrCode).getVisibility());
            });
        } finally {
            cleanupSession();
        }
    }

    @Test
    public void verifyScreenshotProtectionAndUnverifiedCodeCannotEnable() throws Exception {
        authenticateRealVaultForUiTest();
        try (ActivityScenario<VerifyTotpActivity> scenario =
                     ActivityScenario.launch(VerifyTotpActivity.class)) {
            scenario.onActivity(activity -> {
                assertSecureWindow(activity.getWindow().getAttributes().flags);
                android.widget.EditText code = activity.findViewById(R.id.editVerifyTotpCode);
                View enable = activity.findViewById(R.id.buttonEnableTotpProtection);
                assertFalse(enable.isEnabled());
                code.setText("123456");
                assertFalse("Six digits alone must not enable enrollment", enable.isEnabled());
            });
        } finally {
            cleanupSession();
        }
    }

    @Test
    public void setupCancelClosesScreen() throws Exception {
        authenticateRealVaultForUiTest();
        try (ActivityScenario<SetupTotpActivity> scenario =
                     ActivityScenario.launch(SetupTotpActivity.class)) {
            scenario.onActivity(activity -> {
                assertTrue("Cancel click must be accepted",
                        activity.findViewById(R.id.buttonCancelTotpSetup).performClick());
                assertTrue("Cancel must request Activity finish", activity.isFinishing());
            });
            assertEventuallyDestroyed(scenario);
        } finally {
            cleanupSession();
        }
    }

    @Test
    public void verifyBackClosesScreen() throws Exception {
        authenticateRealVaultForUiTest();
        try (ActivityScenario<VerifyTotpActivity> scenario =
                     ActivityScenario.launch(VerifyTotpActivity.class)) {
            scenario.onActivity(activity -> {
                assertTrue("Back click must be accepted",
                        activity.findViewById(R.id.buttonVerifyTotpBack).performClick());
                assertTrue("Back must request Activity finish", activity.isFinishing());
            });
            assertEventuallyDestroyed(scenario);
        } finally {
            cleanupSession();
        }
    }


    @Test
    public void setupRejectsActiveDecoyVault() throws Exception {
        assertActiveDecoyCannotOpen(SetupTotpActivity.class);
    }

    @Test
    public void verifyRejectsActiveDecoyVault() throws Exception {
        assertActiveDecoyCannotOpen(VerifyTotpActivity.class);
    }

    @Test
    public void setupRejectsUnlockedWithoutActiveRealVault() throws Exception {
        assertUnlockedWithoutRealVaultCannotOpen(SetupTotpActivity.class);
    }

    @Test
    public void verifyRejectsUnlockedWithoutActiveRealVault() throws Exception {
        assertUnlockedWithoutRealVaultCannotOpen(VerifyTotpActivity.class);
    }

    @Test
    public void verifyClearsCodeWhenStopped() throws Exception {
        authenticateRealVaultForUiTest();
        try (ActivityScenario<VerifyTotpActivity> scenario =
                     ActivityScenario.launch(VerifyTotpActivity.class)) {
            AtomicReference<EditText> codeReference = new AtomicReference<>();
            scenario.onActivity(activity -> {
                EditText code = activity.findViewById(R.id.editVerifyTotpCode);
                code.setText("123456");
                codeReference.set(code);
                assertEquals("123456", code.getText().toString());
            });
            // Moving to CREATED invokes onStop(). Keep the view reference because
            // protected-session cleanup may also finish the Activity.
            scenario.moveToState(Lifecycle.State.CREATED);
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() ->
                    assertEquals("Verification code must be cleared on stop",
                            "", codeReference.get().getText().toString()));
        } finally {
            cleanupSession();
        }
    }

    /** A pending enrollment must survive Setup and Verify recreation without rotating its seed. */
    @Test
    public void pendingEnrollmentSurvivesSetupAndVerifyRecreation() throws Exception {
        authenticateRealVaultForUiTest();
        com.safekey.app.security.totp.TotpEnrollmentCoordinator coordinator =
                app().getTotpEnrollmentCoordinator();
        CountDownLatch prepared = new CountDownLatch(1);
        AtomicReference<Exception> preparationError = new AtomicReference<>();
        AtomicReference<com.safekey.app.security.totp.TotpEnrollmentCoordinator.Setup> created =
                new AtomicReference<>();
        char[] password = TEST_MASTER.toCharArray();
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                created.set(coordinator.begin(password,
                        new com.safekey.app.security.totp.TotpEnrollmentCoordinator.SetupCallback() {
                            @Override public void onReady(
                                    com.safekey.app.security.totp.TotpEnrollmentCoordinator.Setup setup) {
                                prepared.countDown();
                            }
                            @Override public void onError(Exception error) {
                                preparationError.set(error);
                                prepared.countDown();
                            }
                        }));
            });
            assertTrue("TOTP preparation timed out", prepared.await(20, TimeUnit.SECONDS));
            if (preparationError.get() != null) { throw preparationError.get(); }
            com.safekey.app.security.totp.TotpEnrollmentCoordinator.Setup pending = created.get();
            assertTrue("Pending enrollment should be ready", pending != null && pending.isReady());
            String originalUri = pending.getAuthenticatorUri();
            try (ActivityScenario<SetupTotpActivity> setupScenario =
                         ActivityScenario.launch(SetupTotpActivity.class)) {
                setupScenario.onActivity(activity -> {
                    assertSecureWindow(activity.getWindow().getAttributes().flags);
                    assertTrue("QR must be visible", activity.findViewById(R.id.imageTotpQrCode)
                            .getVisibility() == View.VISIBLE);
                    assertTrue("Continue must be enabled", activity.findViewById(
                            R.id.buttonContinueTotpSetup).isEnabled());
                });
                setupScenario.recreate();
                setupScenario.onActivity(activity -> {
                    assertTrue("QR must survive Setup recreation", activity.findViewById(
                            R.id.imageTotpQrCode).getVisibility() == View.VISIBLE);
                    assertTrue("Continue must survive Setup recreation", activity.findViewById(
                            R.id.buttonContinueTotpSetup).isEnabled());
                });
                assertEquals("Recreation must not rotate TOTP secret", originalUri,
                        coordinator.getPendingSetup().getAuthenticatorUri());
            }
            try (ActivityScenario<VerifyTotpActivity> verifyScenario =
                         ActivityScenario.launch(VerifyTotpActivity.class)) {
                verifyScenario.onActivity(activity -> {
                    assertSecureWindow(activity.getWindow().getAttributes().flags);
                    EditText code = activity.findViewById(R.id.editVerifyTotpCode);
                    code.setText("123456");
                    assertTrue("Verify should accept formatted code with pending setup",
                            activity.findViewById(R.id.buttonEnableTotpProtection).isEnabled());
                });
                verifyScenario.recreate();
                verifyScenario.onActivity(activity -> {
                    assertSecureWindow(activity.getWindow().getAttributes().flags);
                    assertEquals("A recreated Verify screen must not restore the typed code", "",
                            ((EditText) activity.findViewById(R.id.editVerifyTotpCode))
                                    .getText().toString());
                });
                assertEquals("Verify recreation must not rotate TOTP secret", originalUri,
                        coordinator.getPendingSetup().getAuthenticatorUri());
            }
        } finally {
            Arrays.fill(password, '\0');
            InstrumentationRegistry.getInstrumentation().runOnMainSync(coordinator::cancelPending);
            cleanupSession();
        }
    }

    private void assertUnlockedWithoutRealVaultCannotOpen(
            Class<? extends Activity> activityClass) throws Exception {
        // Begin with the REAL vault closed. An unlocked session flag alone
        // must never be accepted as permission for REAL-only screens.
        SafeKeySession.lock();
        awaitAuthenticationReadiness();
        InstrumentationRegistry.getInstrumentation().runOnMainSync(
                SafeKeySession::unlockAfterAuthentication);
        try {
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertTrue("A REAL vault must not be active",
                    app().getActiveVault() != SafeKeyApplication.ActiveVault.REAL);
            Intent intent = new Intent(app(), activityClass);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try (ActivityScenario<? extends Activity> scenario =
                         ActivityScenario.launch(intent)) {
                assertEventuallyDestroyed(scenario);
            }
        } finally {
            cleanupSession();
        }
    }

    private void assertActiveDecoyCannotOpen(
            Class<? extends Activity> activityClass) throws Exception {
        authenticateDecoyVaultForUiTest();
        try {
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertEquals(SafeKeyApplication.ActiveVault.DECOY, app().getActiveVault());
            Intent intent = new Intent(app(), activityClass);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try (ActivityScenario<? extends Activity> scenario =
                         ActivityScenario.launch(intent)) {
                assertEventuallyDestroyed(scenario);
            }
        } finally {
            cleanupSession();
        }
    }

    private interface DecoyOperation {
        void start(VaultDataService.SimpleCallback callback);
    }

    private static void awaitDecoyOperation(DecoyOperation operation) throws Exception {
        CountDownLatch completed = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        operation.start(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { completed.countDown(); }
            @Override public void onError(Exception exception) {
                error.set(exception);
                completed.countDown();
            }
        });
        assertTrue("Decoy operation timed out", completed.await(25, TimeUnit.SECONDS));
        if (error.get() != null) { throw error.get(); }
    }

    private void authenticateDecoyVaultForUiTest() throws Exception {
        authenticateRealVaultForUiTest();
        SafeKeySession.lock();
        awaitAuthenticationReadiness();
        DecoyVaultCoordinator coordinator = app().getDecoyVaultCoordinator();
        char[] password = TEST_DECOY.toCharArray();
        try {
            if (!coordinator.hasDecoyVault()) {
                awaitDecoyOperation(callback -> coordinator.createDecoyVault(password, callback));
                awaitDecoyOperation(coordinator::closeDecoyVault);
            }
            awaitDecoyOperation(callback -> coordinator.unlockDecoyVault(password, callback));
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                SafeKeySession.unlockAfterAuthentication();
                app().activateDecoyVault();
            });
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void awaitAuthenticationReadiness() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        app().prepareForVaultAuthentication(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { ready.countDown(); }
            @Override public void onError(Exception exception) {
                error.set(exception);
                ready.countDown();
            }
        });
        assertTrue("Previous vault cleanup timed out", ready.await(20, TimeUnit.SECONDS));
        if (error.get() != null) { throw error.get(); }
    }

    private static void assertEventuallyDestroyed(ActivityScenario<?> scenario)
            throws InterruptedException {
        long deadline = SystemClock.elapsedRealtime() + 5_000L;
        while (scenario.getState() != Lifecycle.State.DESTROYED
                && SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(50L);
        }
        assertEquals("Activity should be destroyed after navigation",
                Lifecycle.State.DESTROYED, scenario.getState());
    }

    private static void assertSecureWindow(int flags) {
        assertTrue("TOTP screen must prevent screenshots",
                (flags & WindowManager.LayoutParams.FLAG_SECURE) != 0);
    }

    private void assertLockedSessionCloses(Class<? extends android.app.Activity> activityClass) {
        SafeKeySession.lock();
        SafeKeyApplication app = app();
        Intent intent = new Intent(app, activityClass);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try (ActivityScenario<? extends android.app.Activity> scenario =
                     ActivityScenario.launch(intent)) {
            assertEquals(Lifecycle.State.DESTROYED, scenario.getState());
        } finally {
            cleanupSession();
        }
    }

    private static SafeKeyApplication app() {
        return (SafeKeyApplication) InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
    }

    private static void cleanupSession() {
        SafeKeySession.lock();
        app().registerSessionCleanup();
    }

    private void authenticateRealVaultForUiTest() throws Exception {
        SafeKeyApplication app = app();
        long deadline = SystemClock.elapsedRealtime() + 15_000L;
        while (!app.isStartupRuntimeAvailable()
                && SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(100L);
        }
        assertTrue("SafeKey runtime not ready", app.isStartupRuntimeAvailable());
        SafeKeySession.lock();

        CountDownLatch ready = new CountDownLatch(1);
        AtomicReference<Exception> readinessError = new AtomicReference<>();
        app.prepareForVaultAuthentication(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { ready.countDown(); }
            @Override public void onError(Exception error) {
                readinessError.set(error);
                ready.countDown();
            }
        });
        assertTrue("Previous vault cleanup timed out", ready.await(20, TimeUnit.SECONDS));
        if (readinessError.get() != null) { throw readinessError.get(); }

        SecureVaultCoordinator coordinator = app.getSecureVaultCoordinator();
        boolean alreadyEnrolled = coordinator.hasVault();
        CountDownLatch opened = new CountDownLatch(1);
        AtomicReference<Exception> openError = new AtomicReference<>();
        AtomicReference<VaultUnlockFlow.Request> requestHolder = new AtomicReference<>();
        char[] master = TEST_MASTER.toCharArray();
        try {
            VaultDataService.SimpleCallback callback = new VaultDataService.SimpleCallback() {
                @Override public void onSuccess() {
                    Runnable completeOnMain = () -> {
                        try {
                            VaultUnlockFlow.Request request = requestHolder.get();
                            if (request == null || !request.claimSession()) {
                                throw new IllegalStateException("Vault session claim failed");
                            }
                            SafeKeySession.unlockAfterAuthentication();
                            app.activateRealVault();
                        } catch (Exception error) {
                            openError.set(error);
                        } finally {
                            opened.countDown();
                        }
                    };
                    if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
                        completeOnMain.run();
                    } else {
                        InstrumentationRegistry.getInstrumentation().runOnMainSync(completeOnMain);
                    }
                }
                @Override public void onError(Exception error) {
                    openError.set(error);
                    opened.countDown();
                }
            };
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                if (alreadyEnrolled) {
                    requestHolder.set(coordinator.unlockVault(master,
                            new SecureVaultCoordinator.TotpUnlockCallback() {
                                @Override public void onSuccess() { callback.onSuccess(); }
                                @Override public void onError(Exception error) { callback.onError(error); }
                                @Override public void onTotpRequired(VaultUnlockFlow.Request request) {
                                    openError.set(new IllegalStateException(
                                            "Test vault has TOTP enabled; use a fresh disposable emulator"));
                                    opened.countDown();
                                }
                            }));
                } else {
                    requestHolder.set(coordinator.createVaultForEnrollment(
                            master, MasterPasswordCheckStatus.CHECKED, callback));
                }
            });
            assertTrue("Test vault authentication timed out", opened.await(25, TimeUnit.SECONDS));
            if (openError.get() != null) {
                throw new AssertionError("Test-only REAL vault authentication failed. "
                        + "Use a disposable emulator enrolled with the test credential.",
                        openError.get());
            }
            assertEquals(SafeKeyApplication.ActiveVault.REAL, app.getActiveVault());
        } finally {
            Arrays.fill(master, '\0');
            VaultUnlockFlow.Request request = requestHolder.get();
            if (request != null) {
                InstrumentationRegistry.getInstrumentation().runOnMainSync(request::close);
            }
        }
    }
}

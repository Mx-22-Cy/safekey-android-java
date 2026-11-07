package com.safekey.app.securityui;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Intent;
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
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.session.SafeKeySession;

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
                        VaultUnlockFlow.Request request = requestHolder.get();
                        if (request == null || !request.claimSession()) {
                            openError.set(new IllegalStateException("Vault session claim failed"));
                        } else {
                            try {
                                SafeKeySession.unlockAfterAuthentication();
                                app.activateRealVault();
                            } catch (Exception error) {
                                openError.set(error);
                            }
                        }
                    };
                    if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
                        completeOnMain.run();
                    } else {
                        InstrumentationRegistry.getInstrumentation().runOnMainSync(completeOnMain);
                    }
                    opened.countDown();
                }
                @Override public void onError(Exception error) {
                    openError.set(error);
                    opened.countDown();
                }
            };
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
            assertTrue("Test vault authentication timed out", opened.await(25, TimeUnit.SECONDS));
            if (openError.get() != null) {
                throw new AssertionError("Test-only REAL vault authentication failed. "
                        + "Use a disposable emulator enrolled with the test credential.",
                        openError.get());
            }
            assertEquals(SafeKeyApplication.ActiveVault.REAL, app.getActiveVault());
        } finally {
            Arrays.fill(master, '\0');
        }
    }
}

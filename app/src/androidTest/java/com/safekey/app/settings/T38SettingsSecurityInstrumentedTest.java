package com.safekey.app.settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.content.Intent;
import android.view.View;

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
 * T38 Settings access tests. Run ONLY on the disposable SafeKey_Test_API_35 AVD.
 * This fixture never clears existing app data. If the existing vault has another
 * master password or TOTP, it fails instead of overwriting that vault.
 */
@RunWith(AndroidJUnit4.class)
public class T38SettingsSecurityInstrumentedTest {

    private SafeKeyApplication app() {
        return (SafeKeyApplication) InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
    }

    @Test
    public void realVaultShowsRealOnlySettings() throws Exception {
        SafeKeyApplication app = app();
        try {
            authenticateRealVaultForUiTest();
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertEquals(SafeKeyApplication.ActiveVault.REAL, app.getActiveVault());
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                scenario.onActivity(activity -> {
                    assertEquals(View.VISIBLE, activity.findViewById(
                            R.id.cardSettingsEmergency).getVisibility());
                    assertEquals(View.VISIBLE, activity.findViewById(
                            R.id.rowSettingsChangePassword).getVisibility());
                });
            }
        } finally {
            SafeKeySession.lock();
            app.registerSessionCleanup();
        }
    }

    @Test
    public void decoyVaultHidesRealOnlySettings() throws Exception {
        SafeKeyApplication app = app();
        try {
            authenticateDecoyVaultForUiTest();
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertEquals(SafeKeyApplication.ActiveVault.DECOY, app.getActiveVault());
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                scenario.onActivity(activity -> {
                    assertEquals(View.GONE, activity.findViewById(
                            R.id.cardSettingsEmergency).getVisibility());
                    assertEquals(View.GONE, activity.findViewById(
                            R.id.rowSettingsChangePassword).getVisibility());
                });
            }
        } finally {
            SafeKeySession.lock();
            app.registerSessionCleanup();
        }
    }

    @Test
    public void unlockedWithNoActiveVaultCannotAccessSettings() {
        SafeKeyApplication app = app();
        SafeKeySession.unregisterSensitiveDataCleanup();
        try {
            SafeKeySession.lock();
            assertEquals(SafeKeyApplication.ActiveVault.NONE, app.getActiveVault());
            SafeKeySession.unlockAfterAuthentication();
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(new Intent(app, SettingsActivity.class)
                                 .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))) {
                assertEquals("Settings must close without an active vault",
                        Lifecycle.State.DESTROYED, scenario.getState());
            }
        } finally {
            SafeKeySession.lock();
            app.registerSessionCleanup();
        }
    }

    // Runs only on a dedicated disposable emulator. Never delete existing vault data.
    // If another master password is already enrolled, authentication fails safely.
    private static final String TEST_MASTER = "T27DisposableMasterPassword123!";

    private void authenticateRealVaultForUiTest() throws Exception {
        SafeKeyApplication app = (SafeKeyApplication) InstrumentationRegistry
                .getInstrumentation().getTargetContext().getApplicationContext();
        long deadline = android.os.SystemClock.elapsedRealtime() + 15_000L;
        while (!app.isStartupRuntimeAvailable()
                && android.os.SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(100L);
        }
        assertTrue("SafeKey runtime not ready", app.isStartupRuntimeAvailable());
        // Do NOT unregister session cleanup: real vaults must close on lock.
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
        final boolean alreadyEnrolled = coordinator.hasVault();
        final CountDownLatch opened = new CountDownLatch(1);
        final AtomicReference<Exception> openError = new AtomicReference<>();
        final AtomicReference<VaultUnlockFlow.Request> requestHolder = new AtomicReference<>();
        final char[] master = TEST_MASTER.toCharArray();
        try {
            VaultDataService.SimpleCallback callback = new VaultDataService.SimpleCallback() {
                @Override public void onSuccess() {
                    // requestHolder is set before the asynchronous callback fires.
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
                                        "Test vault has TOTP enabled; use a fresh test-only emulator"));
                                opened.countDown();
                            }
                        }));
            } else {
                requestHolder.set(coordinator.createVaultForEnrollment(
                        master, MasterPasswordCheckStatus.CHECKED, callback));
            }
            assertTrue("Test vault authentication timed out", opened.await(25, TimeUnit.SECONDS));
            if (openError.get() != null) {
                throw new AssertionError("Test-only REAL Vault authentication failed. "
                        + "Use only a disposable emulator enrolled with the test credential.",
                        openError.get());
            }
            assertEquals(SafeKeyApplication.ActiveVault.REAL, app.getActiveVault());
        } finally {
            Arrays.fill(master, '\0');
        }
    }

    private static final String TEST_DECOY = "T27DisposableDecoyPassword456!";

    private void authenticateDecoyVaultForUiTest() throws Exception {
        SafeKeyApplication app = (SafeKeyApplication) InstrumentationRegistry
                .getInstrumentation().getTargetContext().getApplicationContext();

        // A real enrollment is necessary for password role separation.
        // This helper uses only the disposable test credential.
        authenticateRealVaultForUiTest();
        SafeKeySession.lock();
        awaitAuthenticationReadiness(app);

        DecoyVaultCoordinator decoy = app.getDecoyVaultCoordinator();
        char[] password = TEST_DECOY.toCharArray();
        try {
            if (!decoy.hasDecoyVault()) {
                awaitDecoyOperation(callback ->
                        decoy.createDecoyVault(password, callback));
                // Enrollment opens the decoy; explicitly close and reopen to
                // validate the same unlock path used by actual sign-in.
                awaitDecoyOperation(decoy::closeDecoyVault);
            }

            awaitDecoyOperation(callback ->
                    decoy.unlockDecoyVault(password, callback));

            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                SafeKeySession.unlockAfterAuthentication();
                app.activateDecoyVault();
            });
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertEquals(SafeKeyApplication.ActiveVault.DECOY, app.getActiveVault());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void awaitAuthenticationReadiness(SafeKeyApplication app)
            throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        app.prepareForVaultAuthentication(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { ready.countDown(); }
            @Override public void onError(Exception error) {
                failure.set(error);
                ready.countDown();
            }
        });
        assertTrue("Vault cleanup did not finish", ready.await(30, TimeUnit.SECONDS));
        if (failure.get() != null) { throw failure.get(); }
    }

    private interface DecoyOperation {
        void start(VaultDataService.SimpleCallback callback);
    }

    private void awaitDecoyOperation(DecoyOperation operation) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        operation.start(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { done.countDown(); }
            @Override public void onError(Exception error) {
                failure.set(error);
                done.countDown();
            }
        });
        assertTrue("Decoy operation timed out", done.await(45, TimeUnit.SECONDS));
        if (failure.get() != null) { throw failure.get(); }
    }

}

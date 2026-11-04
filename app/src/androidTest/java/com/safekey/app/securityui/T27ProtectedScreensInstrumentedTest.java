package com.safekey.app.securityui;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.os.Bundle;
import android.widget.EditText;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.core.app.ActivityScenario;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.data.service.VaultDataService;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class T27ProtectedScreensInstrumentedTest {

    @Test
    public void unlockedWithoutActiveRealVaultCannotOpenDecoySetup() {
        assertUnlockedWithoutRealVaultCannotOpen(
                SetupDecoyVaultActivity.class
        );
    }

    @Test
    public void unlockedWithoutActiveRealVaultCannotOpenPanicSetup() {
        assertUnlockedWithoutRealVaultCannotOpen(
                SetupPanicModeActivity.class
        );
    }

    @Test
    public void unlockedActiveDecoyVaultCannotOpenDecoySetup() throws Exception {
        assertActiveDecoyVaultCannotOpen(SetupDecoyVaultActivity.class);
    }

    @Test
    public void unlockedActiveDecoyVaultCannotOpenPanicSetup() throws Exception {
        assertActiveDecoyVaultCannotOpen(SetupPanicModeActivity.class);
    }

    @Test
    public void lockedDecoySetupRedirectsToSignIn() throws Exception {
        assertRedirectsToSignIn(SetupDecoyVaultActivity.class);
    }

    @Test
    public void lockedPanicSetupRedirectsToSignIn() throws Exception {
        assertRedirectsToSignIn(SetupPanicModeActivity.class);
    }

    @Test
    public void emptyDecoyPasswordShowsValidationError() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupDecoyVaultActivity> scenario =
                     ActivityScenario.launch(SetupDecoyVaultActivity.class)) {

            scenario.onActivity(activity -> {
                // Submit the form without entering a password.
                activity.findViewById(
                        com.safekey.app.R.id.buttonCreateDecoyVault
                ).performClick();

                android.widget.TextView error = activity.findViewById(
                        com.safekey.app.R.id.textDecoyPasswordError
                );

                assertEquals(
                        android.view.View.VISIBLE,
                        error.getVisibility()
                );

                assertEquals(
                        activity.getString(
                                com.safekey.app.R.string.t27_decoy_password_required
                        ),
                        error.getText().toString()
                );
            });

        } finally {
            SafeKeySession.lock();

            android.app.Application application =
                    (android.app.Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
        }
    }

    @Test
    public void emptyPanicMasterPasswordShowsValidationError() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupPanicModeActivity> scenario =
                     ActivityScenario.launch(SetupPanicModeActivity.class)) {

            scenario.onActivity(activity -> {
                activity.findViewById(
                        com.safekey.app.R.id.buttonEnablePanic
                ).performClick();

                android.widget.TextView error = activity.findViewById(
                        com.safekey.app.R.id.textPanicFormError
                );

                assertEquals(
                        android.view.View.VISIBLE,
                        error.getVisibility()
                );

                assertEquals(
                        activity.getString(
                                com.safekey.app.R.string.t27_panic_master_required
                        ),
                        error.getText().toString()
                );
            });

        } finally {
            SafeKeySession.lock();

            Application application =
                    (Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
        }
    }

    @Test
    public void cancelDecoySetupClosesScreen() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupDecoyVaultActivity> scenario =
                     ActivityScenario.launch(SetupDecoyVaultActivity.class)) {

            scenario.onActivity(activity -> {
                activity.findViewById(
                        com.safekey.app.R.id.buttonCancelDecoySetup
                ).performClick();

                assertTrue(
                        "Decoy setup did not finish after Cancel",
                        activity.isFinishing()
                );
            });

        } finally {
            SafeKeySession.lock();

            Application application =
                    (Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
        }
    }

    @Test
    public void cancelPanicSetupClosesScreen() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupPanicModeActivity> scenario =
                     ActivityScenario.launch(SetupPanicModeActivity.class)) {

            scenario.onActivity(activity -> {
                activity.findViewById(
                        com.safekey.app.R.id.buttonCancelPanic
                ).performClick();

                assertTrue(
                        "Panic setup did not finish after Cancel",
                        activity.isFinishing()
                );
            });

        } finally {
            SafeKeySession.lock();

            Application application =
                    (Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
        }
    }

    @Test
    public void decoyPasswordClearedWhenScreenStops() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupDecoyVaultActivity> scenario =
                     ActivityScenario.launch(SetupDecoyVaultActivity.class)) {

            scenario.onActivity(activity -> {
                EditText password = activity.findViewById(
                        com.safekey.app.R.id.editDecoyPassword
                );

                password.setText("TemporaryTestPassword123!");
                assertTrue(password.length() > 0);
            });

            scenario.moveToState(
                    androidx.lifecycle.Lifecycle.State.CREATED
            );

            scenario.moveToState(
                    androidx.lifecycle.Lifecycle.State.RESUMED
            );

            scenario.onActivity(activity -> {
                EditText password = activity.findViewById(
                        com.safekey.app.R.id.editDecoyPassword
                );

                assertEquals(
                        "Password was not cleared when screen stopped",
                        0,
                        password.length()
                );
            });

        } finally {
            SafeKeySession.lock();

            Application application =
                    (Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
        }
    }

    @Test
    public void panicPasswordsClearedWhenScreenStops() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupPanicModeActivity> scenario =
                     ActivityScenario.launch(SetupPanicModeActivity.class)) {

            scenario.onActivity(activity -> {
                ((EditText) activity.findViewById(
                        com.safekey.app.R.id.editPanicMasterPassword
                )).setText("TemporaryMasterPassword123!");

                ((EditText) activity.findViewById(
                        com.safekey.app.R.id.editPanicDecoyPassword
                )).setText("TemporaryDecoyPassword123!");

                ((EditText) activity.findViewById(
                        com.safekey.app.R.id.editPanicNewPassword
                )).setText("TemporaryPanicPassword123!");

                ((EditText) activity.findViewById(
                        com.safekey.app.R.id.editPanicConfirmPassword
                )).setText("TemporaryPanicPassword123!");

                ((android.widget.CheckBox) activity.findViewById(
                        com.safekey.app.R.id.checkPanicConfirmation
                )).setChecked(true);
            });

            scenario.moveToState(
                    androidx.lifecycle.Lifecycle.State.CREATED
            );

            scenario.moveToState(
                    androidx.lifecycle.Lifecycle.State.RESUMED
            );

            scenario.onActivity(activity -> {
                int[] passwordIds = {
                        com.safekey.app.R.id.editPanicMasterPassword,
                        com.safekey.app.R.id.editPanicDecoyPassword,
                        com.safekey.app.R.id.editPanicNewPassword,
                        com.safekey.app.R.id.editPanicConfirmPassword
                };

                for (int id : passwordIds) {
                    EditText field = activity.findViewById(id);

                    assertEquals(
                            "Sensitive password field was not cleared",
                            0,
                            field.length()
                    );
                }

                assertTrue(
                        "Panic confirmation checkbox was not reset",
                        !((android.widget.CheckBox) activity.findViewById(
                                com.safekey.app.R.id.checkPanicConfirmation
                        )).isChecked()
                );
            });

        } finally {
            SafeKeySession.lock();

            Application application =
                    (Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
        }
    }

    @Test
    public void systemBackClosesDecoySetup() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupDecoyVaultActivity> scenario =
                     ActivityScenario.launch(SetupDecoyVaultActivity.class)) {

            scenario.onActivity(activity -> {
                activity.getOnBackPressedDispatcher().onBackPressed();

                assertTrue(
                        "Decoy setup did not finish after system Back",
                        activity.isFinishing()
                );
            });

        } finally {
            SafeKeySession.lock();

            Application application =
                    (Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
        }
    }

    @Test
    public void systemBackClosesPanicSetup() throws Exception {
        authenticateRealVaultForUiTest();

        try (ActivityScenario<SetupPanicModeActivity> scenario =
                     ActivityScenario.launch(SetupPanicModeActivity.class)) {

            scenario.onActivity(activity -> {
                activity.getOnBackPressedDispatcher().onBackPressed();

                assertTrue(
                        "Panic setup did not finish after system Back",
                        activity.isFinishing()
                );
            });

        } finally {
            SafeKeySession.lock();

            Application application =
                    (Application) InstrumentationRegistry
                            .getInstrumentation()
                            .getTargetContext()
                            .getApplicationContext();

            ((SafeKeyApplication) application).registerSessionCleanup();
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

    // Use the application-owned coordinator: an isolated coordinator cannot
    // establish SafeKeyApplication.ActiveVault.DECOY.
    private static final String TEST_DECOY = "T27DisposableDecoyPassword456!";

    private void assertActiveDecoyVaultCannotOpen(
            Class<? extends Activity> protectedClass
    ) throws Exception {
        SafeKeyApplication app = (SafeKeyApplication) InstrumentationRegistry
                .getInstrumentation().getTargetContext().getApplicationContext();
        try {
            authenticateDecoyVaultForUiTest();

            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertEquals(SafeKeyApplication.ActiveVault.DECOY, app.getActiveVault());

            Intent intent = new Intent(app, protectedClass);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try (ActivityScenario<? extends Activity> scenario =
                         ActivityScenario.launch(intent)) {
                assertEquals(
                        "DECOY session must not access REAL-only setup screen",
                        androidx.lifecycle.Lifecycle.State.DESTROYED,
                        scenario.getState()
                );
            }
        } finally {
            SafeKeySession.lock();
            app.registerSessionCleanup();
        }
    }

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

    private void assertUnlockedWithoutRealVaultCannotOpen(
            Class<? extends Activity> protectedClass
    ) {
        SafeKeyApplication application =
                (SafeKeyApplication) InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext()
                        .getApplicationContext();

        SafeKeySession.unregisterSensitiveDataCleanup();

        try {
            SafeKeySession.lock();
            SafeKeySession.unlockAfterAuthentication();

            assertEquals(
                    SafeKeyApplication.ActiveVault.NONE,
                    application.getActiveVault()
            );

            Intent intent = new Intent(application, protectedClass);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            try (ActivityScenario<? extends Activity> scenario =
                         ActivityScenario.launch(intent)) {

                assertEquals(
                        "Unauthorized setup screen was not destroyed",
                        androidx.lifecycle.Lifecycle.State.DESTROYED,
                        scenario.getState()
                );
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    private void assertRedirectsToSignIn(
            Class<? extends Activity> protectedClass
    ) throws Exception {

        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.lock();

        Application application =
                (Application) InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext()
                        .getApplicationContext();

        AtomicReference<Activity> protectedActivity =
                new AtomicReference<>();

        AtomicReference<Activity> signInActivity =
                new AtomicReference<>();

        AtomicBoolean protectedScreenFinishing =
                new AtomicBoolean(false);

        CountDownLatch signInResumed =
                new CountDownLatch(1);

        AtomicReference<String> lastResumedActivity =
                new AtomicReference<>("None");

        Application.ActivityLifecycleCallbacks callbacks =
                new Application.ActivityLifecycleCallbacks() {

                    @Override
                    public void onActivityCreated(
                            Activity activity,
                            Bundle savedInstanceState
                    ) {
                        if (protectedClass.isInstance(activity)) {
                            protectedActivity.set(activity);
                        }
                    }

                    @Override
                    public void onActivityStarted(Activity activity) {
                    }

                    @Override
                    public void onActivityResumed(Activity activity) {
                        lastResumedActivity.set(activity.getClass().getName());

                        if (activity instanceof SignInActivity
                                && protectedActivity.get() != null) {

                            signInActivity.set(activity);

                            protectedScreenFinishing.set(
                                    protectedActivity.get().isFinishing()
                            );

                            signInResumed.countDown();
                        }
                    }

                    @Override
                    public void onActivityPaused(Activity activity) {
                    }

                    @Override
                    public void onActivityStopped(Activity activity) {
                    }

                    @Override
                    public void onActivitySaveInstanceState(
                            Activity activity,
                            Bundle outState
                    ) {
                    }

                    @Override
                    public void onActivityDestroyed(Activity activity) {
                    }
                };

        application.registerActivityLifecycleCallbacks(callbacks);

        try {
            Intent intent =
                    new Intent(application, protectedClass);

            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            application.startActivity(intent);

            assertTrue(
                    "Sign In did not appear. Last resumed Activity: "
                            + lastResumedActivity.get()
                            + "; protected Activity created: "
                            + (protectedActivity.get() != null),
                    signInResumed.await(10, TimeUnit.SECONDS)
            );

            assertNotNull(protectedActivity.get());

            assertTrue(
                    "Protected setup screen was not finishing",
                    protectedScreenFinishing.get()
            );

            assertEquals(
                    SessionState.LOCKED,
                    SafeKeySession.getState()
            );

        } finally {
            application.unregisterActivityLifecycleCallbacks(callbacks);

            InstrumentationRegistry.getInstrumentation()
                    .runOnMainSync(() -> {

                        Activity signIn = signInActivity.get();
                        Activity protectedScreen =
                                protectedActivity.get();

                        if (signIn != null && !signIn.isFinishing()) {
                            signIn.finish();
                        }

                        if (protectedScreen != null
                                && !protectedScreen.isFinishing()) {
                            protectedScreen.finish();
                        }
                    });

            SafeKeySession.lock();

            ((SafeKeyApplication) application)
                    .registerSessionCleanup();
        }
    }
}
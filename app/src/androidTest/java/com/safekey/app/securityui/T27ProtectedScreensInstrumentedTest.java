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

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class T27ProtectedScreensInstrumentedTest {

    @Test
    public void lockedDecoySetupRedirectsToSignIn() throws Exception {
        assertRedirectsToSignIn(SetupDecoyVaultActivity.class);
    }

    @Test
    public void lockedPanicSetupRedirectsToSignIn() throws Exception {
        assertRedirectsToSignIn(SetupPanicModeActivity.class);
    }

    @Test
    public void emptyDecoyPasswordShowsValidationError() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
    public void emptyPanicMasterPasswordShowsValidationError() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
    public void cancelDecoySetupClosesScreen() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
    public void cancelPanicSetupClosesScreen() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
    public void decoyPasswordClearedWhenScreenStops() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
    public void panicPasswordsClearedWhenScreenStops() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
    public void systemBackClosesDecoySetup() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
    public void systemBackClosesPanicSetup() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.unlockAfterAuthentication();

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
                    "Sign In did not appear after opening a locked setup screen",
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
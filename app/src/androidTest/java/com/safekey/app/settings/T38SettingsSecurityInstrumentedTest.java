package com.safekey.app.settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import android.content.Intent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.SwitchCompat;
import android.widget.EditText;
import android.widget.TextView;
import android.os.SystemClock;

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

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * T38 Settings access tests. Run ONLY on the disposable SafeKey_Test_API_35 AVD.
 * This fixture never clears existing app data. If the existing vault has another
 * master password or TOTP, it fails instead of overwriting that vault.
 */
@RunWith(AndroidJUnit4.class)
public class T38SettingsSecurityInstrumentedTest {

    @Test
    public void realVaultManualLockAllowsNormalSignIn() throws Exception {
        verifyManualLockAllowsNormalSignIn(false);
    }

    @Test
    public void decoyVaultManualLockAllowsNormalSignIn() throws Exception {
        verifyManualLockAllowsNormalSignIn(true);
    }

    private void verifyManualLockAllowsNormalSignIn(boolean decoy) throws Exception {
        SafeKeyApplication application = app();
        try {
            if (decoy) {
                authenticateDecoyVaultForUiTest();
            } else {
                authenticateRealVaultForUiTest();
            }

            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());

            android.app.Instrumentation instrumentation =
                    InstrumentationRegistry.getInstrumentation();
            android.app.Instrumentation.ActivityMonitor monitor =
                    instrumentation.addMonitor(
                            "com.safekey.app.auth.SignInActivity", null, false);
            try {
                try (ActivityScenario<SettingsActivity> scenario =
                             ActivityScenario.launch(SettingsActivity.class)) {
                    scenario.onActivity(activity -> {
                        View lockButton = activity.findViewById(R.id.rowSettingsLockVault);
                        assertTrue("Lock Vault control missing", lockButton != null);
                        assertTrue("Lock Vault click was not handled",
                                lockButton.performClick());
                    });

                    android.app.Activity signIn =
                            monitor.waitForActivityWithTimeout(10000);
                    assertTrue("Manual lock did not open Sign In", signIn != null);
                    assertFalse("Manual lock must not require the REAL master password",
                            signIn.getIntent().getBooleanExtra(
                                    com.safekey.app.auth.SignInActivity.REQUIRE_MASTER_PASSWORD,
                                    false));

                    assertEquals("Manual Lock Vault must lock the session",
                            SessionState.LOCKED, SafeKeySession.getState());
                    assertTrue("Settings must leave the foreground after manual lock",
                            scenario.getState() != Lifecycle.State.RESUMED);
                }
            } finally {
                instrumentation.removeMonitor(monitor);
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }
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

    /** Covers the encrypted REAL vault profile through the actual Settings UI. */
    @Test
    public void realVaultRenamePersistsAfterReopeningSettings() throws Exception {
        verifyRenamePersists(false);
    }

    /** Covers the independently encrypted DECOY profile through the Settings UI. */
    @Test
    public void decoyVaultRenamePersistsAfterReopeningSettings() throws Exception {
        verifyRenamePersists(true);
    }

    /** A stopped Settings screen must release its dialog and allow a fresh rename. */
    @Test
    public void backgroundDuringRenameDoesNotLeaveDisabledDialog() throws Exception {
        SafeKeyApplication application = app();
        try {
            authenticateRealVaultForUiTest();
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                awaitEditableName(scenario);
                String original = currentName(scenario);
                String attempted = "T38BackgroundRename";
                try {
                    AlertDialog previousDialog = openRenameDialog(scenario);
                    submitRename(scenario, previousDialog, attempted);
                    // A save may complete before this transition. Either way,
                    // stopping Settings must dismiss the original dialog.
                    scenario.moveToState(Lifecycle.State.CREATED);
                    assertTrue("Stopped Settings retained its rename dialog",
                            !previousDialog.isShowing());
                    scenario.moveToState(Lifecycle.State.RESUMED);
                    awaitEditableName(scenario);
                    AlertDialog newDialog = openRenameDialog(scenario);
                    assertTrue("Settings reopened the same dialog instance",
                            previousDialog != newDialog);
                    submitRename(scenario, newDialog, original);
                    awaitName(scenario, original);
                } finally {
                    // Restore the original test vault name if a save completed late.
                    awaitEditableName(scenario);
                    if (!original.equals(currentName(scenario))) {
                        rename(scenario, original);
                    }
                }
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    /** A DECOY session may not reveal or modify REAL biometric enrollment. */
    @Test
    public void decoyVaultBiometricControlIsDisabled() throws Exception {
        SafeKeyApplication application = app();
        try {
            authenticateDecoyVaultForUiTest();
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                scenario.onActivity(activity -> {
                    SwitchCompat toggle = activity.findViewById(R.id.switchSettingsBiometric);
                    assertFalse("DECOY must not enable REAL biometrics", toggle.isEnabled());
                    assertFalse("DECOY must not reveal REAL biometric state", toggle.isChecked());
                });
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    /** The five-minute timeout is display-only until the session backend PR. */
    @Test
    public void autoLockRemainsReadOnlyAtFiveMinutes() throws Exception {
        SafeKeyApplication application = app();
        try {
            authenticateRealVaultForUiTest();
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                scenario.onActivity(activity -> {
                    View row = activity.findViewById(R.id.rowSettingsAutoLock);
                    TextView value = activity.findViewById(R.id.textSettingsAutoLockValue);
                    assertEquals(activity.getString(R.string.settings_auto_lock_five_minutes),
                            value.getText().toString());
                    assertFalse("Auto-lock has no action in T38", row.hasOnClickListeners());
                });
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    /** Cancelling password re-verification must not enroll biometrics. */
    @Test
    public void cancelBiometricPasswordDialogDoesNotChangeConfiguration() throws Exception {
        SafeKeyApplication application = app();
        try {
            authenticateRealVaultForUiTest();
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                AtomicReference<AlertDialog> held = new AtomicReference<>();
                AtomicReference<EditText> field = new AtomicReference<>();
                AtomicBoolean initiallyConfigured = new AtomicBoolean();
                scenario.onActivity(activity -> {
                    initiallyConfigured.set(biometricConfigured(activity));
                    invokeEnableBiometricDialog(activity);
                    AlertDialog dialog = getBiometricDialog(activity);
                    assertTrue("Password confirmation dialog missing",
                            dialog != null && dialog.isShowing());
                    EditText input = dialog.findViewById(R.id.editSettingsBiometricPassword);
                    assertTrue("Password input missing", input != null);
                    input.setText("not-a-real-password");
                    held.set(dialog);
                    field.set(input);
                });
                scenario.onActivity(activity ->
                        assertTrue("Cancel button did not handle click",
                                held.get().getButton(AlertDialog.BUTTON_NEGATIVE).performClick()));
                awaitUiCondition(scenario, activity -> !held.get().isShowing(),
                        "Cancel did not dismiss dialog");
                scenario.onActivity(activity -> {
                    assertEquals(initiallyConfigured.get(), biometricConfigured(activity));
                    SwitchCompat toggle = activity.findViewById(R.id.switchSettingsBiometric);
                    assertEquals(initiallyConfigured.get(), toggle.isChecked());
                    assertEquals("Cancelled password was not cleared", 0, field.get().length());
                });
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    /** Empty input should show validation feedback and never start enrollment. */
    @Test
    public void emptyBiometricPasswordIsRejected() throws Exception {
        SafeKeyApplication application = app();
        try {
            authenticateRealVaultForUiTest();
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                AtomicReference<AlertDialog> held = new AtomicReference<>();
                AtomicBoolean initiallyConfigured = new AtomicBoolean();
                scenario.onActivity(activity -> {
                    initiallyConfigured.set(biometricConfigured(activity));
                    invokeEnableBiometricDialog(activity);
                    AlertDialog dialog = getBiometricDialog(activity);
                    assertTrue("Password dialog missing", dialog != null && dialog.isShowing());
                    held.set(dialog);
                });
                scenario.onActivity(activity ->
                        assertTrue("Continue button did not handle click",
                                held.get().getButton(AlertDialog.BUTTON_POSITIVE).performClick()));
                awaitUiCondition(scenario, activity -> {
                    AlertDialog dialog = held.get();
                    EditText input = dialog.findViewById(R.id.editSettingsBiometricPassword);
                    return dialog.isShowing() && input != null && input.getError() != null;
                }, "Required-password error not shown");
                scenario.onActivity(activity -> {
                    assertTrue("Validation unexpectedly closed dialog", held.get().isShowing());
                    assertEquals(initiallyConfigured.get(), biometricConfigured(activity));
                    held.get().getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
                });
                awaitUiCondition(scenario, activity -> !held.get().isShowing(),
                        "Cancel did not dismiss validation dialog");
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    /** Stopping Settings dismisses and synchronously clears sensitive input. */
    @Test
    public void backgroundClosesBiometricPasswordDialog() throws Exception {
        SafeKeyApplication application = app();
        try {
            authenticateRealVaultForUiTest();
            try (ActivityScenario<SettingsActivity> scenario =
                         ActivityScenario.launch(SettingsActivity.class)) {
                AtomicReference<AlertDialog> held = new AtomicReference<>();
                AtomicReference<EditText> field = new AtomicReference<>();
                scenario.onActivity(activity -> {
                    invokeEnableBiometricDialog(activity);
                    AlertDialog dialog = getBiometricDialog(activity);
                    assertTrue("Password dialog missing", dialog != null && dialog.isShowing());
                    EditText input = dialog.findViewById(R.id.editSettingsBiometricPassword);
                    assertTrue("Password input missing", input != null);
                    input.setText("temporary-sensitive-test-input");
                    held.set(dialog);
                    field.set(input);
                });
                scenario.moveToState(Lifecycle.State.CREATED);
                assertFalse("Password dialog visible after stop", held.get().isShowing());
                assertEquals("Sensitive password input retained", 0, field.get().length());
                scenario.moveToState(Lifecycle.State.RESUMED);
                scenario.onActivity(activity ->
                        assertTrue("Settings did not restore REAL session", activity.findViewById(
                                R.id.switchSettingsBiometric) != null));
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    private boolean biometricConfigured(SettingsActivity activity) {
        try {
            return app().getSecureVaultCoordinator().isBiometricUnlockConfigured(activity);
        } catch (Exception error) {
            throw new AssertionError("Cannot inspect test biometric configuration", error);
        }
    }

    private void invokeEnableBiometricDialog(SettingsActivity activity) {
        // Invoke the password dialog directly so cancellation/validation coverage works
        // even on an emulator that has no enrolled system biometrics. This does NOT
        // claim that the end-to-end enrollment prompt has been tested.
        try {
            Method method = SettingsActivity.class.getDeclaredMethod("showEnableBiometricDialog");
            method.setAccessible(true);
            method.invoke(activity);
        } catch (ReflectiveOperationException error) {
            throw new AssertionError("Cannot open Settings biometric password dialog", error);
        }
    }

    private AlertDialog getBiometricDialog(SettingsActivity activity) {
        try {
            Field field = SettingsActivity.class.getDeclaredField("biometricDialog");
            field.setAccessible(true);
            return (AlertDialog) field.get(activity);
        } catch (ReflectiveOperationException error) {
            throw new AssertionError("Cannot inspect Settings biometric dialog", error);
        }
    }

    private void verifyRenamePersists(boolean decoy) throws Exception {
        SafeKeyApplication application = app();
        String original;
        String changed = decoy ? "T38DecoyUiRename" : "T38RealUiRename";
        try {
            if (decoy) {
                authenticateDecoyVaultForUiTest();
            } else {
                authenticateRealVaultForUiTest();
            }
            try (ActivityScenario<SettingsActivity> first =
                         ActivityScenario.launch(SettingsActivity.class)) {
                awaitEditableName(first);
                original = currentName(first);
                rename(first, changed);
            }
            try (ActivityScenario<SettingsActivity> reopened =
                         ActivityScenario.launch(SettingsActivity.class)) {
                try {
                    awaitName(reopened, changed);
                } finally {
                    awaitEditableName(reopened);
                    rename(reopened, original);
                }
            }
        } finally {
            SafeKeySession.lock();
            application.registerSessionCleanup();
        }
    }

    /**
     * ActivityScenario dispatches interactions on the UI thread. This avoids
     * requiring an Espresso-focused root when the instrumentation launches
     * Settings directly without the normal Home/Sign-In navigation window.
     */
    private AlertDialog openRenameDialog(ActivityScenario<SettingsActivity> scenario)
            throws Exception {
        awaitEditableName(scenario);
        AtomicReference<AlertDialog> opened = new AtomicReference<>();
        scenario.onActivity(activity -> {
            View editButton = activity.findViewById(R.id.buttonSettingsEditName);
            assertTrue("Rename button is disabled", editButton.isEnabled());
            assertTrue("Rename button did not handle the click", editButton.performClick());
            AlertDialog dialog = getRenameDialog(activity);
            assertTrue("Rename dialog did not open", dialog != null && dialog.isShowing());
            opened.set(dialog);
        });
        return opened.get();
    }

    private void submitRename(ActivityScenario<SettingsActivity> scenario,
                              AlertDialog dialog, String name) {
        scenario.onActivity(activity -> {
            assertTrue("Rename dialog is no longer showing", dialog.isShowing());
            EditText input = findEditText(dialog.getWindow().getDecorView());
            assertTrue("Rename input not found", input != null);
            assertTrue("Rename input is disabled", input.isEnabled());
            input.setText(name);
            Button save = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            assertTrue("Rename Save button is disabled", save != null && save.isEnabled());
            assertTrue("Rename Save button did not handle the click", save.performClick());
        });
    }

    private void rename(ActivityScenario<SettingsActivity> scenario, String name)
            throws Exception {
        submitRename(scenario, openRenameDialog(scenario), name);
        awaitName(scenario, name);
    }

    // Read-only access to the dialog owned by Settings. No production code is changed.
    private AlertDialog getRenameDialog(SettingsActivity activity) {
        try {
            Field field = SettingsActivity.class.getDeclaredField("renameDialog");
            field.setAccessible(true);
            return (AlertDialog) field.get(activity);
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError("Settings renameDialog field was changed", exception);
        }
    }

    private EditText findEditText(View view) {
        if (view instanceof EditText) {
            return (EditText) view;
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int index = 0; index < group.getChildCount(); index++) {
                EditText found = findEditText(group.getChildAt(index));
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private String currentName(ActivityScenario<SettingsActivity> scenario) {
        AtomicReference<String> name = new AtomicReference<>();
        scenario.onActivity(activity -> name.set(((TextView) activity.findViewById(
                R.id.textSettingsVaultName)).getText().toString()));
        return name.get();
    }

    private void awaitEditableName(ActivityScenario<SettingsActivity> scenario)
            throws Exception {
        awaitUiCondition(scenario, activity -> activity.findViewById(
                R.id.buttonSettingsEditName).isEnabled(), "vault name did not load");
    }

    private void awaitName(ActivityScenario<SettingsActivity> scenario, String expected)
            throws Exception {
        awaitUiCondition(scenario, activity -> expected.equals(((TextView)
                        activity.findViewById(R.id.textSettingsVaultName)).getText().toString())
                        && activity.findViewById(R.id.buttonSettingsEditName).isEnabled(),
                "vault name did not update to expected value");
    }

    private interface UiCondition {
        boolean matches(SettingsActivity activity);
    }

    private void awaitUiCondition(ActivityScenario<SettingsActivity> scenario,
                                  UiCondition condition, String failure) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 15_000L;
        while (SystemClock.elapsedRealtime() < deadline) {
            AtomicBoolean met = new AtomicBoolean();
            scenario.onActivity(activity -> met.set(condition.matches(activity)));
            if (met.get()) {
                return;
            }
            Thread.sleep(100L);
        }
        throw new AssertionError(failure);
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
            // Store the request on the same thread that receives success callbacks.
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
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
            });
            assertTrue("Test vault authentication timed out", opened.await(25, TimeUnit.SECONDS));
            if (openError.get() != null) {
                throw new AssertionError("Test-only REAL Vault authentication failed. "
                        + "Use only a disposable emulator enrolled with the test credential.",
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

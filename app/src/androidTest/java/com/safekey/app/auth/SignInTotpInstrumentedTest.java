package com.safekey.app.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.os.SystemClock;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry;
import androidx.test.runner.lifecycle.Stage;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.totp.TotpGenerator;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.security.totp.TotpState;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/** Resets the emulator application's test vault, TOTP, and biometric configuration. */
@RunWith(AndroidJUnit4.class)
public class SignInTotpInstrumentedTest {

    private static final String PASSWORD = "correct horse battery staple";

    // Public RFC data only, installed temporarily by the test fixture.
    private static final byte[] SECRET =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private Context context;
    private SecureVaultCoordinator coordinator;
    private TotpSecretStore store;

    @Before
    public void setUp() throws Exception {
        finishActivities();

        context = InstrumentationRegistry.getInstrumentation()
                .getTargetContext()
                .getApplicationContext();

        coordinator = ((SafeKeyApplication) context)
                .getSecureVaultCoordinator();

        SafeKeySession.lock();
        awaitOperation(coordinator::closeVault);
        resetBiometrics();

        store = new TotpSecretStore(context);
        store.clear();
        new VaultKeyEnvelopeStore(context).clear();
        context.deleteDatabase("safekey.db");

        char[] password = PASSWORD.toCharArray();

        try {
            awaitOperation(
                    callback -> coordinator.createVault(password, callback));
        } finally {
            Arrays.fill(password, '\0');
        }

        awaitOperation(coordinator::closeVault);

        try (TotpState state = new TotpState(SECRET, -1L, 0, 0L)) {
            store.save(state);
        }
    }

    @After
    public void tearDown() throws Exception {
        finishActivities();
        SafeKeySession.lock();

        if (coordinator != null) {
            awaitOperation(coordinator::closeVault);
        }

        if (store != null) {
            store.clear();
        }

        if (context != null) {
            new VaultKeyEnvelopeStore(context).clear();
            context.deleteDatabase("safekey.db");
        }
    }

    @Test
    public void correctPasswordShowsCodeDialogWithoutOpeningVault()
            throws Exception {
        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitCondition(() -> dialogShowing(scenario));
            assertLockedAndClosed();

            scenario.onActivity(activity -> {
                EditText password =
                        activity.findViewById(R.id.editMasterPassword);

                assertEquals("", password.getText().toString());
                assertFalse(password.isSaveEnabled());

                assertTrue((activity.getWindow().getAttributes().flags
                        & WindowManager.LayoutParams.FLAG_SECURE) != 0);

                assertTrue((dialog(activity).getWindow().getAttributes().flags
                        & WindowManager.LayoutParams.FLAG_SECURE) != 0);
            });
        }
    }

    @Test
    public void invalidCodeKeepsVaultLockedAndClearsCodeField()
            throws Exception {
        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitCondition(() -> dialogShowing(scenario));
            submit(scenario, wrongCode());

            awaitCondition(() -> message(scenario).equals(
                    context.getString(R.string.totp_signin_invalid_code)));

            assertLockedAndClosed();

            scenario.onActivity(activity -> {
                EditText input =
                        dialog(activity).findViewById(R.id.editTotpCode);

                assertEquals("", input.getText().toString());
                assertTrue(input.isEnabled());
            });
        }
    }

    @Test
    public void currentCodeOpensHomeOnlyAfterBothFactors() throws Exception {
        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitCondition(() -> dialogShowing(scenario));

            submit(scenario, TotpGenerator.generate(
                    SECRET, System.currentTimeMillis() / 1_000L));

            awaitHome();

            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertTrue(coordinator.isVaultOpen());
        }
    }

    @Test
    public void cancelRequiresFreshPasswordAndLeavesVaultClosed()
            throws Exception {
        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitCondition(() -> dialogShowing(scenario));

            scenario.onActivity(activity -> dialog(activity)
                    .findViewById(R.id.buttonTotpCancel)
                    .performClick());

            awaitCondition(() -> readyForPassword(scenario));
            assertLockedAndClosed();
        }
    }

    @Test
    public void backgroundingPendingTotpCancelsTheRequest() throws Exception {
        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitCondition(() -> dialogShowing(scenario));

            scenario.moveToState(Lifecycle.State.CREATED);
            scenario.moveToState(Lifecycle.State.RESUMED);

            awaitCondition(() -> readyForPassword(scenario));
            assertLockedAndClosed();
        }
    }

    @Test
    public void recreationDoesNotRestorePasswordCodeOrAuthentication()
            throws Exception {
        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitCondition(() -> dialogShowing(scenario));

            scenario.onActivity(activity -> {
                EditText input =
                        dialog(activity).findViewById(R.id.editTotpCode);
                input.setText("123456");
            });

            scenario.recreate();

            awaitCondition(() -> readyForPassword(scenario));
            assertLockedAndClosed();
        }
    }

    @Test
    public void fiveBadCodesPersistLockoutAndDisableVerifyButton()
            throws Exception {
        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitCondition(() -> dialogShowing(scenario));

            String wrong = wrongCode();

            for (int i = 0; i < 4; i++) {
                submit(scenario, wrong);

                awaitCondition(() -> message(scenario).equals(
                        context.getString(R.string.totp_signin_invalid_code)));
            }

            submit(scenario, wrong);

            awaitCondition(
                    () -> isBlocked() && !message(scenario).isEmpty());

            scenario.onActivity(activity -> {
                Button verify =
                        dialog(activity).findViewById(R.id.buttonTotpVerify);
                assertFalse(verify.isEnabled());
            });

            assertLockedAndClosed();
        }
    }

    @Test
    @SuppressWarnings("try")
    public void passwordOnlySignInStillWorksWhenTotpIsDisabled()
            throws Exception {
        store.clear();

        try (ActivityScenario<SignInActivity> scenario =
                     launchAndEnterPassword()) {
            awaitHome();

            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertTrue(coordinator.isVaultOpen());
        }
    }

    private ActivityScenario<SignInActivity> launchAndEnterPassword() {
        ActivityScenario<SignInActivity> scenario =
                ActivityScenario.launch(SignInActivity.class);

        scenario.onActivity(activity -> {
            EditText password =
                    activity.findViewById(R.id.editMasterPassword);
            password.setText(PASSWORD);
            activity.findViewById(R.id.buttonUnlockVault).performClick();
        });

        return scenario;
    }

    private static Dialog dialog(SignInActivity activity) {
        Fragment fragment = activity.getSupportFragmentManager()
                .findFragmentByTag(TotpCodeDialogFragment.TAG);

        return fragment instanceof TotpCodeDialogFragment
                ? ((TotpCodeDialogFragment) fragment).getDialog()
                : null;
    }

    private static boolean dialogShowing(
            ActivityScenario<SignInActivity> scenario
    ) {
        AtomicBoolean showing = new AtomicBoolean();

        scenario.onActivity(activity -> {
            Dialog current = dialog(activity);
            showing.set(current != null && current.isShowing());
        });

        return showing.get();
    }

    private static boolean readyForPassword(
            ActivityScenario<SignInActivity> scenario
    ) {
        AtomicBoolean ready = new AtomicBoolean();

        scenario.onActivity(activity -> {
            EditText password =
                    activity.findViewById(R.id.editMasterPassword);
            Button unlock =
                    activity.findViewById(R.id.buttonUnlockVault);

            ready.set(dialog(activity) == null
                    && unlock.isEnabled()
                    && password.getText().length() == 0);
        });

        return ready.get();
    }

    private static String message(
            ActivityScenario<SignInActivity> scenario
    ) {
        AtomicReference<String> value = new AtomicReference<>("");

        scenario.onActivity(activity -> {
            Dialog current = dialog(activity);

            if (current != null) {
                TextView message =
                        current.findViewById(R.id.textTotpCodeMessage);
                value.set(message.getText().toString());
            }
        });

        return value.get();
    }

    private static void submit(
            ActivityScenario<SignInActivity> scenario,
            String code
    ) {
        scenario.onActivity(activity -> {
            Dialog current = dialog(activity);
            EditText input = current.findViewById(R.id.editTotpCode);
            input.setText(code);
            current.findViewById(R.id.buttonTotpVerify).performClick();
        });
    }

    private static void awaitHome() throws Exception {
        awaitCondition(() -> {
            AtomicBoolean home = new AtomicBoolean();

            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                for (Activity activity : new ArrayList<>(
                        ActivityLifecycleMonitorRegistry.getInstance()
                                .getActivitiesInStage(Stage.RESUMED))) {
                    if (activity instanceof HomeActivity) {
                        home.set(true);
                    } else if (activity instanceof SignInActivity) {
                        try {
                            // Accept the existing optional consent UI if shown.
                            Field field = SignInActivity.class
                                    .getDeclaredField(
                                            "biometricEnrollmentDialog");
                            field.setAccessible(true);

                            AlertDialog consent =
                                    (AlertDialog) field.get(activity);

                            if (consent != null && consent.isShowing()) {
                                consent.findViewById(
                                                R.id.buttonBiometricNotNow)
                                        .performClick();
                            }
                        } catch (ReflectiveOperationException error) {
                            throw new AssertionError(error);
                        }
                    }
                }
            });

            return home.get();
        });
    }

    private boolean isBlocked() {
        try (TotpState state = store.load()) {
            return state != null
                    && state.getFailedAttempts() == 5
                    && state.getBlockedUntilEpochMillis()
                    > System.currentTimeMillis();
        } catch (Exception error) {
            throw new AssertionError(error);
        }
    }

    private void assertLockedAndClosed() {
        assertEquals(SessionState.LOCKED, SafeKeySession.getState());
        assertFalse(coordinator.isVaultOpen());
    }

    private static String wrongCode() {
        long step = System.currentTimeMillis() / 30_000L;
        Set<String> nearby = new HashSet<>();

        for (long offset = -2L; offset <= 2L; offset++) {
            nearby.add(TotpGenerator.generate(
                    SECRET, (step + offset) * 30L));
        }

        for (int value = 0; value < 1_000_000; value++) {
            String candidate =
                    String.format(Locale.US, "%06d", value);

            if (!nearby.contains(candidate)) {
                return candidate;
            }
        }

        throw new AssertionError("No invalid test code found.");
    }

    private static void awaitCondition(BooleanSupplier condition)
            throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 15_000L;

        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }

            SystemClock.sleep(50L);
        }

        throw CallbackTimeoutDiagnostics.timeout(
                "Timed out waiting for the expected UI state. Limit: 15 seconds."
        );
    }

    private static void awaitOperation(Operation operation)
            throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();

        operation.run(new VaultDataService.SimpleCallback() {
            @Override
            public void onSuccess() {
                done.countDown();
            }

            @Override
            public void onError(Exception failure) {
                error.set(failure);
                done.countDown();
            }
        });

        CallbackTimeoutDiagnostics.await(done, 30L);

        if (error.get() != null) {
            throw error.get();
        }
    }

    private void resetBiometrics() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();

        try (ActivityScenario<SignInActivity> scenario =
                     ActivityScenario.launch(SignInActivity.class)) {
            scenario.onActivity(activity ->
                    coordinator.disableBiometricUnlock(
                            activity,
                            new VaultDataService.SimpleCallback() {
                                @Override
                                public void onSuccess() {
                                    done.countDown();
                                }

                                @Override
                                public void onError(Exception failure) {
                                    error.set(failure);
                                    done.countDown();
                                }
                            }));

            CallbackTimeoutDiagnostics.await(done, 30L);

            if (error.get() != null) {
                throw error.get();
            }
        }
    }

    private static void finishActivities() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            Set<Activity> activities = new HashSet<>();

            for (Stage stage : Stage.values()) {
                if (stage != Stage.DESTROYED) {
                    activities.addAll(new ArrayList<>(
                            ActivityLifecycleMonitorRegistry.getInstance()
                                    .getActivitiesInStage(stage)));
                }
            }

            for (Activity activity : activities) {
                if (activity instanceof SignInActivity
                        || activity instanceof HomeActivity) {
                    activity.finish();
                }
            }
        });

        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
    }

    private interface Operation {
        void run(VaultDataService.SimpleCallback callback);
    }
}

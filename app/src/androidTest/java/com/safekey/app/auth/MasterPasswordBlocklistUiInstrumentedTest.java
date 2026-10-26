package com.safekey.app.auth;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.lifecycle.ActivityLifecycleCallback;
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry;
import androidx.test.runner.lifecycle.Stage;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.breach.HibpRangeSource;
import com.safekey.app.breach.PasswordBreachCoordinator;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Uses an emulator test vault and deterministic responses, never live HIBP. */
@RunWith(AndroidJUnit4.class)
public class MasterPasswordBlocklistUiInstrumentedTest {
    private static final String PASSWORD = "clouds drift quietly over mountains";
    private SafeKeyApplication app;
    private SecureVaultCoordinator coordinator;
    private MasterPasswordHealth originalHealth;
    private MasterPasswordHealth testHealth;
    private VaultKeyEnvelopeStore store;
    private Context context;
    private FakeSource source;
    private final CountDownLatch home = new CountDownLatch(1);
    private final ActivityLifecycleCallback homeListener = (activity, stage) -> {
        if (activity instanceof HomeActivity && stage == Stage.RESUMED) { home.countDown(); }
    };

    @Before
    public void setUp() throws Exception {
        finishActivities();
        context = InstrumentationRegistry.getInstrumentation().getTargetContext().getApplicationContext();
        app = (SafeKeyApplication) context;
        originalHealth = app.getMasterPasswordHealth();
        originalHealth.cancelRecheck();
        SafeKeySession.lock();
        coordinator = app.getSecureVaultCoordinator();
        awaitSuccess(coordinator::closeVault);
        store = new VaultKeyEnvelopeStore(context);
        store.clear();
        new TotpSecretStore(context).clear();
        context.deleteDatabase("safekey.db");
        source = new FakeSource();
        testHealth = new MasterPasswordHealth(context, source);
        setHealth(testHealth);
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() ->
                ActivityLifecycleMonitorRegistry.getInstance().addLifecycleCallback(homeListener));
    }

    @After
    public void tearDown() throws Exception {
        finishActivities();
        SafeKeySession.lock();
        awaitSuccess(coordinator::closeVault);
        testHealth.close();
        setHealth(originalHealth);
        store.clear();
        new TotpSecretStore(context).clear();
        context.deleteDatabase("safekey.db");
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() ->
                ActivityLifecycleMonitorRegistry.getInstance().removeLifecycleCallback(homeListener));
    }

    @Test
    public void breachedSignupIsRejectedWithoutCreatingVault() throws Exception {
        try (ActivityScenario<SignUpActivity> scenario = ActivityScenario.launch(SignUpActivity.class)) {
            submitSignup(scenario);
            CallbackTimeoutDiagnostics.await(source.requested, 30L);
            source.callback.onSuccess(suffix(PASSWORD) + ":5\r\n");
            drainCheck();
            scenario.onActivity(activity -> assertEquals(
                    activity.getString(R.string.master_password_breached_rejected),
                    ((TextView) activity.findViewById(R.id.textValidationMessage)).getText().toString()));
            assertFalse(store.hasEnvelope());
            assertFalse(coordinator.isVaultOpen());
        }
    }

    @Test
    public void offlineSignupRequiresConsentAndCancellationCreatesNoVault() throws Exception {
        try (ActivityScenario<SignUpActivity> scenario = ActivityScenario.launch(SignUpActivity.class)) {
            submitSignup(scenario);
            offlineResponse();
            assertFalse(store.hasEnvelope());
            scenario.onActivity(activity -> dialog(activity).getButton(DialogInterface.BUTTON_NEGATIVE)
                    .performClick());
            assertFalse(store.hasEnvelope());
            assertFalse(coordinator.isVaultOpen());
        }
    }

    @Test
    public void acceptedOfflineSignupOpensHomeWithPendingCheck() throws Exception {
        try (ActivityScenario<SignUpActivity> scenario = ActivityScenario.launch(SignUpActivity.class)) {
            submitSignup(scenario);
            offlineResponse();
            scenario.onActivity(activity -> dialog(activity).getButton(DialogInterface.BUTTON_POSITIVE)
                    .performClick());
            CallbackTimeoutDiagnostics.await(home, 30L);
            assertTrue(store.hasEnvelope());
            assertTrue(coordinator.isVaultOpen());
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertEquals(MasterPasswordCheckStatus.PENDING, store.getMasterPasswordCheckStatus());
        }
    }

    @Test
    public void breachedPasswordChangeLeavesEnvelopeUnchanged() throws Exception {
        awaitSuccess(callback -> coordinator.createVault(PASSWORD.toCharArray(), callback));
        SafeKeySession.unlockAfterAuthentication();
        String original = store.load().getWrappedDatabaseKey();
        String next = "violet otters wander beside rivers";
        try (ActivityScenario<ChangeMasterPasswordActivity> scenario =
                     ActivityScenario.launch(ChangeMasterPasswordActivity.class)) {
            scenario.onActivity(activity -> {
                ((EditText) activity.findViewById(R.id.editCurrentMasterPassword)).setText(PASSWORD);
                ((EditText) activity.findViewById(R.id.editNewMasterPassword)).setText(next);
                ((EditText) activity.findViewById(R.id.editConfirmNewMasterPassword)).setText(next);
                activity.findViewById(R.id.buttonSaveMasterPassword).performClick();
            });
            CallbackTimeoutDiagnostics.await(source.requested, 30L);
            source.callback.onSuccess(suffix(next) + ":9\r\n");
            drainCheck();
            scenario.onActivity(activity -> assertEquals(
                    activity.getString(R.string.master_password_breached_rejected),
                    ((TextView) activity.findViewById(R.id.textMasterPasswordChangeMessage))
                            .getText().toString()));
            assertEquals(original, store.load().getWrappedDatabaseKey());
        }
    }

    private void submitSignup(ActivityScenario<SignUpActivity> scenario) {
        scenario.onActivity(activity -> {
            ((EditText) activity.findViewById(R.id.editMasterPassword)).setText(PASSWORD);
            ((EditText) activity.findViewById(R.id.editConfirmPassword)).setText(PASSWORD);
            activity.findViewById(R.id.buttonCreateVault).performClick();
        });
    }

    private void offlineResponse() throws Exception {
        CallbackTimeoutDiagnostics.await(source.requested, 30L);
        source.callback.onError(new java.io.IOException("Test offline response"));
        drainCheck();
    }

    private static AlertDialog dialog(SignUpActivity activity) {
        try {
            Field field = SignUpActivity.class.getDeclaredField("offlineDialog");
            field.setAccessible(true);
            return (AlertDialog) field.get(activity);
        } catch (ReflectiveOperationException error) { throw new AssertionError(error); }
    }

    private void setHealth(MasterPasswordHealth health) throws Exception {
        Field field = SafeKeyApplication.class.getDeclaredField("masterPasswordHealth");
        field.setAccessible(true);
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            try { field.set(app, health); }
            catch (IllegalAccessException error) { throw new AssertionError(error); }
        });
    }

    private void drainCheck() throws Exception {
        Field coordinatorField = MasterPasswordHealth.class.getDeclaredField("coordinator");
        coordinatorField.setAccessible(true);
        Field workerField = PasswordBreachCoordinator.class.getDeclaredField("workerExecutor");
        workerField.setAccessible(true);
        ExecutorService worker = (ExecutorService) workerField.get(coordinatorField.get(testHealth));
        CountDownLatch finished = new CountDownLatch(1);
        worker.execute(finished::countDown);
        CallbackTimeoutDiagnostics.await(finished, 30L);
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
    }

    private static String suffix(String password) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-1")
                .digest(password.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder();
        for (byte value : hash) { result.append(String.format(Locale.US, "%02X", value & 255)); }
        Arrays.fill(hash, (byte) 0);
        return result.substring(5);
    }

    private static void awaitSuccess(Operation operation) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        operation.run(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { done.countDown(); }
            @Override public void onError(Exception error) { failure.set(error); done.countDown(); }
        });
        CallbackTimeoutDiagnostics.await(done, 30L);
        if (failure.get() != null) { throw failure.get(); }
    }

    private interface Operation { void run(VaultDataService.SimpleCallback callback); }

    private static void finishActivities() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            Set<Activity> activities = new HashSet<>();
            for (Stage stage : new Stage[]{Stage.CREATED, Stage.STARTED, Stage.RESUMED, Stage.PAUSED,
                    Stage.STOPPED}) {
                activities.addAll(ActivityLifecycleMonitorRegistry.getInstance()
                        .getActivitiesInStage(stage));
            }
            for (Activity activity : new ArrayList<>(activities)) { activity.finish(); }
        });
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
    }

    private static final class FakeSource implements HibpRangeSource {
        private final CountDownLatch requested = new CountDownLatch(1);
        private volatile Callback callback;
        @Override public void fetchRange(String prefix, Callback callback) {
            this.callback = callback;
            requested.countDown();
        }
    }
}

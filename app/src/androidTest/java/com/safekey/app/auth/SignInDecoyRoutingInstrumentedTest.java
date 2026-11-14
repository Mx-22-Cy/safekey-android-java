package com.safekey.app.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry;
import androidx.test.runner.lifecycle.Stage;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.DecoyVaultStorage;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/**
 * Destructive, disposable-emulator-only integration tests.
 * Creates temporary real and Decoy vaults, then deletes their test data.
 * Never configure a Panic password or exercise destructive Panic Sign In here.
 */
@RunWith(AndroidJUnit4.class)
public final class SignInDecoyRoutingInstrumentedTest {
    private static final String REAL_PASSWORD = "test real vault master password 2026";
    private static final String DECOY_PASSWORD = "test separate decoy password 2026";
    private static final long TIMEOUT_MILLIS = 30_000L;

    private Context context;
    private SafeKeyApplication app;
    private SecureVaultCoordinator real;
    private DecoyVaultCoordinator decoy;

    @Before
    public void setUp() throws Exception {
        finishAuthenticationActivities();
        context = InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
        app = (SafeKeyApplication) context;
        real = app.getSecureVaultCoordinator();
        decoy = app.getDecoyVaultCoordinator();
        SafeKeySession.lock();
        awaitSuccess(real::closeVault);
        awaitSuccess(decoy::closeDecoyVault);

        // Test fixture only: both vaults and their envelopes are disposable.
        new VaultKeyEnvelopeStore(context).clear();
        VaultKeyEnvelopeStore.forDecoy(context).clear();
        context.deleteDatabase("safekey.db");
        context.deleteDatabase(DecoyVaultStorage.DATABASE_NAME);
        DecoyVaultStorage.ensureDatabaseFile(context);

        char[] realPassword = REAL_PASSWORD.toCharArray();
        char[] decoyPassword = DECOY_PASSWORD.toCharArray();
        try {
            awaitSuccess(callback -> real.createVault(realPassword, callback));
            awaitSuccess(callback -> decoy.createDecoyVault(decoyPassword, callback));
        } finally {
            Arrays.fill(realPassword, '\0');
            Arrays.fill(decoyPassword, '\0');
        }
        SafeKeySession.lock();
        awaitSuccess(real::closeVault);
        awaitSuccess(decoy::closeDecoyVault);
    }

    @After
    public void tearDown() throws Exception {
        finishAuthenticationActivities();
        SafeKeySession.lock();
        if (real != null) awaitSuccess(real::closeVault);
        if (decoy != null) awaitSuccess(decoy::closeDecoyVault);
        if (context != null) {
            new VaultKeyEnvelopeStore(context).clear();
            VaultKeyEnvelopeStore.forDecoy(context).clear();
            context.deleteDatabase("safekey.db");
            context.deleteDatabase(DecoyVaultStorage.DATABASE_NAME);
            DecoyVaultStorage.ensureDatabaseFile(context);
        }
    }

    @Test
    public void decoyPasswordOpensOnlyDecoyHome() throws Exception {
        try (ActivityScenario<SignInActivity> scenario = launch(false)) {
            enterPassword(scenario, DECOY_PASSWORD);
            awaitCondition(this::isHomeResumed);
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
            assertEquals(SafeKeyApplication.ActiveVault.DECOY, app.getActiveVault());
            assertTrue(decoy.isDecoyVaultOpen());
            assertFalse(real.isVaultOpen());
        }
    }

    @Test
    public void decoyPasswordCannotSatisfyMasterOnlyRequest() throws Exception {
        try (ActivityScenario<SignInActivity> scenario = launch(true)) {
            enterPassword(scenario, DECOY_PASSWORD);
            awaitCondition(() -> isErrorVisible(scenario));
            assertEquals(SessionState.LOCKED, SafeKeySession.getState());
            assertFalse(real.isVaultOpen());
            assertFalse(decoy.isDecoyVaultOpen());
            assertFalse(isHomeResumed());
        }
    }

    @Test
    public void unknownPasswordDoesNotUnlockEitherVault() throws Exception {
        try (ActivityScenario<SignInActivity> scenario = launch(false)) {
            enterPassword(scenario, "test unrelated unknown password 2026");
            awaitCondition(() -> isErrorVisible(scenario));
            assertEquals(SessionState.LOCKED, SafeKeySession.getState());
            assertFalse(real.isVaultOpen());
            assertFalse(decoy.isDecoyVaultOpen());
            assertFalse(isHomeResumed());
        }
    }

    private ActivityScenario<SignInActivity> launch(boolean masterRequired) {
        Intent intent = new Intent(context, SignInActivity.class);
        intent.putExtra(SignInActivity.REQUIRE_MASTER_PASSWORD, masterRequired);
        return ActivityScenario.launch(intent);
    }

    private static void enterPassword(ActivityScenario<SignInActivity> scenario,
                                      String suppliedPassword) {
        scenario.onActivity(activity -> {
            EditText input = activity.findViewById(R.id.editMasterPassword);
            input.setText(suppliedPassword);
            activity.findViewById(R.id.buttonUnlockVault).performClick();
        });
    }

    private static boolean isErrorVisible(ActivityScenario<SignInActivity> scenario) {
        AtomicBoolean visible = new AtomicBoolean();
        scenario.onActivity(activity -> {
            TextView message = activity.findViewById(R.id.textValidationMessage);
            Button submit = activity.findViewById(R.id.buttonUnlockVault);
            visible.set(message.getText() != null && message.length() > 0
                    && submit.isEnabled());
        });
        return visible.get();
    }

    private boolean isHomeResumed() {
        AtomicBoolean found = new AtomicBoolean();
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            for (Activity activity : new ArrayList<>(
                    ActivityLifecycleMonitorRegistry.getInstance()
                            .getActivitiesInStage(Stage.RESUMED))) {
                if (activity instanceof HomeActivity) {
                    found.set(true);
                }
            }
        });
        return found.get();
    }

    private static void awaitCondition(BooleanSupplier condition) throws Exception {
        long until = SystemClock.elapsedRealtime() + TIMEOUT_MILLIS;
        while (SystemClock.elapsedRealtime() < until) {
            if (condition.getAsBoolean()) return;
            SystemClock.sleep(75L);
        }
        throw new AssertionError("Timed out waiting for Sign In routing result.");
    }

    private static void awaitSuccess(Operation operation) throws Exception {
        CountDownLatch completed = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<Exception> failure =
                new java.util.concurrent.atomic.AtomicReference<>();
        operation.run(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { completed.countDown(); }
            @Override public void onError(Exception error) {
                failure.set(error);
                completed.countDown();
            }
        });
        if (!completed.await(30, TimeUnit.SECONDS)) {
            throw new AssertionError("Timed out waiting for vault fixture operation.");
        }
        if (failure.get() != null) throw failure.get();
    }

    private static void finishAuthenticationActivities() {
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
                if (activity instanceof SignInActivity || activity instanceof HomeActivity) {
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

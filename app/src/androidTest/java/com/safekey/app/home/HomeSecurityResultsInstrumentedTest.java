package com.safekey.app.home;

import android.app.Activity;
import android.content.Context;
import android.os.SystemClock;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry;
import androidx.test.runner.lifecycle.Stage;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.alerts.AlertsActivity;
import com.safekey.app.breach.PasswordBreachResult.Status;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.Assert.assertEquals;

/** Saved fixture results make UI assertions independent of the network. */
@RunWith(AndroidJUnit4.class)
public class HomeSecurityResultsInstrumentedTest {
    private static final String STRONG = "jD7!Qp4#Wm9$Lv2@Zt6%Rx8&";
    private static final String REUSED = "uP8%Xv3!Ka7#Bn2$Ft9@Qw6&";
    private Context context;
    private SecureVaultCoordinator coordinator;

    @Before public void setUp() throws Exception {
        finishActivities();
        context = InstrumentationRegistry.getInstrumentation().getTargetContext().getApplicationContext();
        coordinator = ((SafeKeyApplication) context).getSecureVaultCoordinator();
        SafeKeySession.lock();
        success(coordinator::closeVault);
        new TotpSecretStore(context).clear();
        new VaultKeyEnvelopeStore(context).clear();
        context.deleteDatabase("safekey.db");
        char[] password = "public home security test vault".toCharArray();
        try { success(callback -> coordinator.createVault(password, callback)); }
        finally { Arrays.fill(password, '\0'); }
        SafeKeySession.unlockAfterAuthentication();
    }

    @After public void tearDown() throws Exception {
        finishActivities();
        SafeKeySession.lock();
        success(coordinator::closeVault);
        new TotpSecretStore(context).clear();
        new VaultKeyEnvelopeStore(context).clear();
        context.deleteDatabase("safekey.db");
    }

    @Test public void emptyVaultShowsRealZerosAndNoInventedScore() throws Exception {
        try (ActivityScenario<HomeActivity> scenario = ActivityScenario.launch(HomeActivity.class)) {
            await(() -> matches(scenario, R.id.textHomeSecurityStatus,
                    context.getString(R.string.security_no_credentials)));
            scenario.onActivity(activity -> {
                assertEquals("0", text(activity, R.id.textAtRiskCount));
                assertEquals("0", text(activity, R.id.textBreachCount));
                assertEquals(activity.getString(R.string.security_no_credentials),
                        activity.findViewById(R.id.securityScoreView).getContentDescription());
            });
        }
    }

    @Test public void uncheckedCredentialShowsNotCheckedAndKnownWeakRisk() throws Exception {
        add("Weak fixture", "password", false);
        try (ActivityScenario<HomeActivity> scenario = ActivityScenario.launch(HomeActivity.class)) {
            await(() -> matches(scenario, R.id.textHomeSecurityStatus,
                    context.getString(R.string.security_not_checked)));
            scenario.onActivity(activity -> {
                assertEquals("1", text(activity, R.id.textAtRiskCount));
                assertEquals("0", text(activity, R.id.textBreachCount));
                assertEquals(activity.getString(R.string.security_not_checked),
                        activity.findViewById(R.id.securityScoreView).getContentDescription());
            });
        }
    }

    @Test public void homeScoreAndAlertsGroupsUseSameSavedResults() throws Exception {
        add("Clean fixture", STRONG, true);
        add("Weak fixture", "password", true);
        add("Reuse A", REUSED, true);
        add("Reuse B", REUSED, true);
        try (ActivityScenario<HomeActivity> scenario = ActivityScenario.launch(HomeActivity.class)) {
            await(() -> matches(scenario, R.id.textAtRiskCount, "3"));
            scenario.onActivity(activity -> {
                assertEquals("0", text(activity, R.id.textBreachCount));
                assertEquals(activity.getString(R.string.home_security_score_accessibility, 25),
                        activity.findViewById(R.id.securityScoreView).getContentDescription());
            });
        }
        try (ActivityScenario<AlertsActivity> scenario = ActivityScenario.launch(AlertsActivity.class)) {
            await(() -> {
                AtomicBoolean matches = new AtomicBoolean();
                scenario.onActivity(activity -> matches.set(
                        ((LinearLayout) activity.findViewById(R.id.layoutAlertsAttentionCards))
                                .getChildCount() == 3));
                return matches.get();
            });
            scenario.onActivity(activity -> {
                assertEquals(1, ((LinearLayout) activity.findViewById(R.id.layoutAlertsPassedCards))
                        .getChildCount());
                assertEquals(0, ((LinearLayout) activity.findViewById(R.id.layoutAlertsBreachedCards))
                        .getChildCount());
                activity.findViewById(R.id.filterAlertsPassed).performClick();
                assertEquals(View.GONE, activity.findViewById(R.id.layoutAlertsAttentionSection).getVisibility());
                assertEquals(View.VISIBLE, activity.findViewById(R.id.layoutAlertsPassedSection).getVisibility());
            });
        }
    }

    @Test public void failedCredentialLoadShowsUnavailableInsteadOfZeroResults() throws Exception {
        success(coordinator::closeVault);
        try (ActivityScenario<HomeActivity> scenario = ActivityScenario.launch(HomeActivity.class)) {
            await(() -> matches(scenario, R.id.textHomeSecurityStatus,
                    context.getString(R.string.security_unavailable)));
            scenario.onActivity(activity -> {
                assertEquals("\u2014", text(activity, R.id.textAtRiskCount));
                assertEquals("\u2014", text(activity, R.id.textBreachCount));
            });
        }
    }

    private void add(String title, String password, boolean completed) throws Exception {
        Long id = HomeSecurityResultsInstrumentedTest.<Long>result(callback -> coordinator.addCredential(new Credential(title, "test@example.com",
                password, "https://example.com", "Work", ""), callback));
        if (completed) {
            HomeSecurityResultsInstrumentedTest.<Status>result(callback -> coordinator.updateCredentialBreachStatus(coordinator.getVaultGeneration(),
                    id, password, Status.NOT_FOUND, callback));
        }
    }

    private static boolean matches(ActivityScenario<HomeActivity> scenario, int id, String expected) {
        AtomicBoolean matches = new AtomicBoolean();
        scenario.onActivity(activity -> matches.set(expected.equals(text(activity, id))));
        return matches.get();
    }

    private static String text(Activity activity, int id) {
        return ((TextView) activity.findViewById(id)).getText().toString();
    }

    private static void await(BooleanSupplier condition) {
        long end = SystemClock.elapsedRealtime() + 15_000L;
        while (!condition.getAsBoolean()) {
            if (SystemClock.elapsedRealtime() >= end) {
                throw CallbackTimeoutDiagnostics.timeout("Timed out waiting for security results UI.");
            }
            SystemClock.sleep(50L);
        }
    }

    private interface Simple { void run(VaultDataService.SimpleCallback callback); }
    private interface Result<T> { void run(VaultDataService.ResultCallback<T> callback); }

    private static void success(Simple operation) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        operation.run(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { done.countDown(); }
            @Override public void onError(Exception failure) { error.set(failure); done.countDown(); }
        });
        CallbackTimeoutDiagnostics.await(done, 30L);
        if (error.get() != null) { throw error.get(); }
    }

    private static <T> T result(Result<T> operation) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<T> value = new AtomicReference<>();
        AtomicReference<Exception> error = new AtomicReference<>();
        operation.run(new VaultDataService.ResultCallback<T>() {
            @Override public void onSuccess(T result) { value.set(result); done.countDown(); }
            @Override public void onError(Exception failure) { error.set(failure); done.countDown(); }
        });
        CallbackTimeoutDiagnostics.await(done, 30L);
        if (error.get() != null) { throw error.get(); }
        return value.get();
    }

    private static void finishActivities() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            Set<Activity> activities = new HashSet<>();
            for (Stage stage : new Stage[]{Stage.CREATED, Stage.STARTED, Stage.RESUMED,
                    Stage.PAUSED, Stage.STOPPED}) {
                activities.addAll(ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(stage));
            }
            for (Activity activity : activities) { activity.finish(); }
        });
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
    }
}

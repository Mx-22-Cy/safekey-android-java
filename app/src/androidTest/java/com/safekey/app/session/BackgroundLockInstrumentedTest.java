package com.safekey.app.session;

import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.session.logic.VaultSessionManager;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/** Tests lifecycle/session wiring without creating or deleting vault records. */
@RunWith(AndroidJUnit4.class)
public class BackgroundLockInstrumentedTest {

    private final AtomicLong clock = new AtomicLong(10_000L);
    private final AtomicInteger cleanups = new AtomicInteger();
    private final CountDownLatch cleanupObserved = new CountDownLatch(1);
    private final CountDownLatch signInResumed = new CountDownLatch(1);
    private final AtomicReference<Activity> resumed = new AtomicReference<>();
    private final Set<Activity> live =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private SafeKeyApplication application;
    private long originalTimeout =
            VaultSessionManager.DEFAULT_INACTIVITY_TIMEOUT_MILLIS;
    private Application.ActivityLifecycleCallbacks callbacks;

    @Before
    public void setUp() throws Exception {
        application = (SafeKeyApplication) InstrumentationRegistry
                .getInstrumentation().getTargetContext().getApplicationContext();

        // Drain real connections before substituting a cleanup counter.
        CountDownLatch ready = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        onMain(() -> {
            originalTimeout = SafeKeySession.getInactivityTimeoutMillis();
            SafeKeySession.lock();
            application.prepareForVaultAuthentication(
                    new VaultDataService.SimpleCallback() {
                        @Override public void onSuccess() { ready.countDown(); }
                        @Override public void onError(Exception failure) {
                            error.set(failure);
                            ready.countDown();
                        }
                    });
        });
        assertTrue("Authentication cleanup did not finish.",
                ready.await(15, TimeUnit.SECONDS));
        if (error.get() != null) {
            throw new AssertionError("Authentication cleanup failed.", error.get());
        }

        callbacks = new Application.ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity activity, Bundle state) {
                if (activity instanceof BackgroundLockTestActivity
                        || activity instanceof SignInActivity) {
                    live.add(activity);
                }
            }
            @Override public void onActivityStarted(Activity activity) { }
            @Override public void onActivityResumed(Activity activity) {
                resumed.set(activity);
                if (activity instanceof SignInActivity) {
                    signInResumed.countDown();
                }
            }
            @Override public void onActivityPaused(Activity activity) {
                resumed.compareAndSet(activity, null);
            }
            @Override public void onActivityStopped(Activity activity) { }
            @Override public void onActivitySaveInstanceState(
                    Activity activity, Bundle state) { }
            @Override public void onActivityDestroyed(Activity activity) {
                live.remove(activity);
                resumed.compareAndSet(activity, null);
            }
        };

        onMain(() -> {
            application.registerActivityLifecycleCallbacks(callbacks);
            SafeKeySession.unregisterSensitiveDataCleanup();
            SafeKeySession.setClockForTesting(clock::get);
            SafeKeySession.setInactivityTimeoutMillis(
                    VaultSessionManager.DEFAULT_INACTIVITY_TIMEOUT_MILLIS);
            SafeKeySession.registerSensitiveDataCleanup(() -> {
                cleanups.incrementAndGet();
                cleanupObserved.countDown();
            });
            SafeKeySession.unlockAfterAuthentication();
        });
    }

    @After
    public void tearDown() {
        try {
            onMain(() -> {
                for (Activity activity : new ArrayList<>(live)) {
                    if (!activity.isFinishing() && !activity.isDestroyed()) {
                        activity.finish();
                    }
                }
            });
            awaitCondition("Test Activities did not finish.", () -> {
                AtomicReference<Boolean> empty = new AtomicReference<>(false);
                onMain(() -> empty.set(live.isEmpty()));
                return empty.get();
            });
        } finally {
            onMain(() -> {
                if (application != null && callbacks != null) {
                    application.unregisterActivityLifecycleCallbacks(callbacks);
                }
                SafeKeySession.lock();
                SafeKeySession.resetClockForTesting();
                SafeKeySession.setInactivityTimeoutMillis(originalTimeout);
                SafeKeySession.unregisterSensitiveDataCleanup();
                if (application != null) {
                    application.registerSessionCleanup();
                }
            });
        }
    }

    @Test
    public void backgroundingLocksBeforeClockAdvancesAndReturnRequiresSignIn()
            throws Exception {
        try (ActivityScenario<BackgroundLockTestActivity> scenario =
                     ActivityScenario.launch(BackgroundLockTestActivity.class)) {
            long authentication = SafeKeySession.getManager()
                    .getAuthenticationGeneration();
            assertTrue(authentication >= 0L);
            scenario.moveToState(Lifecycle.State.CREATED);
            InstrumentationRegistry.getInstrumentation().waitForIdleSync();
            assertEquals(SessionState.LOCKED, SafeKeySession.getState());
            assertEquals(10_000L, clock.get());
            assertEquals(1, cleanups.get());
            assertFalse(SafeKeySession.getManager()
                    .runIfCurrentAuthentication(authentication,
                            () -> { throw new AssertionError("Stale session ran."); }));
            scenario.moveToState(Lifecycle.State.RESUMED);
            assertTrue("Sign In did not appear after background locking.",
                    signInResumed.await(10, TimeUnit.SECONDS));
        }
    }

    @Test
    public void internalNavigationDoesNotLock() throws Exception {
        try (ActivityScenario<BackgroundLockTestActivity> scenario =
                     ActivityScenario.launch(BackgroundLockTestActivity.class)) {
            scenario.onActivity(activity -> activity.startActivity(
                    new Intent(activity, BackgroundLockTestActivity.Second.class)));
            awaitCondition("Second test screen did not resume.",
                    () -> resumed.get() instanceof BackgroundLockTestActivity.Second);
            assertFalse("Internal navigation caused a background lock.",
                    cleanupObserved.await(1500, TimeUnit.MILLISECONDS));
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
        }
    }

    @Test
    public void activityRecreationDoesNotLock() throws Exception {
        try (ActivityScenario<BackgroundLockTestActivity> scenario =
                     ActivityScenario.launch(BackgroundLockTestActivity.class)) {
            scenario.recreate();
            assertFalse("Configuration recreation caused a background lock.",
                    cleanupObserved.await(1500, TimeUnit.MILLISECONDS));
            assertEquals(SessionState.UNLOCKED, SafeKeySession.getState());
        }
    }

    @Test
    public void shorteningPolicyRearmsTheResumedScreenTimer() throws Exception {
        onMain(() -> SafeKeySession.setInactivityTimeoutMillis(60_000L));
        try (ActivityScenario<BackgroundLockTestActivity> scenario =
                     ActivityScenario.launch(BackgroundLockTestActivity.class)) {
            onMain(() -> {
                clock.addAndGet(100L);
                SafeKeySession.setInactivityTimeoutMillis(120L);
                clock.addAndGet(20L);
            });
            assertTrue("The updated foreground timer did not redirect.",
                    signInResumed.await(10, TimeUnit.SECONDS));
            assertEquals(SessionState.LOCKED, SafeKeySession.getState());
        }
    }

    @Test
    public void detachedTimeoutObserverReceivesNoFurtherUpdates() {
        AtomicInteger notifications = new AtomicInteger();
        AtomicReference<SafeKeySession.TimeoutRegistration> registration =
                new AtomicReference<>();
        onMain(() -> registration.set(
                SafeKeySession.observeTimeoutChanges(notifications::incrementAndGet)));
        try {
            onMain(() -> {
                SafeKeySession.setInactivityTimeoutMillis(60_000L);
                SafeKeySession.setInactivityTimeoutMillis(900_000L);
                assertEquals(2, notifications.get());
                registration.get().close();
                SafeKeySession.setInactivityTimeoutMillis(300_000L);
                assertEquals(2, notifications.get());
            });
        } finally {
            onMain(() -> registration.get().close());
        }
    }

    @Test
    public void applicationPolicyChangeRequiresAnActiveAuthenticatedVault() {
        onMain(() -> {
            long previous = application.getAutoLockTimeoutMillis();
            assertThrows(IllegalStateException.class,
                    () -> application.setAutoLockTimeoutMillis(60_000L));
            assertEquals(previous, application.getAutoLockTimeoutMillis());
        });
    }

    @Test
    public void backgroundingWhileAlreadyLockedStillInvalidatesPendingWork() {
        onMain(() -> {
            SafeKeySession.lock();
            cleanups.set(0);
        });
        try (ActivityScenario<SignInActivity> scenario =
                     ActivityScenario.launch(SignInActivity.class)) {
            scenario.moveToState(Lifecycle.State.CREATED);
            InstrumentationRegistry.getInstrumentation().waitForIdleSync();
            assertEquals(SessionState.LOCKED, SafeKeySession.getState());
            assertEquals(1, cleanups.get());
        }
    }

    private static void onMain(Runnable action) {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(action);
    }

    private static void awaitCondition(String message, BooleanSupplier condition) {
        long deadline = SystemClock.elapsedRealtime() + 10_000L;
        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            SystemClock.sleep(25L);
        }
        assertTrue(message, condition.getAsBoolean());
    }
}

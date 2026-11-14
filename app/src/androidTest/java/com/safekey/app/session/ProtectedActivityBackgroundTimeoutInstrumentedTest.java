package com.safekey.app.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.os.SystemClock;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.safekey.app.SafeKeyApplication;

import com.safekey.app.auth.SignInActivity;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.session.logic.SessionState;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class ProtectedActivityBackgroundTimeoutInstrumentedTest {

    private final AtomicLong nowMillis = new AtomicLong();

    @Before
    public void setUp() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        SafeKeySession.lock();

        nowMillis.set(SystemClock.elapsedRealtime());
        SafeKeySession.setClockForTesting(nowMillis::get);
    }

    @After
    public void tearDown() {
        SafeKeySession.lock();
        SafeKeySession.resetClockForTesting();
        SafeKeySession.unregisterSensitiveDataCleanup();
        ((SafeKeyApplication) InstrumentationRegistry
                .getInstrumentation()
                .getTargetContext()
                .getApplicationContext())
                .registerSessionCleanup();
    }

    @Test
    public void backgrounding_locksBeforeResume_andRedirectsToSignIn()
            throws InterruptedException {

        Application application =
                (Application) InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext()
                        .getApplicationContext();

        CountDownLatch homePaused = new CountDownLatch(1);
        CountDownLatch homeDestroyed = new CountDownLatch(1);
        CountDownLatch signInResumed = new CountDownLatch(1);
        AtomicReference<Activity> signInActivity =
                new AtomicReference<>();

        Application.ActivityLifecycleCallbacks callbacks =
                new Application.ActivityLifecycleCallbacks() {
                    @Override
                    public void onActivityCreated(
                            Activity activity,
                            Bundle savedInstanceState
                    ) {
                    }

                    @Override
                    public void onActivityStarted(Activity activity) {
                    }

                    @Override
                    public void onActivityResumed(Activity activity) {
                        if (activity instanceof SignInActivity
                                && homePaused.getCount() == 0L) {
                            signInActivity.set(activity);
                            signInResumed.countDown();
                        }
                    }

                    @Override
                    public void onActivityPaused(Activity activity) {
                        if (activity instanceof HomeActivity) {
                            homePaused.countDown();
                        }
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
                        if (activity instanceof HomeActivity) {
                            homeDestroyed.countDown();
                        }
                    }
                };

        application.registerActivityLifecycleCallbacks(callbacks);

        try {
            SafeKeySession.unlockAfterAuthentication();

            try (ActivityScenario<HomeActivity> scenario =
                         ActivityScenario.launch(HomeActivity.class)) {

                assertEquals(
                        SessionState.UNLOCKED,
                        SafeKeySession.getState()
                );

                scenario.moveToState(Lifecycle.State.CREATED);
                InstrumentationRegistry.getInstrumentation().waitForIdleSync();

                assertTrue(
                        "Home did not pause",
                        homePaused.await(10, TimeUnit.SECONDS)
                );
                assertEquals(
                        Lifecycle.State.CREATED,
                        scenario.getState()
                );
                assertEquals(
                        SessionState.LOCKED,
                        SafeKeySession.getState()
                );

                scenario.moveToState(Lifecycle.State.RESUMED);

                assertTrue(
                        "Sign In did not resume after background locking",
                        signInResumed.await(10, TimeUnit.SECONDS)
                );
                assertTrue(
                        "Home was not destroyed after redirect",
                        homeDestroyed.await(10, TimeUnit.SECONDS)
                );
                assertEquals(
                        SessionState.LOCKED,
                        SafeKeySession.getState()
                );
            }
        } finally {
            application.unregisterActivityLifecycleCallbacks(callbacks);

            InstrumentationRegistry.getInstrumentation()
                    .runOnMainSync(() -> {
                        Activity signIn = signInActivity.get();

                        if (signIn != null && !signIn.isFinishing()) {
                            signIn.finish();
                        }
                    });
        }
    }
}

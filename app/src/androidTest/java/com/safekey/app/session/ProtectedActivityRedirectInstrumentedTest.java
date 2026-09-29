package com.safekey.app.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.os.Bundle;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.auth.SignInActivity;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.vault.VaultActivity;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class ProtectedActivityRedirectInstrumentedTest {

    @Test
    public void lockedHome_redirectsToSignIn() throws InterruptedException {
        assertLockedActivityRedirectsToSignIn(HomeActivity.class);
    }

    @Test
    public void lockedVault_redirectsToSignIn() throws InterruptedException {
        assertLockedActivityRedirectsToSignIn(VaultActivity.class);
    }

    private void assertLockedActivityRedirectsToSignIn(
            Class<? extends Activity> protectedClass
    ) throws InterruptedException {
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
                    "Sign In did not resume after opening a locked screen",
                    signInResumed.await(10, TimeUnit.SECONDS)
            );
            assertNotNull(protectedActivity.get());
            assertTrue(
                    "The protected screen was not finishing",
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
                        Activity protectedScreen = protectedActivity.get();

                        if (signIn != null && !signIn.isFinishing()) {
                            signIn.finish();
                        }
                        if (protectedScreen != null
                                && !protectedScreen.isFinishing()) {
                            protectedScreen.finish();
                        }
                    });

            SafeKeySession.lock();
        }
    }
}

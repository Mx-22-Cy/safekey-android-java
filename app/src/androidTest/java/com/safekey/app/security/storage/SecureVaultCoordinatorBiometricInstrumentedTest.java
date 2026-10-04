package com.safekey.app.security.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.os.SystemClock;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.auth.SignInActivity;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.biometric.BiometricAuthenticator;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class SecureVaultCoordinatorBiometricInstrumentedTest {

    private static final String DATABASE_NAME =
            "safekey.db";

    private static final long CALLBACK_TIMEOUT_SECONDS =
            30;

    private Context context;
    private SecureVaultCoordinator coordinator;

    @Before
    public void setUp() {

        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        clearStoredVault();

        coordinator =
                new SecureVaultCoordinator(
                        context
                );
    }

    @After
    public void tearDown() {

        shutdownCoordinator();

        clearStoredVault();

        context = null;
    }

    @Test
    public void getBiometricAvailability_returnsResult() {

        try (
                ActivityScenario<SignInActivity> scenario =
                        ActivityScenario.launch(
                                SignInActivity.class
                        )
        ) {

            AtomicReference<BiometricAuthenticator.Availability> availability =
                    new AtomicReference<>();

            scenario.onActivity(
                    activity ->
                            availability.set(
                                    coordinator.getBiometricAvailability(
                                            activity
                                    )
                            )
            );

            assertNotNull(
                    availability.get()
            );
        }
    }

    @Test
    public void enableBiometricUnlock_withNullCallback_isRejected() {

        char[] masterPassword =
                "correct horse battery staple"
                        .toCharArray();

        try (
                ActivityScenario<SignInActivity> scenario =
                        ActivityScenario.launch(
                                SignInActivity.class
                        )
        ) {

            scenario.onActivity(
                    activity -> {

                        NullPointerException exception =
                                assertThrows(
                                        NullPointerException.class,
                                        () ->
                                                coordinator.enableBiometricUnlock(
                                                        activity,
                                                        masterPassword,
                                                        "Enable biometric unlock",
                                                        "Confirm your identity",
                                                        null
                                                )
                                );

                        assertEquals(
                                "callback",
                                exception.getMessage()
                        );
                    }
            );

        } finally {

            Arrays.fill(
                    masterPassword,
                    '\0'
            );
        }
    }

    @Test
    public void unlockVaultWithBiometrics_withNullCallback_isRejected() {

        try (
                ActivityScenario<SignInActivity> scenario =
                        ActivityScenario.launch(
                                SignInActivity.class
                        )
        ) {

            scenario.onActivity(
                    activity -> {

                        NullPointerException exception =
                                assertThrows(
                                        NullPointerException.class,
                                        () ->
                                                coordinator.unlockVaultWithBiometrics(
                                                        activity,
                                                        "Unlock SafeKey",
                                                        "Confirm your identity",
                                                        null
                                                )
                                );

                        assertEquals(
                                "callback",
                                exception.getMessage()
                        );
                    }
            );
        }
    }

    @Test
    public void enableBiometricUnlock_withoutVault_reportsError()
            throws Exception {

        CountDownLatch latch =
                new CountDownLatch(
                        1
                );

        AtomicReference<String> errorMessage =
                new AtomicReference<>();

        AtomicReference<Boolean> unexpectedlyEnabled =
                new AtomicReference<>(
                        false
                );

        char[] masterPassword =
                "correct horse battery staple"
                        .toCharArray();

        try (
                ActivityScenario<SignInActivity> scenario =
                        ActivityScenario.launch(
                                SignInActivity.class
                        )
        ) {

            scenario.onActivity(
                    activity ->
                            coordinator.enableBiometricUnlock(
                                    activity,
                                    masterPassword,
                                    "Enable biometric unlock",
                                    "Confirm your identity",
                                    new SecureVaultCoordinator.BiometricSetupCallback() {

                                        @Override
                                        public void onEnabled() {

                                            unexpectedlyEnabled.set(
                                                    true
                                            );

                                            latch.countDown();
                                        }

                                        @Override
                                        public void onError(
                                                String message
                                        ) {

                                            errorMessage.set(
                                                    message
                                            );

                                            latch.countDown();
                                        }

                                        @Override
                                        public void onFailed() {

                                            latch.countDown();
                                        }
                                    }
                            )
            );

            assertTrue(
                    "Timed out waiting for biometric setup error.",
                    latch.await(
                            CALLBACK_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS
                    )
            );

            assertEquals(
                    Boolean.FALSE,
                    unexpectedlyEnabled.get()
            );

            assertEquals(
                    "Unable to verify the master password or prepare biometric unlock.",
                    errorMessage.get()
            );

        } finally {

            Arrays.fill(
                    masterPassword,
                    '\0'
            );
        }
    }

    @Test
    public void enableBiometricUnlock_withWrongPassword_reportsError()
            throws Exception {

        char[] correctPassword =
                "correct horse battery staple"
                        .toCharArray();

        char[] wrongPassword =
                "incorrect master password value"
                        .toCharArray();

        try {

            awaitSuccess(
                    callback ->
                            coordinator.createVault(
                                    correctPassword,
                                    callback
                            )
            );

            CountDownLatch latch =
                    new CountDownLatch(
                            1
                    );

            AtomicReference<String> errorMessage =
                    new AtomicReference<>();

            AtomicReference<Boolean> unexpectedlyEnabled =
                    new AtomicReference<>(
                            false
                    );

            try (
                    ActivityScenario<SignInActivity> scenario =
                            ActivityScenario.launch(
                                    SignInActivity.class
                            )
            ) {

                scenario.onActivity(
                        activity ->
                                coordinator.enableBiometricUnlock(
                                        activity,
                                        wrongPassword,
                                        "Enable biometric unlock",
                                        "Confirm your identity",
                                        new SecureVaultCoordinator.BiometricSetupCallback() {

                                            @Override
                                            public void onEnabled() {

                                                unexpectedlyEnabled.set(
                                                        true
                                                );

                                                latch.countDown();
                                            }

                                            @Override
                                            public void onError(
                                                    String message
                                            ) {

                                                errorMessage.set(
                                                        message
                                                );

                                                latch.countDown();
                                            }

                                            @Override
                                            public void onFailed() {

                                                latch.countDown();
                                            }
                                        }
                                )
                );

                assertTrue(
                        "Timed out waiting for wrong-password biometric setup error.",
                        latch.await(
                                CALLBACK_TIMEOUT_SECONDS,
                                TimeUnit.SECONDS
                        )
                );

                assertEquals(
                        Boolean.FALSE,
                        unexpectedlyEnabled.get()
                );

                assertEquals(
                        "Unable to verify the master password or prepare biometric unlock.",
                        errorMessage.get()
                );
            }

        } finally {

            Arrays.fill(
                    correctPassword,
                    '\0'
            );

            Arrays.fill(
                    wrongPassword,
                    '\0'
            );
        }
    }

    private void awaitSuccess(
            AsyncOperation operation
    ) throws Exception {

        CountDownLatch latch =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.run(
                new VaultDataService.SimpleCallback() {

                    @Override
                    public void onSuccess() {

                        latch.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        error.set(
                                exception
                        );

                        latch.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for successful operation.",
                latch.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        if (error.get() != null) {

            throw error.get();
        }
    }

    private void shutdownCoordinator() {

        if (coordinator == null) {

            return;
        }

        coordinator.shutdown();

        long deadline =
                SystemClock.elapsedRealtime()
                        + TimeUnit.SECONDS.toMillis(
                        CALLBACK_TIMEOUT_SECONDS
                );

        while (
                coordinator.isVaultOpen()
                        && SystemClock.elapsedRealtime()
                        < deadline
        ) {

            SystemClock.sleep(
                    50
            );
        }

        coordinator = null;
    }

    private void clearStoredVault() {

        if (context == null) {

            return;
        }

        context.deleteDatabase(
                DATABASE_NAME
        );

        context
                .getSharedPreferences(
                        VaultKeyEnvelopeStore.PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                )
                .edit()
                .clear()
                .commit();
    }

    private interface AsyncOperation {

        void run(
                VaultDataService.SimpleCallback callback
        );
    }
}
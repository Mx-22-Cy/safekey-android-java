package com.safekey.app.security.storage;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.auth.SignInActivity;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;
import com.safekey.app.security.biometric.BiometricVaultKeyManager;
import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.security.totp.TotpState;
import com.safekey.app.security.totp.TotpVerificationService;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.security.totp.VaultUnlockGate;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class SecureVaultCoordinatorTotpInstrumentedTest {

    private static final String PASSWORD = "correct horse battery staple";

    // Public RFC test data only.
    private static final byte[] SECRET =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private static final long WAIT_SECONDS = 30L;

    private Context context;
    private MemoryStore store;
    private FakeBiometrics biometrics;
    private SecureVaultCoordinator coordinator;

    @Before
    public void setUp() {
        SafeKeySession.lock();

        context = new TestContext(
                InstrumentationRegistry.getInstrumentation()
                        .getTargetContext().getApplicationContext()
        );

        new VaultKeyEnvelopeStore(context).clear();
        context.deleteDatabase("safekey.db");

        store = new MemoryStore();

        try (TotpState initial = new TotpState(SECRET, -1L, 0, 0L)) {
            store.replace(initial);
        }

        biometrics = new FakeBiometrics();

        coordinator = new SecureVaultCoordinator(
                context,
                new VaultUnlockGate(
                        store,
                        () -> 59_000L,
                        SystemClock::elapsedRealtime
                ),
                biometrics
        );
    }

    @After
    public void tearDown() throws Exception {
        if (coordinator != null) {
            Outcome closed = new Outcome();
            coordinator.closeVault(closed);
            await(closed.finished);
            coordinator.shutdown();
        }

        if (store != null) {
            store.replace(null);
        }

        if (context != null) {
            new VaultKeyEnvelopeStore(context).clear();
            context.deleteDatabase("safekey.db");
        }

        SafeKeySession.lock();
    }

    @Test
    public void passwordRequiresTotpBeforeDatabaseOpen_andDoesNotUnlockSession()
            throws Exception {
        createClosedVault();

        Outcome outcome = new Outcome();
        VaultUnlockFlow.Request request =
                passwordUnlock(PASSWORD, outcome);

        await(outcome.challenge);

        assertFalse(coordinator.isVaultOpen());
        assertEquals(SessionState.LOCKED, SafeKeySession.getState());

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                submit(request, "000000")
        );

        assertFalse(coordinator.isVaultOpen());

        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                submit(request, "287082")
        );

        await(outcome.finished);

        assertEquals(1, outcome.successes.get());
        assertTrue(coordinator.isVaultOpen());
        assertEquals(SessionState.LOCKED, SafeKeySession.getState());
    }

    @Test
    public void legacyPasswordCallbackCannotBypassTotp() throws Exception {
        createClosedVault();

        Outcome outcome = new Outcome();
        passwordUnlock(PASSWORD, legacy(outcome));

        await(outcome.finished);

        assertNotNull(outcome.error.get());
        assertEquals(0, outcome.successes.get());
        assertFalse(coordinator.isVaultOpen());
    }

    @Test
    public void passwordOnlyUnlockStillWorksWhenTotpIsNotConfigured()
            throws Exception {
        createClosedVault();
        store.replace(null);

        Outcome outcome = new Outcome();
        passwordUnlock(PASSWORD, legacy(outcome));

        await(outcome.finished);

        assertEquals(1, outcome.successes.get());
        assertTrue(coordinator.isVaultOpen());
    }

    @Test
    public void wrongPasswordNeverStartsTotpChallenge() throws Exception {
        createClosedVault();

        Outcome outcome = new Outcome();

        passwordUnlock(
                "this is an incorrect master password",
                outcome
        );

        await(outcome.finished);

        assertNotNull(outcome.error.get());
        assertEquals(1L, outcome.challenge.getCount());
        assertFalse(coordinator.isVaultOpen());
    }

    @Test
    public void cancelledChallengeCannotSubmitCodeOrOpenVault()
            throws Exception {
        createClosedVault();

        Outcome outcome = new Outcome();
        VaultUnlockFlow.Request request =
                passwordUnlock(PASSWORD, outcome);

        await(outcome.challenge);
        request.close();

        assertFalse(request.isActive());

        assertThrows(
                IllegalStateException.class,
                () -> request.submitCode(
                        "287082".toCharArray(),
                        result -> {
                        }
                )
        );

        assertFalse(coordinator.isVaultOpen());
        assertEquals(0, outcome.successes.get());
    }

    @Test
    public void unreadableTotpStateCannotBeTreatedAsDisabled()
            throws Exception {
        createClosedVault();
        store.failLoad = true;

        Outcome outcome = new Outcome();
        passwordUnlock(PASSWORD, outcome);

        await(outcome.finished);

        assertNotNull(outcome.error.get());
        assertEquals(0, outcome.successes.get());
        assertFalse(coordinator.isVaultOpen());
    }

    @Test
    public void biometricResultRequiresTotpBeforeRealDatabaseOpen()
            throws Exception {
        createClosedVault();

        byte[] key = readDatabaseKey();
        Outcome outcome = new Outcome();

        try (ActivityScenario<SignInActivity> scenario =
                     ActivityScenario.launch(SignInActivity.class)) {
            AtomicReference<VaultUnlockFlow.Request> request =
                    new AtomicReference<>();

            scenario.onActivity(activity ->
                    request.set(
                            coordinator.unlockVaultWithBiometrics(
                                    activity,
                                    "Unlock SafeKey",
                                    "Test prompt",
                                    outcome
                            )
                    )
            );

            await(biometrics.started);
            biometrics.callback.get().onUnlocked(key);

            assertArrayEquals(new byte[32], key);

            await(outcome.challenge);
            assertFalse(coordinator.isVaultOpen());

            assertEquals(
                    TotpVerificationService.Status.VERIFIED,
                    submit(request.get(), "287082")
            );

            await(outcome.finished);

            assertEquals(1, outcome.successes.get());
            assertTrue(coordinator.isVaultOpen());
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    @Test
    public void cancelledBiometricResultIsIgnoredAndItsKeyIsCleared()
            throws Exception {
        Outcome outcome = new Outcome();

        try (ActivityScenario<SignInActivity> scenario =
                     ActivityScenario.launch(SignInActivity.class)) {
            AtomicReference<VaultUnlockFlow.Request> request =
                    new AtomicReference<>();

            scenario.onActivity(activity ->
                    request.set(
                            coordinator.unlockVaultWithBiometrics(
                                    activity,
                                    "Unlock SafeKey",
                                    "Test prompt",
                                    outcome
                            )
                    )
            );

            await(biometrics.started);
            request.get().close();

            byte[] lateKey = new byte[32];
            Arrays.fill(lateKey, (byte) 7);

            biometrics.callback.get().onUnlocked(lateKey);
            drainMain();

            assertArrayEquals(new byte[32], lateKey);
            assertEquals(1L, outcome.challenge.getCount());
            assertEquals(0, outcome.successes.get());
            assertFalse(coordinator.isVaultOpen());
        }
    }

    @Test
    public void cancelledQueuedDatabaseOpenCannotDeliverSuccess()
            throws Exception {
        MemoryStore emptyStore = new MemoryStore();
        FakeVault vault = new FakeVault();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        VaultUnlockFlow flow = new VaultUnlockFlow(
                new VaultUnlockGate(emptyStore),
                worker,
                new Handler(Looper.getMainLooper()),
                vault
        );

        Outcome outcome = new Outcome();

        try {
            VaultUnlockFlow.Request request = flow.begin(outcome);
            flow.acceptPrimary(request, new byte[32]);

            await(vault.firstOpen);

            request.close();
            vault.callback(0).onSuccess();
            drainMain();

            assertEquals(0, outcome.successes.get());
            assertEquals(2, vault.closes.get());
        } finally {
            flow.shutdown();
            worker.shutdown();
        }
    }

    @Test
    public void staleOpenCallbackCannotCloseOrCompleteReplacement()
            throws Exception {
        MemoryStore emptyStore = new MemoryStore();
        FakeVault vault = new FakeVault();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        VaultUnlockFlow flow = new VaultUnlockFlow(
                new VaultUnlockGate(emptyStore),
                worker,
                new Handler(Looper.getMainLooper()),
                vault
        );

        Outcome oldOutcome = new Outcome();
        Outcome newOutcome = new Outcome();

        try {
            VaultUnlockFlow.Request old = flow.begin(oldOutcome);
            flow.acceptPrimary(old, new byte[32]);

            await(vault.firstOpen);

            VaultUnlockFlow.Request replacement =
                    flow.begin(newOutcome);

            flow.acceptPrimary(replacement, new byte[32]);

            await(vault.secondOpen);

            vault.callback(1).onSuccess();
            await(newOutcome.finished);

            int closes = vault.closes.get();

            vault.callback(0).onSuccess();
            old.close();
            drainMain();

            assertEquals(1, newOutcome.successes.get());
            assertEquals(0, oldOutcome.successes.get());
            assertEquals(closes, vault.closes.get());
        } finally {
            flow.shutdown();
            worker.shutdown();
        }
    }

    private void createClosedVault() throws Exception {
        Outcome created = new Outcome();
        char[] password = PASSWORD.toCharArray();

        try {
            coordinator.createVault(password, created);
        } finally {
            Arrays.fill(password, '\0');
        }

        await(created.finished);
        assertEquals(1, created.successes.get());

        Outcome closed = new Outcome();
        coordinator.closeVault(closed);

        await(closed.finished);
        assertFalse(coordinator.isVaultOpen());
    }

    private VaultUnlockFlow.Request passwordUnlock(
            String value,
            VaultDataService.SimpleCallback callback
    ) {
        char[] password = value.toCharArray();

        try {
            return coordinator.unlockVault(password, callback);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static VaultDataService.SimpleCallback legacy(Outcome outcome) {
        return new VaultDataService.SimpleCallback() {
            @Override
            public void onSuccess() {
                outcome.onSuccess();
            }

            @Override
            public void onError(Exception error) {
                outcome.onError(error);
            }
        };
    }

    private static TotpVerificationService.Status submit(
            VaultUnlockFlow.Request request,
            String value
    ) throws Exception {
        CountDownLatch done = new CountDownLatch(1);

        AtomicReference<TotpVerificationService.Status> status =
                new AtomicReference<>();

        char[] code = value.toCharArray();

        try {
            request.submitCode(code, result -> {
                status.set(result.getStatus());
                done.countDown();
            });
        } finally {
            Arrays.fill(code, '\0');
        }

        await(done);
        return status.get();
    }

    private byte[] readDatabaseKey() throws Exception {
        VaultKeyEnvelope envelope =
                new VaultKeyEnvelopeStore(context).load();

        byte[] salt = envelope.getSalt();
        byte[] masterKey = null;
        char[] password = PASSWORD.toCharArray();

        try {
            masterKey = new Argon2idMasterKeyDeriver()
                    .deriveKey(password, salt);

            return new AesGcmCipher().decrypt(
                    envelope.getWrappedDatabaseKey(),
                    masterKey,
                    "safekey:database-key-envelope:v1"
                            .getBytes(StandardCharsets.UTF_8)
            );
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(salt, (byte) 0);

            if (masterKey != null) {
                Arrays.fill(masterKey, (byte) 0);
            }
        }
    }

    private static void await(CountDownLatch latch)
            throws InterruptedException {
        CallbackTimeoutDiagnostics.await(latch, WAIT_SECONDS);
    }

    private static void drainMain() throws InterruptedException {
        CountDownLatch done = new CountDownLatch(1);
        new Handler(Looper.getMainLooper()).post(done::countDown);
        await(done);
    }

    private static final class Outcome
            implements SecureVaultCoordinator.TotpUnlockCallback,
            SecureVaultCoordinator.TotpBiometricUnlockCallback,
            VaultUnlockFlow.Listener {

        final CountDownLatch challenge = new CountDownLatch(1);
        final CountDownLatch finished = new CountDownLatch(1);
        final AtomicInteger successes = new AtomicInteger();

        final AtomicReference<Exception> error =
                new AtomicReference<>();

        @Override
        public void onSuccess() {
            successes.incrementAndGet();
            finished.countDown();
        }

        @Override
        public void onError(Exception failure) {
            error.set(failure);
            finished.countDown();
        }

        @Override
        public void onError(String message) {
            onError(new IllegalStateException(message));
        }

        @Override
        public void onTotpRequired(VaultUnlockFlow.Request request) {
            challenge.countDown();
        }

        @Override
        public void onFailed() {
        }
    }

    private static final class FakeBiometrics
            implements SecureVaultCoordinator.BiometricUnlockSource {

        final CountDownLatch started = new CountDownLatch(1);

        final AtomicReference<BiometricVaultKeyManager.UnlockCallback> callback =
                new AtomicReference<>();

        @Override
        public void unlock(
                androidx.fragment.app.FragmentActivity activity,
                String title,
                String subtitle,
                BiometricVaultKeyManager.UnlockCallback result
        ) {
            callback.set(result);
            started.countDown();
        }
    }

    private static final class FakeVault
            implements VaultUnlockFlow.VaultAccess {

        final CountDownLatch firstOpen = new CountDownLatch(1);
        final CountDownLatch secondOpen = new CountDownLatch(1);
        final AtomicInteger closes = new AtomicInteger();

        private final List<VaultDataService.SimpleCallback> callbacks =
                new ArrayList<>();

        @Override
        public synchronized void open(
                byte[] key,
                VaultDataService.SimpleCallback callback
        ) {
            callbacks.add(callback);
            firstOpen.countDown();

            if (callbacks.size() == 2) {
                secondOpen.countDown();
            }
        }

        @Override
        public void close(VaultDataService.SimpleCallback callback) {
            closes.incrementAndGet();
            callback.onSuccess();
        }

        synchronized VaultDataService.SimpleCallback callback(int index) {
            return callbacks.get(index);
        }
    }

    private static final class MemoryStore
            implements TotpVerificationService.StateStore {

        private final Object lock = new Object();
        private TotpState state;
        volatile boolean failLoad;

        @Override
        public Object getTransactionLock() {
            return lock;
        }

        @Override
        public TotpState load() throws IOException {
            requireLock();

            if (failLoad) {
                throw new IOException(
                        "Simulated unreadable TOTP state."
                );
            }

            return copy(state);
        }

        @Override
        public void save(TotpState updated) {
            requireLock();
            replace(updated);
        }

        void replace(TotpState updated) {
            synchronized (lock) {
                TotpState replacement = copy(updated);

                if (state != null) {
                    state.close();
                }

                state = replacement;
            }
        }

        private static TotpState copy(TotpState original) {
            if (original == null) {
                return null;
            }

            byte[] secret = original.copySecret();

            try {
                return new TotpState(
                        secret,
                        original.getLastAcceptedStep(),
                        original.getFailedAttempts(),
                        original.getBlockedUntilEpochMillis()
                );
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
        }

        private void requireLock() {
            if (!Thread.holdsLock(lock)) {
                throw new AssertionError(
                        "Shared TOTP transaction lock is required."
                );
            }
        }
    }

    private static final class TestContext extends ContextWrapper {

        TestContext(Context base) {
            super(base);
        }

        @Override
        public Context getApplicationContext() {
            return this;
        }

        @Override
        public SharedPreferences getSharedPreferences(
                String name,
                int mode
        ) {
            return super.getSharedPreferences(
                    "totp_unlock_test_" + name,
                    mode
            );
        }

        @Override
        public File getDatabasePath(String name) {
            return super.getDatabasePath(
                    "totp_unlock_test_" + name
            );
        }

        @Override
        public boolean deleteDatabase(String name) {
            return super.deleteDatabase(
                    "totp_unlock_test_" + name
            );
        }
    }
}

package com.safekey.app.security.storage;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.security.totp.TotpState;
import com.safekey.app.security.totp.TotpVerificationService;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.security.totp.VaultUnlockGate;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class MasterPasswordBlocklistInstrumentedTest {
    private static final String OLD = "clouds drift quietly over mountains";
    private static final String NEXT = "violet otters wander beside rivers";
    private static final byte[] SECRET =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private Context context;
    private SecureVaultCoordinator coordinator;
    private VaultKeyEnvelopeStore envelopes;
    private MemoryTotp store;

    @Before
    public void setUp() {
        SafeKeySession.lock();
        context = new TestContext(InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext());
        envelopes = new VaultKeyEnvelopeStore(context);
        envelopes.clear();
        context.deleteDatabase("safekey.db");
        store = new MemoryTotp();
        coordinator = new SecureVaultCoordinator(context,
                new VaultUnlockGate(store, () -> 59_000L, SystemClock::elapsedRealtime), null);
    }

    @After
    public void tearDown() throws Exception {
        awaitSuccess(coordinator::closeVault);
        coordinator.shutdown();
        envelopes.clear();
        context.deleteDatabase("safekey.db");
        store.replace(null);
        SafeKeySession.lock();
    }

    @Test
    public void changeRewrapsSameDatabaseKeyAndOnlyNewPasswordUnlocks() throws Exception {
        createAuthenticatedVault();
        byte[] before = databaseKey(envelopes.load(), OLD);
        awaitSuccess(callback -> coordinator.changeMasterPassword(OLD.toCharArray(),
                NEXT.toCharArray(), MasterPasswordCheckStatus.CHECKED, callback));
        byte[] after = databaseKey(envelopes.load(), NEXT);
        try { assertArrayEquals(before, after); }
        finally { Arrays.fill(before, (byte) 0); Arrays.fill(after, (byte) 0); }
        assertEquals(MasterPasswordCheckStatus.CHECKED, envelopes.getMasterPasswordCheckStatus());
        awaitSuccess(coordinator::closeVault);
        Outcome wrong = new Outcome();
        coordinator.unlockVault(OLD.toCharArray(), wrong);
        wrong.await();
        assertNotNull(wrong.error.get());
        assertFalse(coordinator.isVaultOpen());
        awaitSuccess(callback -> coordinator.unlockVault(NEXT.toCharArray(), callback));
        assertTrue(coordinator.isVaultOpen());
    }

    @Test
    public void incorrectCurrentPasswordCannotReplaceEnvelope() throws Exception {
        createAuthenticatedVault();
        String original = envelopes.load().getWrappedDatabaseKey();
        Outcome result = new Outcome();
        coordinator.changeMasterPassword("incorrect current passphrase".toCharArray(),
                NEXT.toCharArray(), MasterPasswordCheckStatus.PENDING, result);
        result.await();
        assertNotNull(result.error.get());
        assertEquals(original, envelopes.load().getWrappedDatabaseKey());
    }

    @Test
    public void lockedSessionAndLocalBlocklistCannotChangePassword() throws Exception {
        createAuthenticatedVault();
        assertThrows(IllegalArgumentException.class, () -> coordinator.changeMasterPassword(
                OLD.toCharArray(), "PasswordPassword".toCharArray(),
                MasterPasswordCheckStatus.PENDING, new Outcome()));
        SafeKeySession.lock();
        assertThrows(IllegalStateException.class, () -> coordinator.changeMasterPassword(
                OLD.toCharArray(), NEXT.toCharArray(),
                MasterPasswordCheckStatus.PENDING, new Outcome()));
    }

    @Test
    public void cancelledQueuedChangeCannotCommitOrDeliverCallback() throws Exception {
        createAuthenticatedVault();
        String original = envelopes.load().getWrappedDatabaseKey();
        ExecutorService worker = worker();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        blockWorker(worker, entered, release);
        AtomicBoolean delivered = new AtomicBoolean();
        try {
            MasterPasswordChangeRequest request = coordinator.changeMasterPassword(
                    OLD.toCharArray(), NEXT.toCharArray(), MasterPasswordCheckStatus.PENDING,
                    recording(delivered));
            request.close();
        } finally { release.countDown(); }
        drainWorker(worker);
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        assertEquals(original, envelopes.load().getWrappedDatabaseKey());
        assertFalse(delivered.get());
    }

    @Test
    public void replacementSessionCannotAuthorizeQueuedChangeFromOldSession() throws Exception {
        createAuthenticatedVault();
        String original = envelopes.load().getWrappedDatabaseKey();
        ExecutorService worker = worker();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        blockWorker(worker, entered, release);
        AtomicBoolean delivered = new AtomicBoolean();
        try {
            coordinator.changeMasterPassword(OLD.toCharArray(), NEXT.toCharArray(),
                    MasterPasswordCheckStatus.PENDING, recording(delivered));
            SafeKeySession.lock();
            SafeKeySession.unlockAfterAuthentication();
        } finally { release.countDown(); }
        drainWorker(worker);
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        assertEquals(original, envelopes.load().getWrappedDatabaseKey());
        assertFalse(delivered.get());
    }

    @Test
    public void changingPasswordPreservesTotpAndDoesNotBypassChallenge() throws Exception {
        createAuthenticatedVault();
        try (TotpState initial = new TotpState(SECRET, -1L, 0, 0L)) { store.replace(initial); }
        awaitSuccess(callback -> coordinator.changeMasterPassword(OLD.toCharArray(),
                NEXT.toCharArray(), MasterPasswordCheckStatus.PENDING, callback));
        synchronized (store) {
            try (TotpState retained = store.load()) {
                byte[] secret = retained.copySecret();
                try { assertArrayEquals(SECRET, secret); }
                finally { Arrays.fill(secret, (byte) 0); }
                assertEquals(-1L, retained.getLastAcceptedStep());
            }
        }
        awaitSuccess(coordinator::closeVault);
        CountDownLatch challenge = new CountDownLatch(1);
        AtomicReference<VaultUnlockFlow.Request> request = new AtomicReference<>();
        Outcome opened = new Outcome();
        coordinator.unlockVault(NEXT.toCharArray(), new SecureVaultCoordinator.TotpUnlockCallback() {
            @Override public void onSuccess() { opened.onSuccess(); }
            @Override public void onError(Exception error) { opened.onError(error); challenge.countDown(); }
            @Override public void onTotpRequired(VaultUnlockFlow.Request pending) {
                request.set(pending);
                challenge.countDown();
            }
        });
        CallbackTimeoutDiagnostics.await(challenge, 30L);
        assertNotNull(request.get());
        assertFalse(coordinator.isVaultOpen());
        char[] code = "287082".toCharArray();
        try { request.get().submitCode(code, ignored -> { }); }
        finally { Arrays.fill(code, '\0'); }
        opened.await();
        assertEquals(null, opened.error.get());
        assertTrue(request.get().claimSession());
    }

    @Test
    public void metadataIsBoundToEnvelopeAndReplacementDefaultsToPending() {
        VaultKeyEnvelope first = new VaultKeyEnvelope(new byte[16], "first wrapped key");
        VaultKeyEnvelope second = new VaultKeyEnvelope(new byte[16], "replacement wrapped key");
        envelopes.save(first);
        assertEquals(MasterPasswordCheckStatus.PENDING, envelopes.getMasterPasswordCheckStatus());
        assertTrue(envelopes.updateMasterPasswordCheckStatus(first, MasterPasswordCheckStatus.CHECKED));
        assertEquals(MasterPasswordCheckStatus.CHECKED, envelopes.getMasterPasswordCheckStatus());
        envelopes.save(second);
        assertFalse(envelopes.updateMasterPasswordCheckStatus(first, MasterPasswordCheckStatus.CHECKED));
        assertEquals(MasterPasswordCheckStatus.PENDING, envelopes.getMasterPasswordCheckStatus());
    }

    private void createAuthenticatedVault() throws Exception {
        awaitSuccess(callback -> coordinator.createVault(OLD.toCharArray(), callback));
        SafeKeySession.unlockAfterAuthentication();
    }

    private byte[] databaseKey(VaultKeyEnvelope envelope, String password) throws Exception {
        byte[] salt = envelope.getSalt();
        char[] characters = password.toCharArray();
        byte[] masterKey = null;
        try {
            masterKey = new Argon2idMasterKeyDeriver().deriveKey(characters, salt);
            return new AesGcmCipher().decrypt(envelope.getWrappedDatabaseKey(), masterKey,
                    "safekey:database-key-envelope:v1".getBytes(StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(characters, '\0');
            Arrays.fill(salt, (byte) 0);
            if (masterKey != null) { Arrays.fill(masterKey, (byte) 0); }
        }
    }

    private ExecutorService worker() throws Exception {
        Field field = SecureVaultCoordinator.class.getDeclaredField("securityExecutor");
        field.setAccessible(true);
        return (ExecutorService) field.get(coordinator);
    }

    private static void blockWorker(ExecutorService worker, CountDownLatch entered,
                                    CountDownLatch release) throws Exception {
        worker.execute(() -> {
            entered.countDown();
            try { CallbackTimeoutDiagnostics.await(release, 30L); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        });
        CallbackTimeoutDiagnostics.await(entered, 30L);
    }

    private static void drainWorker(ExecutorService worker) throws Exception {
        CountDownLatch finished = new CountDownLatch(1);
        worker.execute(finished::countDown);
        CallbackTimeoutDiagnostics.await(finished, 30L);
    }

    private static VaultDataService.SimpleCallback recording(AtomicBoolean delivered) {
        return new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { delivered.set(true); }
            @Override public void onError(Exception error) { delivered.set(true); }
        };
    }

    private static void awaitSuccess(Operation operation) throws Exception {
        Outcome result = new Outcome();
        operation.run(result);
        result.await();
        if (result.error.get() != null) { throw result.error.get(); }
    }

    private interface Operation { void run(VaultDataService.SimpleCallback callback); }

    private static final class Outcome implements VaultDataService.SimpleCallback {
        private final CountDownLatch done = new CountDownLatch(1);
        private final AtomicReference<Exception> error = new AtomicReference<>();
        @Override public void onSuccess() { done.countDown(); }
        @Override public void onError(Exception failure) { error.set(failure); done.countDown(); }
        void await() throws Exception { CallbackTimeoutDiagnostics.await(done, 30L); }
    }

    private static final class MemoryTotp implements TotpVerificationService.StateStore {
        private TotpState state;
        @Override public Object getTransactionLock() { return this; }
        @Override public synchronized TotpState load() { return copy(state); }
        @Override public synchronized void save(TotpState updated) { replace(updated); }
        synchronized void replace(TotpState updated) {
            TotpState replacement = copy(updated);
            if (state != null) { state.close(); }
            state = replacement;
        }
        private static TotpState copy(TotpState original) {
            if (original == null) { return null; }
            byte[] secret = original.copySecret();
            try { return new TotpState(secret, original.getLastAcceptedStep(),
                    original.getFailedAttempts(), original.getBlockedUntilEpochMillis()); }
            finally { Arrays.fill(secret, (byte) 0); }
        }
    }

    private static final class TestContext extends ContextWrapper {
        TestContext(Context context) { super(context); }
        @Override public Context getApplicationContext() { return this; }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) {
            return super.getSharedPreferences("t45_change_" + name, mode);
        }
        @Override public File getDatabasePath(String name) {
            return super.getDatabasePath("t45_change_" + name);
        }
        @Override public boolean deleteDatabase(String name) {
            return super.deleteDatabase("t45_change_" + name);
        }
    }
}

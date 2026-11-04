package com.safekey.app.security.storage;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class RecoveryEnrollmentInstrumentedTest {

    private TestContext context;
    private SecureVaultCoordinator coordinator;
    private VaultKeyEnvelopeStore store;

    @Before
    public void setUp() {
        Context base = InstrumentationRegistry.getInstrumentation().getTargetContext();
        context = new TestContext(base.getApplicationContext());
        coordinator = new SecureVaultCoordinator(context);
        store = new VaultKeyEnvelopeStore(context);
    }

    @After
    public void tearDown() throws Exception {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(context.runtime::cancelPending);
        context.runtime.closeAndAwait(30_000L);
        context.deleteFixtureFiles();
    }

    @Test
    public void closingKeyBeforeConfirmationLeavesVaultUnenrolled() {
        try (SecureVaultCoordinator.EnrollmentRecoveryKey prepared =
                     coordinator.prepareEnrollmentRecoveryKey()) {
            char[] displayed = prepared.takeDisplayCopy();
            try {
                assertEquals(32, displayed.length);
            } finally {
                Arrays.fill(displayed, '\0');
            }
        }

        assertFalse(coordinator.hasVault());
        assertNull(store.loadRecoveryEnvelope());
        assertFalse(context.getDatabasePath("safekey.db").exists());
    }

    @Test
    public void confirmedEnrollmentSavesTwoWrapsOfTheSameDatabaseKey() throws Exception {
        char[] master = "RecoveryFixtureMasterPassword123!".toCharArray();
        try (SecureVaultCoordinator.EnrollmentRecoveryKey prepared =
                     coordinator.prepareEnrollmentRecoveryKey()) {
            char[] recoveryKey = prepared.takeDisplayCopy();
            try {
                CountDownLatch ready = new CountDownLatch(1);
                AtomicReference<Exception> error = new AtomicReference<>();
                VaultDataService.SimpleCallback callback = new VaultDataService.SimpleCallback() {
                    @Override public void onSuccess() { ready.countDown(); }

                    @Override public void onError(Exception failure) {
                        error.set(failure);
                        ready.countDown();
                    }
                };

                try (VaultUnlockFlow.Request request =
                             coordinator.createVaultForEnrollmentWithRecovery(
                                     master, MasterPasswordCheckStatus.CHECKED, prepared, callback)) {
                    assertTrue("Recovery enrollment timed out", ready.await(120, TimeUnit.SECONDS));
                    if (error.get() != null) {
                        throw new AssertionError("Recovery enrollment failed", error.get());
                    }
                    assertTrue("Enrollment session claim failed", request.claimSession());
                    assertTrue(coordinator.isVaultOpen());
                    assertTrue(context.getDatabasePath("safekey.db").isFile());
                    assertEquals(MasterPasswordCheckStatus.CHECKED, store.getMasterPasswordCheckStatus());
                    assertMatchingEnvelopes(master, recoveryKey);
                }
            } finally {
                Arrays.fill(recoveryKey, '\0');
            }
        } finally {
            Arrays.fill(master, '\0');
        }
    }

    @Test
    public void recoveryResetPreservesVault() throws Exception {
        SafeKeySession.lock();
        char[] oldMaster = "RecoveryFixtureMasterPassword123!".toCharArray();
        char[] newMaster = "RecoveryFixtureReplacementPassword456!".toCharArray();

        try (SecureVaultCoordinator.EnrollmentRecoveryKey prepared =
                     coordinator.prepareEnrollmentRecoveryKey()) {
            char[] recoveryKey = prepared.takeDisplayCopy();
            try {
                AwaitedOperation enrollment = new AwaitedOperation();
                try (VaultUnlockFlow.Request request =
                             coordinator.createVaultForEnrollmentWithRecovery(
                                     oldMaster, MasterPasswordCheckStatus.CHECKED, prepared, enrollment)) {
                    enrollment.requireSuccess("Enrollment");
                    assertTrue(coordinator.isVaultOpen());
                    // Closing this unclaimed request closes the fixture vault.
                }

                long deadline = android.os.SystemClock.elapsedRealtime() + 30_000L;
                while (coordinator.isVaultOpen() && android.os.SystemClock.elapsedRealtime() < deadline) {
                    Thread.sleep(25L);
                }
                assertFalse("Fixture vault did not close", coordinator.isVaultOpen());

                File database = context.getDatabasePath("safekey.db");
                byte[] originalDatabase = Files.readAllBytes(database.toPath());
                VaultKeyEnvelope originalMaster = store.load();
                VaultKeyEnvelope originalRecovery = store.loadRecoveryEnvelope();
                assertNotNull(originalMaster);
                assertNotNull(originalRecovery);

                assertWrongRecoveryKeyRejected(recoveryKey, newMaster);
                assertEquals(originalMaster.getWrappedDatabaseKey(), store.load().getWrappedDatabaseKey());
                assertArrayEquals(originalMaster.getSalt(), store.load().getSalt());
                assertEquals(MasterPasswordCheckStatus.CHECKED, store.getMasterPasswordCheckStatus());

                AwaitedOperation reset = new AwaitedOperation();
                try (MasterPasswordChangeRequest request = coordinator.resetMasterPasswordWithRecovery(
                        recoveryKey, newMaster, MasterPasswordCheckStatus.PENDING, reset)) {
                    reset.requireSuccess("Recovery reset");
                }

                assertEquals(SessionState.LOCKED, SafeKeySession.getState());
                assertFalse(coordinator.isVaultOpen());
                assertArrayEquals(originalDatabase, Files.readAllBytes(database.toPath()));
                assertEquals(MasterPasswordCheckStatus.PENDING, store.getMasterPasswordCheckStatus());
                assertEquals(originalRecovery.getWrappedDatabaseKey(),
                        store.loadRecoveryEnvelope().getWrappedDatabaseKey());
                assertMatchingEnvelopes(newMaster, recoveryKey);

                AwaitedOperation oldUnlock = new AwaitedOperation();
                try (VaultUnlockFlow.Request request = coordinator.unlockVault(oldMaster, oldUnlock)) {
                    assertNotNull("Old Master password still opens the vault",
                            oldUnlock.await("Old password check"));
                    assertFalse(coordinator.isVaultOpen());
                }

                AwaitedOperation newUnlock = new AwaitedOperation();
                try (VaultUnlockFlow.Request request = coordinator.unlockVault(newMaster, newUnlock)) {
                    newUnlock.requireSuccess("New password sign-in");
                    assertTrue(coordinator.isVaultOpen());
                }
            } finally {
                Arrays.fill(recoveryKey, '\0');
            }
        } finally {
            Arrays.fill(oldMaster, '\0');
            Arrays.fill(newMaster, '\0');
        }
    }

    private void assertWrongRecoveryKeyRejected(char[] recoveryKey, char[] newMaster) throws Exception {
        char[] wrongKey = recoveryKey.clone();
        try {
            wrongKey[0] = wrongKey[0] == '0' ? '1' : '0';
            AwaitedOperation rejected = new AwaitedOperation();
            try (MasterPasswordChangeRequest request = coordinator.resetMasterPasswordWithRecovery(
                    wrongKey, newMaster, MasterPasswordCheckStatus.PENDING, rejected)) {
                assertTrue("Wrong Recovery key was not rejected",
                        rejected.await("Wrong Recovery key check") instanceof AesGcmException);
            }
        } finally {
            Arrays.fill(wrongKey, '\0');
        }
    }

    private static final class AwaitedOperation implements VaultDataService.SimpleCallback {
        private final CountDownLatch completed = new CountDownLatch(1);
        private Exception failure;

        @Override public void onSuccess() { completed.countDown(); }

        @Override public void onError(Exception error) {
            failure = error;
            completed.countDown();
        }

        private Exception await(String operation) throws InterruptedException {
            assertTrue(operation + " timed out", completed.await(120, TimeUnit.SECONDS));
            return failure;
        }

        private void requireSuccess(String operation) throws InterruptedException {
            Exception error = await(operation);
            if (error != null) {
                throw new AssertionError(operation + " failed", error);
            }
        }
    }

    private void assertMatchingEnvelopes(char[] master, char[] recoveryKey) throws Exception {
        VaultKeyEnvelope masterEnvelope = store.load();
        VaultKeyEnvelope recoveryEnvelope = store.loadRecoveryEnvelope();
        assertNotNull(masterEnvelope);
        assertNotNull(recoveryEnvelope);

        Argon2idMasterKeyDeriver deriver = new Argon2idMasterKeyDeriver();
        AesGcmCipher cipher = new AesGcmCipher();
        byte[] wrappingKey = deriver.deriveKey(master, masterEnvelope.getSalt());
        byte[] masterDatabaseKey = null;
        byte[] recoveryDatabaseKey = null;
        try {
            byte[] masterContext = "safekey:database-key-envelope:v1".getBytes(StandardCharsets.UTF_8);
            masterDatabaseKey = cipher.decrypt(masterEnvelope.getWrappedDatabaseKey(), wrappingKey, masterContext);
            recoveryDatabaseKey = new RecoveryKeyProtector(deriver, cipher, new SecureRandom())
                    .unwrap(recoveryKey, recoveryEnvelope);
            assertArrayEquals(masterDatabaseKey, recoveryDatabaseKey);
        } finally {
            Arrays.fill(wrappingKey, (byte) 0);
            if (masterDatabaseKey != null) {
                Arrays.fill(masterDatabaseKey, (byte) 0);
            }
            if (recoveryDatabaseKey != null) {
                Arrays.fill(recoveryDatabaseKey, (byte) 0);
            }
        }
    }

    private static final class TestContext extends ContextWrapper implements PanicRuntimeScope.Owner {
        private final PanicRuntimeScope runtime = new PanicRuntimeScope();
        private final String prefix = "recovery_test_" + UUID.randomUUID() + "_";
        private final Set<String> preferences = ConcurrentHashMap.newKeySet();

        private TestContext(Context base) { super(base); }

        @Override public Context getApplicationContext() { return this; }
        @Override public PanicRuntimeScope getPanicRuntimeScope() { return runtime; }

        @Override
        public SharedPreferences getSharedPreferences(String name, int mode) {
            String fixtureName = prefix + name;
            preferences.add(fixtureName);
            return super.getSharedPreferences(fixtureName, mode);
        }

        @Override
        public File getDatabasePath(String name) {
            return super.getDatabasePath(prefix + name);
        }

        private void deleteFixtureFiles() {
            getBaseContext().deleteDatabase(prefix + "safekey.db");
            for (String name : preferences) {
                getBaseContext().deleteSharedPreferences(name);
            }
        }
    }
}

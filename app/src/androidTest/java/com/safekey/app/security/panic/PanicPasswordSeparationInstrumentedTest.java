package com.safekey.app.security.panic;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.DecoyVaultStorage;
import com.safekey.app.security.storage.MasterPasswordChangeRequest;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.PanicEnrollmentVaultTestSupport;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelope;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.totp.PanicEnrollmentTotpTestSupport;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.session.SafeKeySession;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/** Actual coordinator setup/change paths, using only isolated databases, preferences and keys. */
@RunWith(AndroidJUnit4.class)
public class PanicPasswordSeparationInstrumentedTest {
    private static final String MASTER = "M4ster!R7pL2qZ9x8N";
    private static final String DECOY = "D3coy!K8wT6vY2s4B";
    private static final String PANIC = "P4nic!F9rQ6uL2c8W";
    private static final String NEW_MASTER = "N3wMaster!P7dL4sQ9r";
    private interface Start { void run(VaultDataService.SimpleCallback callback); }

    private static final class Outcome implements VaultDataService.SimpleCallback {
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<Exception> error = new AtomicReference<>();
        @Override public void onSuccess() { done.countDown(); }
        @Override public void onError(Exception failure) { error.set(failure); done.countDown(); }
        Exception await() throws Exception {
            assertTrue("Coordinator callback timed out", done.await(15, TimeUnit.SECONDS));
            return error.get();
        }
    }

    private static final class Fixture implements AutoCloseable {
        final PanicRuntimeScope scope = new PanicRuntimeScope();
        final ScopedContext context;
        final TotpSecretStore totp;
        final SecureVaultCoordinator real;
        final DecoyVaultCoordinator decoy;
        final VaultKeyEnvelopeStore masterStore;
        final VaultKeyEnvelopeStore decoyStore;
        final PanicPasswordStore proof;
        final PanicBackend backend;

        Fixture() {
            SafeKeySession.unregisterSensitiveDataCleanup(); main(SafeKeySession::lock);
            context = new ScopedContext(InstrumentationRegistry.getInstrumentation()
                    .getTargetContext().getApplicationContext(), scope);
            totp = PanicEnrollmentTotpTestSupport.create(context, context.prefix);
            real = PanicEnrollmentVaultTestSupport.create(context, totp);
            decoy = new DecoyVaultCoordinator(context);
            masterStore = new VaultKeyEnvelopeStore(context);
            decoyStore = VaultKeyEnvelopeStore.forDecoy(context);
            proof = new PanicPasswordStore(context);
            DecoyVaultStorage.ensureDatabaseFile(context);
            PanicWipeCoordinator wipe = new PanicWipeCoordinator(scope.getWorkGate(), new PanicWipeJournal(context),
                    new PanicWipeCoordinator.Runtime() {
                        @Override public void lockAndClearSession() { fail("Separation test attempted a wipe."); }
                        @Override public void closeResources() { fail("Separation test attempted a wipe."); }
                        @Override public boolean areResourcesClosed() { return false; }
                    }, Collections.singletonList(new PanicWipeCoordinator.Target() {
                        @Override public String name() { return "unused isolated target"; }
                        @Override public void erase() { fail("Separation test attempted deletion."); }
                        @Override public void verifyAbsent() { }
                    }));
            PanicPasswordService passwords = new PanicPasswordService(scope.getWorkGate(), proof, new PanicPasswordCrypto(), wipe);
            backend = new PanicBackend(scope, passwords, new AndroidPanicEnrollmentAuthority(context, real, decoy, totp));
        }

        void createReal() throws Exception {
            char[] password = MASTER.toCharArray(); Outcome outcome = new Outcome();
            try (VaultUnlockFlow.Request request = real.createVaultForEnrollment(
                    password, MasterPasswordCheckStatus.CHECKED, outcome)) {
                assertNull(outcome.await());
                main(() -> { assertTrue(request.claimSession()); SafeKeySession.unlockAfterAuthentication(); });
            } finally { Arrays.fill(password, '\0'); }
        }

        void createDecoy() throws Exception {
            char[] password = DECOY.toCharArray();
            try { assertNull(call(callback -> decoy.createDecoyVault(password, callback))); }
            finally { Arrays.fill(password, '\0'); }
            assertNull(call(decoy::closeDecoyVault));
        }

        void enrollPanic(String currentMaster, String proposed) throws Exception {
            char[] master = currentMaster.toCharArray(); char[] secondary = DECOY.toCharArray();
            char[] panic = proposed.toCharArray(); char[] confirm = panic.clone();
            try { backend.enrollPanicPassword(master, secondary, panic, confirm, true); }
            finally { Arrays.fill(master, '\0'); Arrays.fill(secondary, '\0'); Arrays.fill(panic, '\0'); Arrays.fill(confirm, '\0'); }
        }

        Exception changeMaster(String proposed) throws Exception {
            char[] current = MASTER.toCharArray(); char[] next = proposed.toCharArray(); Outcome outcome = new Outcome();
            try (MasterPasswordChangeRequest ignored = real.changeMasterPassword(
                    current, next, MasterPasswordCheckStatus.CHECKED, outcome)) { return outcome.await(); }
            finally { Arrays.fill(current, '\0'); Arrays.fill(next, '\0'); }
        }

        void assertMasterStillWorks(VaultKeyEnvelope original) throws Exception {
            VaultKeyEnvelope current = masterStore.load();
            assertArrayEquals(original.getSalt(), current.getSalt());
            assertEquals(original.getWrappedDatabaseKey(), current.getWrappedDatabaseKey());
            assertTrue(AndroidPanicEnrollmentAuthority.matches(MASTER.toCharArray(), current,
                    "safekey:database-key-envelope:v1"));
        }

        @Override public void close() throws Exception {
            try {
                if (!scope.isStopped()) { totp.clear(); }
                PanicAndroidRuntime runtime = new PanicAndroidRuntime(scope,
                        new Handler(Looper.getMainLooper()), SafeKeySession::lock);
                runtime.lockAndClearSession(); runtime.closeResources(); assertTrue(runtime.areResourcesClosed());
            } finally {
                try {
                    context.deleteDatabase("safekey.db"); context.deleteDatabase("safekey_secondary.db");
                    context.deleteSharedPreferences("safekey_vault_key_envelope");
                    context.deleteSharedPreferences("safekey_decoy_vault_key_envelope");
                    File[] files = context.directory.listFiles();
                    if (files != null) { for (File file : files) { assertTrue(file.delete()); } }
                    assertTrue(context.directory.delete());
                } finally {
                    main(SafeKeySession::lock);
                    ((SafeKeyApplication) InstrumentationRegistry.getInstrumentation().getTargetContext()
                            .getApplicationContext()).registerSessionCleanup();
                }
            }
        }
    }

    private static Exception call(Start action) throws Exception {
        Outcome outcome = new Outcome(); action.run(outcome); return outcome.await();
    }
    private static void main(Runnable action) { InstrumentationRegistry.getInstrumentation().runOnMainSync(action); }

    @Test public void legacyRealSetupRejectsConfiguredDecoyPassword() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createDecoy();
            Exception error = call(callback -> f.real.createVault(DECOY.toCharArray(), callback));
            assertTrue(error instanceof IllegalArgumentException); assertFalse(f.real.hasVault());
            assertNotNull(f.decoyStore.load());
        }
    }

    @Test public void enrollmentRealSetupRejectsConfiguredDecoyPassword() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createDecoy(); Outcome outcome = new Outcome();
            try (VaultUnlockFlow.Request ignored = f.real.createVaultForEnrollment(
                    DECOY.toCharArray(), MasterPasswordCheckStatus.CHECKED, outcome)) {
                assertTrue(outcome.await() instanceof IllegalArgumentException);
            }
            assertFalse(f.real.hasVault()); assertNotNull(f.decoyStore.load());
        }
    }

    @Test public void bothRealSetupPathsRejectPersistedPanicPassword() throws Exception {
        try (Fixture f = new Fixture()) {
            f.proof.save(new PanicPasswordCrypto().create(PANIC.toCharArray()));
            assertTrue(call(callback -> f.real.createVault(PANIC.toCharArray(), callback)) instanceof IllegalArgumentException);
            Outcome outcome = new Outcome();
            try (VaultUnlockFlow.Request ignored = f.real.createVaultForEnrollment(
                    PANIC.toCharArray(), MasterPasswordCheckStatus.CHECKED, outcome)) {
                assertTrue(outcome.await() instanceof IllegalArgumentException);
            }
            assertFalse(f.real.hasVault()); assertNotNull(f.proof.load());
        }
    }

    @Test public void decoySetupRejectsMasterWithoutChangingItsCoverDatabase() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); VaultKeyEnvelope original = f.masterStore.load();
            File cover = f.context.getDatabasePath("safekey_secondary.db"); byte[] before = Files.readAllBytes(cover.toPath());
            assertTrue(call(callback -> f.decoy.createDecoyVault(MASTER.toCharArray(), callback)) instanceof IllegalArgumentException);
            assertFalse(f.decoy.hasDecoyVault()); assertArrayEquals(before, Files.readAllBytes(cover.toPath()));
            f.assertMasterStillWorks(original);
        }
    }

    @Test public void decoySetupRejectsPanicWithoutChangingRealEnvelope() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); VaultKeyEnvelope original = f.masterStore.load();
            f.proof.save(new PanicPasswordCrypto().create(PANIC.toCharArray()));
            assertTrue(call(callback -> f.decoy.createDecoyVault(PANIC.toCharArray(), callback)) instanceof IllegalArgumentException);
            assertFalse(f.decoy.hasDecoyVault()); f.assertMasterStillWorks(original);
        }
    }

    @Test public void distinctSetupPasswordsAndActualPanicEnrollmentSucceed() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); f.createDecoy(); f.enrollPanic(MASTER, PANIC);
            assertNotNull(f.masterStore.load()); assertNotNull(f.decoyStore.load());
            assertTrue(new PanicPasswordCrypto().matches(PANIC.toCharArray(), f.proof.load()));
            assertTrue(f.real.isVaultOpen()); assertFalse(f.decoy.isDecoyVaultOpen());
        }
    }

    @Test public void masterChangeRejectsDecoyAndKeepsOldMaster() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); f.createDecoy(); VaultKeyEnvelope original = f.masterStore.load();
            assertTrue(f.changeMaster(DECOY) instanceof IllegalArgumentException); f.assertMasterStillWorks(original);
        }
    }

    @Test public void masterChangeRejectsPanicAndKeepsOldMaster() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); f.createDecoy(); f.enrollPanic(MASTER, PANIC); VaultKeyEnvelope original = f.masterStore.load();
            assertTrue(f.changeMaster(PANIC) instanceof IllegalArgumentException); f.assertMasterStillWorks(original);
            assertTrue(new PanicPasswordCrypto().matches(PANIC.toCharArray(), f.proof.load()));
        }
    }

    @Test public void uniqueMasterChangeKeepsTheDatabaseKeyAndOtherRoleProofs() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); f.createDecoy(); f.enrollPanic(MASTER, PANIC);
            byte[] panic = f.proof.load().encode(); String secondary = f.decoyStore.load().getWrappedDatabaseKey();
            assertNull(f.changeMaster(NEW_MASTER));
            assertFalse(AndroidPanicEnrollmentAuthority.matches(MASTER.toCharArray(), f.masterStore.load(),
                    "safekey:database-key-envelope:v1"));
            assertTrue(AndroidPanicEnrollmentAuthority.matches(NEW_MASTER.toCharArray(), f.masterStore.load(),
                    "safekey:database-key-envelope:v1"));
            assertArrayEquals(panic, f.proof.load().encode()); assertEquals(secondary, f.decoyStore.load().getWrappedDatabaseKey());
            assertNull(call(f.real::closeVault)); main(SafeKeySession::lock);
            Outcome outcome = new Outcome();
            try (VaultUnlockFlow.Request ignored = f.real.unlockVault(NEW_MASTER.toCharArray(), outcome)) {
                assertNull(outcome.await()); assertTrue(f.real.isVaultOpen());
            }
        }
    }

    @Test public void panicReenrollmentRejectsCurrentMasterAndDecoyWithoutReplacingProof() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); f.createDecoy(); f.enrollPanic(MASTER, PANIC); byte[] original = f.proof.load().encode();
            for (String collision : new String[]{MASTER, DECOY}) {
                boolean rejected = false;
                try { f.enrollPanic(MASTER, collision); } catch (IllegalArgumentException expected) { rejected = true; }
                assertTrue(rejected); assertArrayEquals(original, f.proof.load().encode());
            }
        }
    }

    @Test public void corruptOtherRoleProofPreventsMasterReplacement() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); f.createDecoy(); VaultKeyEnvelope original = f.masterStore.load();
            PanicInstrumentedFixture.write(new File(f.context.directory, PanicPasswordStore.FILE_NAME), new byte[]{1});
            assertTrue(f.changeMaster(NEW_MASTER) instanceof GeneralSecurityException); f.assertMasterStillWorks(original);
        }
    }

    @Test public void realStorageMutationInvalidatesPreparedSeparationPermit() throws Exception {
        try (Fixture f = new Fixture()) {
            f.createReal(); f.createDecoy(); AtomicBoolean saved = new AtomicBoolean();
            PanicPasswordSeparation guard = AndroidPanicPasswordSeparation.create(f.context, f.scope);
            try (PanicPasswordSeparation.Permit permit = guard.prepare(PanicPasswordSeparation.Role.MASTER,
                    NEW_MASTER.toCharArray())) {
                f.decoyStore.save(f.decoyStore.load());
                boolean rejected = false;
                try { permit.commit(() -> saved.set(true)); }
                catch (java.util.concurrent.CancellationException expected) { rejected = true; }
                assertTrue(rejected); assertFalse(saved.get());
            }
        }
    }

    private static final class ScopedContext extends ContextWrapper implements PanicRuntimeScope.Owner {
        final String prefix = "safekey_panic_test_" + UUID.randomUUID().toString().replace("-", "") + "_";
        final PanicRuntimeScope scope; final File directory;
        ScopedContext(Context base, PanicRuntimeScope scope) {
            super(base); this.scope = scope; directory = new File(base.getNoBackupFilesDir(), prefix);
            if (!directory.mkdir()) { throw new IllegalStateException("Unable to create isolated test storage."); }
        }
        @Override public Context getApplicationContext() { return this; }
        @Override public PanicRuntimeScope getPanicRuntimeScope() { return scope; }
        @Override public File getNoBackupFilesDir() { return directory; }
        @Override public File getDatabasePath(String name) { return getBaseContext().getDatabasePath(prefix + name); }
        @Override public boolean deleteDatabase(String name) { return getBaseContext().deleteDatabase(prefix + name); }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) {
            return getBaseContext().getSharedPreferences(prefix + name, mode);
        }
        @Override public boolean deleteSharedPreferences(String name) { return getBaseContext().deleteSharedPreferences(prefix + name); }
    }
}

package com.safekey.app.security.panic;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.security.storage.VaultKeyEnvelope;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/** Production role crypto/storage and shutdown, with isolated manifests and no production wipe. */
@RunWith(AndroidJUnit4.class)
public class PanicSignInInstrumentedTest {
    private static final String MASTER = "M4ster!R7pL2qZ9x8N";
    private static final String DECOY = "D3coy!K8wT6vY2s4B";
    private static final String PANIC = "P4nic!F9rQ6uL2c8W";
    private interface Checked { void run() throws Exception; }

    private static final class Fixture implements AutoCloseable {
        final Context base = InstrumentationRegistry.getInstrumentation().getTargetContext().getApplicationContext();
        final String prefix = "safekey_panic_test_" + UUID.randomUUID().toString().replace("-", "") + "_";
        final PanicWipeTargets.Names names = PanicWipeTargets.Names.forTests(prefix);
        final PanicRuntimeScope scope = new PanicRuntimeScope();
        final Context context = new ContextWrapper(base) {
            @Override public Context getApplicationContext() { return this; }
            @Override public SharedPreferences getSharedPreferences(String name, int mode) {
                if (name.equals("safekey_vault_key_envelope")) { return base.getSharedPreferences(names.preferences[0], mode); }
                if (name.equals("safekey_decoy_vault_key_envelope")) { return base.getSharedPreferences(names.preferences[1], mode); }
                throw new IllegalArgumentException("Unmapped preference in isolated test: " + name);
            }
        };
        // Store adapters capture this Owner, rather than the actual application's production runtime.
        final Context ownedContext = new ScopedOwner(context, scope);
        final PanicPasswordStore proof = new PanicPasswordStore(ownedContext, names.panicFile);
        final PanicWipeJournal journal = new PanicWipeJournal(base, names.journalFile);
        final VaultKeyEnvelopeStore master = new VaultKeyEnvelopeStore(ownedContext);
        final VaultKeyEnvelopeStore decoy = VaultKeyEnvelopeStore.forDecoy(ownedContext);
        final AndroidPanicPasswordCredentials credentials = new AndroidPanicPasswordCredentials(ownedContext, proof);
        final List<PanicWipeCoordinator.Target> targets = PanicWipeTargets.create(base, names);
        final CountDownLatch locked = new CountDownLatch(1);
        boolean failDelete;
        boolean failMarkerRead;
        boolean failMarkerWrite;
        PanicBackend.SignInRequest lastRequest;
        final PanicAndroidRuntime runtime = new PanicAndroidRuntime(scope,
                new Handler(Looper.getMainLooper()), locked::countDown);
        final PanicWipeCoordinator wipe;
        final PanicSignInService service;
        final PanicBackend backend;

        Fixture() throws Exception {
            List<PanicWipeCoordinator.Target> plan = new ArrayList<>(targets);
            plan.add(new PanicWipeCoordinator.Target() {
                @Override public String name() { return "isolated injected failure"; }
                @Override public void erase() throws Exception { if (failDelete) { throw new IOException("Injected failure."); } }
                @Override public void verifyAbsent() { }
            });
            PanicWipeCoordinator.Journal checkedJournal = new PanicWipeCoordinator.Journal() {
                @Override public boolean isPending() throws Exception {
                    if (failMarkerRead) { throw new IOException("Injected marker read failure."); }
                    return journal.isPending();
                }
                @Override public void markPending() throws Exception {
                    if (failMarkerWrite) { throw new IOException("Injected marker write failure."); }
                    journal.markPending();
                }
                @Override public void clearPending() throws Exception { journal.clearPending(); }
            };
            wipe = new PanicWipeCoordinator(scope.getWorkGate(), checkedJournal, runtime, plan);
            service = new PanicSignInService(scope.getWorkGate(), credentials, wipe);
            backend = new PanicBackend(scope, null, null, service);
            for (String database : names.databases) {
                // File-manifest sentinels; actual SQLCipher shutdown is covered by existing runtime tests.
                for (String suffix : new String[]{"", "-wal", "-shm", "-journal"}) {
                    PanicInstrumentedFixture.write(new File(base.getDatabasePath(database).getPath() + suffix), new byte[]{7, 8});
                }
            }
            for (String alias : names.aliases) { PanicInstrumentedFixture.generateKey(alias); }
            PanicInstrumentedFixture.write(new File(base.getNoBackupFilesDir(), names.totpFile), new byte[]{9});
            master.save(envelope(MASTER, "safekey:database-key-envelope:v1"));
            decoy.save(envelope(DECOY, "safekey:decoy-database-key-envelope:v1"));
            proof.save(new PanicPasswordCrypto().create(PANIC.toCharArray()));
        }

        PanicSignInService.Result run(String password) throws Exception {
            char[] input = password.toCharArray();
            try (PanicBackend.SignInRequest request = backend.prepareSignIn(input)) {
                lastRequest = request;
                assertFalse(request.isPanicCommitted());
                return request.run();
            }
            finally { Arrays.fill(input, '\0'); }
        }

        void assertPresent() throws Exception {
            for (String database : names.databases) { assertTrue(base.getDatabasePath(database).isFile()); }
            for (String alias : names.aliases) { assertTrue(PanicInstrumentedFixture.keyStore().containsAlias(alias)); }
            assertFalse(journal.isPending()); assertFalse(scope.isStopped());
            assertEquals(1L, locked.getCount()); assertFalse(backend.wasWipeCompleted());
        }

        void assertWiped() throws Exception {
            assertTrue(scope.isStopped()); assertTrue(scope.areResourcesClosed());
            assertFalse(journal.isPending()); assertEquals(0L, locked.getCount()); assertTrue(backend.wasWipeCompleted());
            for (PanicWipeCoordinator.Target target : targets) { target.verifyAbsent(); }
        }

        @Override public void close() throws Exception {
            // Exact isolated manifest only; this also works after a stopped runtime rejects store calls.
            try { for (PanicWipeCoordinator.Target target : targets) { target.erase(); } }
            finally { journal.clearPending(); }
        }
    }

    private static final class ScopedOwner extends ContextWrapper implements PanicRuntimeScope.Owner {
        private final PanicRuntimeScope scope;
        ScopedOwner(Context base, PanicRuntimeScope scope) { super(base); this.scope = scope; }
        @Override public Context getApplicationContext() { return this; }
        @Override public PanicRuntimeScope getPanicRuntimeScope() { return scope; }
    }

    private static VaultKeyEnvelope envelope(String password, String context) throws Exception {
        Argon2idMasterKeyDeriver deriver = new Argon2idMasterKeyDeriver();
        byte[] salt = deriver.generateSalt(); byte[] key = null;
        byte[] databaseKey = new byte[32]; new java.security.SecureRandom().nextBytes(databaseKey);
        char[] input = password.toCharArray();
        try {
            key = deriver.deriveKey(input, salt);
            return new VaultKeyEnvelope(salt, new AesGcmCipher().encrypt(databaseKey, key,
                    context.getBytes(StandardCharsets.UTF_8)));
        } finally {
            Arrays.fill(input, '\0'); Arrays.fill(salt, (byte) 0); Arrays.fill(databaseKey, (byte) 0);
            if (key != null) { Arrays.fill(key, (byte) 0); }
        }
    }

    private static void rejects(Checked action) throws Exception {
        try { action.run(); fail("Unsafe role routing was accepted."); }
        catch (IOException | java.security.GeneralSecurityException
                | IllegalArgumentException | IllegalStateException expected) { }
    }

    private static PanicBackend afterMasterCheck(Fixture f, Checked hook) {
        PanicSignInService service = new PanicSignInService(f.scope.getWorkGate(), () -> {
            PanicSignInService.Snapshot actual = f.credentials.capture();
            return new PanicSignInService.Snapshot() {
                @Override public boolean matchesMaster(char[] candidate) throws Exception {
                    boolean result = actual.matchesMaster(candidate); hook.run(); return result;
                }
                @Override public boolean matchesDecoy(char[] candidate) throws Exception { return actual.matchesDecoy(candidate); }
                @Override public boolean matchesPanic(char[] candidate) throws Exception { return actual.matchesPanic(candidate); }
                @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
                    actual.commitIfCurrent(action);
                }
            };
        }, f.wipe);
        return new PanicBackend(f.scope, null, null, service);
    }

    @Test public void actualMasterDecoyAndIncorrectPasswordsRouteWithoutWiping() throws Exception {
        try (Fixture f = new Fixture()) {
            assertEquals(PanicSignInService.Result.MASTER, f.run(MASTER));
            assertFalse(f.lastRequest.isPanicCommitted());
            assertEquals(PanicSignInService.Result.DECOY, f.run(DECOY));
            assertFalse(f.lastRequest.isPanicCommitted());
            assertEquals(PanicSignInService.Result.NO_MATCH, f.run("Unrelated test password"));
            assertFalse(f.lastRequest.isPanicCommitted());
            f.assertPresent();
        }
    }

    @Test public void validPanicWipesOnlyIsolatedOwnedResources() throws Exception {
        try (Fixture f = new Fixture()) {
            File unrelated = new File(f.base.getNoBackupFilesDir(), f.prefix + "unrelated.txt");
            try {
                PanicInstrumentedFixture.write(unrelated, new byte[]{3});
                assertEquals(PanicSignInService.Result.PANIC_WIPED, f.run(PANIC)); f.assertWiped();
                assertTrue(f.lastRequest.isPanicCommitted());
                f.lastRequest.close();
                assertTrue(f.lastRequest.isPanicCommitted());
                assertTrue(unrelated.isFile());
            } finally { PanicFiles.deleteAll(new File[]{unrelated}); }
        }
    }

    @Test public void absentDecoyAndPanicUseDummyChecksWithoutCreatingConfiguration() throws Exception {
        try (Fixture f = new Fixture()) {
            f.base.getSharedPreferences(f.names.preferences[1], Context.MODE_PRIVATE).edit().clear().commit();
            PanicFiles.deleteAll(PanicFiles.atomicArtifacts(new File(f.base.getNoBackupFilesDir(), f.names.panicFile)));
            assertEquals(PanicSignInService.Result.MASTER, f.run(MASTER));
            assertEquals(PanicSignInService.Result.NO_MATCH, f.run(DECOY));
            assertNull(f.decoy.load()); assertNull(f.proof.load()); f.assertPresent();
        }
    }

    @Test public void allUnconfiguredRolesNeverMatchOrWipe() throws Exception {
        try (Fixture f = new Fixture()) {
            for (String preference : f.names.preferences) { f.base.getSharedPreferences(preference, 0).edit().clear().commit(); }
            PanicFiles.deleteAll(PanicFiles.atomicArtifacts(new File(f.base.getNoBackupFilesDir(), f.names.panicFile)));
            assertEquals(PanicSignInService.Result.NO_MATCH, f.run(PANIC)); f.assertPresent();
        }
    }

    @Test public void malformedPanicProofPreventsNormalRouteAndDeletion() throws Exception {
        try (Fixture f = new Fixture()) {
            PanicInstrumentedFixture.write(new File(f.base.getNoBackupFilesDir(), f.names.panicFile), new byte[]{1});
            rejects(() -> f.run(MASTER)); rejects(() -> f.run(PANIC)); f.assertPresent();
            assertFalse(f.lastRequest.isPanicCommitted());
        }
    }

    @Test public void malformedMasterEnvelopeCannotAuthorizeEvenValidPanic() throws Exception {
        try (Fixture f = new Fixture()) {
            assertTrue(f.base.getSharedPreferences(f.names.preferences[0], 0).edit()
                    .putString("wrapped_database_key", "invalid-envelope").commit());
            rejects(() -> f.run(PANIC)); f.assertPresent();
            assertFalse(f.lastRequest.isPanicCommitted());
        }
    }

    @Test public void actualCollidingRolePasswordsFailClosedWithoutWipe() throws Exception {
        try (Fixture f = new Fixture()) {
            f.master.save(envelope(PANIC, "safekey:database-key-envelope:v1"));
            rejects(() -> f.run(PANIC)); f.assertPresent();
            assertFalse(f.lastRequest.isPanicCommitted());
        }
    }

    @Test public void canceledUnstartedRequestAndReusedRequestCannotWipe() throws Exception {
        try (Fixture f = new Fixture()) {
            char[] input = PANIC.toCharArray();
            try (PanicBackend.SignInRequest request = f.backend.prepareSignIn(input)) {
                request.close(); rejects(request::run); assertArrayEquals(PANIC.toCharArray(), input);
                assertFalse(request.isPanicCommitted());
            } finally { Arrays.fill(input, '\0'); }
            PanicBackend.SignInRequest normal = f.backend.prepareSignIn(MASTER.toCharArray());
            assertEquals(PanicSignInService.Result.MASTER, normal.run()); rejects(normal::run); f.assertPresent();
            assertFalse(normal.isPanicCommitted());
        }
    }

    @Test public void mainThreadCannotExecuteSignInPasswordWork() throws Exception {
        try (Fixture f = new Fixture(); PanicBackend.SignInRequest request = f.backend.prepareSignIn(PANIC.toCharArray())) {
            AtomicReference<Exception> failure = new AtomicReference<>();
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                try { request.run(); } catch (Exception error) { failure.set(error); }
            });
            assertTrue(failure.get() instanceof IllegalStateException); f.assertPresent();
            assertFalse(request.isPanicCommitted());
        }
    }

    @Test public void cancellationDuringActualChecksPreventsPanicCommit() throws Exception {
        try (Fixture f = new Fixture()) {
            AtomicReference<PanicBackend.SignInRequest> pending = new AtomicReference<>();
            PanicBackend backend = afterMasterCheck(f, () -> pending.get().close());
            try (PanicBackend.SignInRequest request = backend.prepareSignIn(PANIC.toCharArray())) {
                pending.set(request); rejects(request::run); f.assertPresent();
                assertFalse(backend.wasWipeCompleted());
                assertFalse(request.isPanicCommitted());
            }
        }
    }

    @Test public void credentialWriteDuringActualChecksInvalidatesSnapshot() throws Exception {
        try (Fixture f = new Fixture()) {
            PanicBackend backend = afterMasterCheck(f, () -> f.proof.save(f.proof.load()));
            try (PanicBackend.SignInRequest request = backend.prepareSignIn(PANIC.toCharArray())) {
                rejects(request::run); f.assertPresent(); assertFalse(backend.wasWipeCompleted());
                assertFalse(request.isPanicCommitted());
            }
        }
    }

    @Test public void pendingJournalRequiresStartupRecoveryInsteadOfFreshPasswordRouting() throws Exception {
        try (Fixture f = new Fixture()) {
            f.journal.markPending(); rejects(() -> f.run(PANIC)); assertTrue(f.journal.isPending());
            assertFalse(f.lastRequest.isPanicCommitted());
            for (String database : f.names.databases) { assertTrue(f.base.getDatabasePath(database).isFile()); }
        }
    }

    @Test public void cleanupFailureNeverReportsPanicSuccessAndKeepsRecoveryMarker() throws Exception {
        try (Fixture f = new Fixture()) {
            f.failDelete = true; rejects(() -> f.run(PANIC));
            assertTrue(f.journal.isPending()); assertTrue(f.scope.isStopped());
            assertTrue(f.lastRequest.isPanicCommitted()); assertFalse(f.backend.wasWipeCompleted());
        }
    }

    @Test public void markerWriteFailureStillIdentifiesThisCommittedRequestWithoutDeleting() throws Exception {
        try (Fixture f = new Fixture()) {
            f.failMarkerWrite = true;
            rejects(() -> f.run(PANIC));
            assertTrue(f.lastRequest.isPanicCommitted());
            assertFalse(f.backend.wasWipeCompleted());
            assertTrue(f.scope.isStopped());
            assertFalse(f.journal.isPending());
            assertEquals(0L, f.locked.getCount());
            for (String database : f.names.databases) { assertTrue(f.base.getDatabasePath(database).isFile()); }
            for (String alias : f.names.aliases) {
                assertTrue(PanicInstrumentedFixture.keyStore().containsAlias(alias));
            }
            assertTrue(new File(f.base.getNoBackupFilesDir(), f.names.panicFile).isFile());
            f.lastRequest.close();
            assertTrue(f.lastRequest.isPanicCommitted());
        }
    }

    @Test public void unreadableMarkerBlocksRuntimeWithoutClaimingACommittedPanic() throws Exception {
        try (Fixture f = new Fixture()) {
            f.failMarkerRead = true;
            rejects(() -> f.run(PANIC));
            assertFalse(f.lastRequest.isPanicCommitted());
            assertFalse(f.backend.wasWipeCompleted());
            assertTrue(f.scope.isStopped());
            assertFalse(f.journal.isPending());
            for (String database : f.names.databases) { assertTrue(f.base.getDatabasePath(database).isFile()); }
        }
    }

    @Test public void anotherPreparedRequestCannotInheritPanicCommitment() throws Exception {
        try (Fixture f = new Fixture();
             PanicBackend.SignInRequest other = f.backend.prepareSignIn(MASTER.toCharArray())) {
            f.failMarkerWrite = true;
            rejects(() -> f.run(PANIC));
            assertTrue(f.lastRequest.isPanicCommitted());
            rejects(other::run);
            assertFalse(other.isPanicCommitted());
            assertFalse(f.backend.wasWipeCompleted());
            assertFalse(f.journal.isPending());
        }
    }

    @Test public void acceptedWorkMustDrainBeforeSignInCanDelete() throws Exception {
        try (Fixture f = new Fixture()) {
            ExecutorService control = Executors.newSingleThreadExecutor();
            PanicWorkGate.Operation existing = f.scope.begin();
            try {
                Future<PanicSignInService.Result> result = control.submit(() -> f.run(PANIC));
                assertTrue(f.locked.await(10, TimeUnit.SECONDS)); assertFalse(result.isDone());
                for (String database : f.names.databases) { assertTrue(f.base.getDatabasePath(database).isFile()); }
                existing.close();
                assertEquals(PanicSignInService.Result.PANIC_WIPED, result.get(15, TimeUnit.SECONDS)); f.assertWiped();
            } finally {
                existing.close(); control.shutdownNow(); assertTrue(control.awaitTermination(15, TimeUnit.SECONDS));
            }
        }
    }
}

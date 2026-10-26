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
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.PanicEnrollmentVaultTestSupport;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.totp.PanicEnrollmentTotpTestSupport;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.security.totp.TotpState;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.session.SafeKeySession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PanicEnrollmentInstrumentedTest {
    private static final String MASTER = "M4ster!R7pL2qZ9x8N";
    private static final String DECOY = "D3coy!K8wT6vY2s4B";
    private static final String PANIC = "P4nic!F9rQ6uL2c8W";
    private ScopedContext context;
    private PanicRuntimeScope scope;
    private SecureVaultCoordinator real;
    private DecoyVaultCoordinator decoy;
    private TotpSecretStore totp;
    private PanicPasswordStore proof;
    private AndroidPanicEnrollmentAuthority authority;
    private PanicPasswordService service;
    private PanicWipeCoordinator wipe;

    private interface Start { void run(VaultDataService.SimpleCallback callback); }
    private interface Checked { void run() throws Exception; }

    @Before public void setUp() {
        SafeKeySession.unregisterSensitiveDataCleanup();
        main(SafeKeySession::lock);
        scope = new PanicRuntimeScope();
        Context app = InstrumentationRegistry.getInstrumentation().getTargetContext().getApplicationContext();
        context = new ScopedContext(app, scope);
        totp = PanicEnrollmentTotpTestSupport.create(context, context.prefix);
        real = PanicEnrollmentVaultTestSupport.create(context, totp);
        decoy = new DecoyVaultCoordinator(context);
        proof = new PanicPasswordStore(context);
        authority = new AndroidPanicEnrollmentAuthority(context, real, decoy, totp);
        // The enrollment test never uses production wipe targets or production Keystore aliases.
        wipe = new PanicWipeCoordinator(scope.getWorkGate(), new PanicWipeJournal(context),
                new PanicWipeCoordinator.Runtime() {
                    @Override public void lockAndClearSession() { fail("Enrollment attempted a wipe."); }
                    @Override public void closeResources() { fail("Enrollment attempted a wipe."); }
                    @Override public boolean areResourcesClosed() { return false; }
                }, Collections.singletonList(new PanicWipeCoordinator.Target() {
                    @Override public String name() { return "unused isolated enrollment target"; }
                    @Override public void erase() { fail("Enrollment attempted deletion."); }
                    @Override public void verifyAbsent() { }
                }));
        service = new PanicPasswordService(scope.getWorkGate(), proof, new PanicPasswordCrypto(), wipe);
    }

    @After public void tearDown() throws Exception {
        try {
            if (totp != null && !scope.isStopped()) { totp.clear(); }
            if (scope != null) {
                PanicAndroidRuntime runtime = new PanicAndroidRuntime(scope,
                        new Handler(Looper.getMainLooper()), SafeKeySession::lock);
                runtime.lockAndClearSession();
                runtime.closeResources();
                assertTrue(runtime.areResourcesClosed());
            }
        } finally {
            try {
                if (context != null) {
                    context.deleteDatabase("safekey.db");
                    context.deleteDatabase("safekey_secondary.db");
                    context.deleteSharedPreferences("safekey_vault_key_envelope");
                    context.deleteSharedPreferences("safekey_decoy_vault_key_envelope");
                    File[] files = context.directory.listFiles();
                    if (files != null) { for (File file : files) { assertTrue(file.delete()); } }
                    assertTrue(context.directory.delete());
                }
            } finally {
                main(SafeKeySession::lock);
                ((SafeKeyApplication) InstrumentationRegistry.getInstrumentation()
                        .getTargetContext().getApplicationContext()).registerSessionCleanup();
            }
        }
    }

    private void prepare(boolean claim) throws Exception {
        CountDownLatch opened = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        VaultUnlockFlow.Request request = real.createVaultForEnrollment(MASTER.toCharArray(),
                MasterPasswordCheckStatus.CHECKED, callback(opened, error));
        await(opened, error);
        if (claim) { claim(request); }
        simple(callback -> decoy.createDecoyVault(DECOY.toCharArray(), callback));
        simple(decoy::closeDecoyVault);
    }

    private void claim(VaultUnlockFlow.Request request) {
        main(() -> { assertTrue(request.claimSession()); SafeKeySession.unlockAfterAuthentication(); });
    }

    private VaultUnlockFlow.Request beginTotpUnlock(CountDownLatch challenge, CountDownLatch opened,
                                                   AtomicReference<Exception> error) throws Exception {
        main(SafeKeySession::lock);
        simple(real::closeVault);
        return real.unlockVault(MASTER.toCharArray(), new SecureVaultCoordinator.TotpUnlockCallback() {
            @Override public void onSuccess() { opened.countDown(); }
            @Override public void onError(Exception failure) {
                error.set(failure); challenge.countDown(); opened.countDown();
            }
            @Override public void onTotpRequired(VaultUnlockFlow.Request request) { challenge.countDown(); }
        });
    }

    private void enroll(String master, String secondary) throws Exception {
        char[] first = master.toCharArray(); char[] second = secondary.toCharArray();
        char[] panic = PANIC.toCharArray(); char[] confirmation = panic.clone();
        try { service.enroll(first, second, panic, confirmation, authority); }
        finally { Arrays.fill(first, '\0'); Arrays.fill(second, '\0'); Arrays.fill(panic, '\0'); Arrays.fill(confirmation, '\0'); }
    }

    @Test public void actualClaimedRealSessionAndCredentialsEnrollWithoutOpeningDecoy() throws Exception {
        prepare(true); enroll(MASTER, DECOY);
        assertNotNull(proof.load());
        assertTrue(new PanicPasswordCrypto().matches(PANIC.toCharArray(), proof.load()));
        assertTrue(real.isVaultOpen()); assertFalse(decoy.isDecoyVaultOpen());
    }

    @Test public void incorrectActualMasterAndDecoyPasswordsNeverSaveProof() throws Exception {
        prepare(true);
        rejects(() -> enroll("Wrong!MasterR7pL2qZ9x8N", DECOY));
        rejects(() -> enroll(MASTER, "Wrong!DecoyK8wT6vY2s4B"));
        assertNull(proof.load());
    }

    @Test public void preparedRequestCopiesInputsAndCanOnlyRunOnce() throws Exception {
        prepare(true);
        PanicBackend backend = new PanicBackend(scope, service, authority);
        char[] master = MASTER.toCharArray(); char[] secondary = DECOY.toCharArray();
        char[] panic = PANIC.toCharArray(); char[] confirmation = panic.clone();
        try (PanicBackend.EnrollmentRequest request = backend.prepareEnrollment(
                master, secondary, panic, confirmation, true)) {
            Arrays.fill(master, '\0'); Arrays.fill(secondary, '\0');
            Arrays.fill(panic, '\0'); Arrays.fill(confirmation, '\0');
            request.run();
            assertTrue(new PanicPasswordCrypto().matches(PANIC.toCharArray(), proof.load()));
            rejects(request::run);
        } finally {
            Arrays.fill(master, '\0'); Arrays.fill(secondary, '\0');
            Arrays.fill(panic, '\0'); Arrays.fill(confirmation, '\0');
        }
    }

    @Test public void cancellationBeforeWorkerAndMissingWarningCannotSaveProof() throws Exception {
        prepare(true);
        PanicBackend backend = new PanicBackend(scope, service, authority);
        rejects(() -> backend.prepareEnrollment(MASTER.toCharArray(), DECOY.toCharArray(),
                PANIC.toCharArray(), PANIC.toCharArray(), false));
        PanicBackend.EnrollmentRequest request = backend.prepareEnrollment(MASTER.toCharArray(),
                DECOY.toCharArray(), PANIC.toCharArray(), PANIC.toCharArray(), true);
        request.close();
        rejects(request::run);
        assertNull(proof.load());
    }

    @Test public void cancellationDuringCryptoRejectsTheFinalSave() throws Exception {
        prepare(true);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        PanicPasswordCrypto crypto = new PanicPasswordCrypto();
        PanicPasswordService delayed = new PanicPasswordService(scope.getWorkGate(), proof,
                new PanicPasswordService.Crypto() {
                    @Override public PanicPasswordCrypto.Record create(char[] password) throws Exception {
                        entered.countDown();
                        assertTrue("Test did not release crypto worker", release.await(10, TimeUnit.SECONDS));
                        return crypto.create(password);
                    }
                    @Override public boolean matches(char[] password, PanicPasswordCrypto.Record record)
                            throws Exception { return crypto.matches(password, record); }
                }, wipe);
        PanicBackend backend = new PanicBackend(scope, delayed, authority);
        PanicBackend.EnrollmentRequest request = backend.prepareEnrollment(MASTER.toCharArray(),
                DECOY.toCharArray(), PANIC.toCharArray(), PANIC.toCharArray(), true);
        AtomicReference<Exception> failure = new AtomicReference<>();
        CountDownLatch finished = new CountDownLatch(1);
        Thread worker = new Thread(() -> {
            try { request.run(); }
            catch (Exception error) { failure.set(error); }
            finally { finished.countDown(); }
        }, "panic-enrollment-cancellation-test");
        worker.start();
        try {
            assertTrue("Crypto worker did not start", entered.await(10, TimeUnit.SECONDS));
            request.close();
        } finally {
            request.close(); release.countDown();
            assertTrue("Enrollment worker did not finish", finished.await(10, TimeUnit.SECONDS));
        }
        assertTrue(failure.get() instanceof java.util.concurrent.CancellationException);
        assertNull(proof.load());
    }

    @Test public void lockedUnclaimedAndDecoyOpenStatesCannotAuthorizeEnrollment() throws Exception {
        prepare(false);
        rejects(() -> enroll(MASTER, DECOY));
        main(SafeKeySession::unlockAfterAuthentication);
        rejects(() -> enroll(MASTER, DECOY));
        simple(callback -> decoy.unlockDecoyVault(DECOY.toCharArray(), callback));
        rejects(() -> enroll(MASTER, DECOY));
        assertNull(proof.load());
    }

    @Test public void pendingTotpCannotAuthorizeEvenIfSessionIsIncorrectlyMarkedUnlocked() throws Exception {
        prepare(true);
        byte[] secret = new byte[TotpState.SECRET_LENGTH_BYTES]; Arrays.fill(secret, (byte) 17);
        try (TotpState state = new TotpState(secret, -1L, 0, 0L)) { totp.save(state); }
        CountDownLatch challenge = new CountDownLatch(1); CountDownLatch opened = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        try (VaultUnlockFlow.Request request = beginTotpUnlock(challenge, opened, error)) {
            await(challenge, error);
            main(SafeKeySession::unlockAfterAuthentication);
            rejects(() -> enroll(MASTER, DECOY));
            assertNull(proof.load());
            assertFalse(real.isVaultOpen());
        } finally { Arrays.fill(secret, (byte) 0); }
    }

    @Test public void completedTotpCanEnrollButConfigurationChangeInvalidatesGrant() throws Exception {
        prepare(true);
        byte[] secret = new byte[TotpState.SECRET_LENGTH_BYTES]; Arrays.fill(secret, (byte) 31);
        try (TotpState state = new TotpState(secret, -1L, 0, 0L)) { totp.save(state); }
        CountDownLatch challenge = new CountDownLatch(1); CountDownLatch opened = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        VaultUnlockFlow.Request request = beginTotpUnlock(challenge, opened, error);
        await(challenge, error);
        char[] code = code(secret);
        try { request.submitCode(code, result -> { }); }
        finally { Arrays.fill(code, '\0'); Arrays.fill(secret, (byte) 0); }
        await(opened, error); claim(request);
        enroll(MASTER, DECOY);
        AtomicBoolean committed = new AtomicBoolean();
        try (PanicPasswordService.Grant grant = authority.authenticate(MASTER.toCharArray(), DECOY.toCharArray())) {
            totp.clear();
            rejects(() -> grant.commitIfCurrent(() -> committed.set(true)));
        }
        assertFalse(committed.get()); assertNotNull(proof.load());
    }

    @Test public void sessionAndCredentialChangesRejectPreviouslyVerifiedGrants() throws Exception {
        prepare(true); AtomicBoolean committed = new AtomicBoolean();
        try (PanicPasswordService.Grant grant = authority.authenticate(MASTER.toCharArray(), DECOY.toCharArray())) {
            VaultKeyEnvelopeStore stored = new VaultKeyEnvelopeStore(context);
            stored.save(stored.load());
            rejects(() -> grant.commitIfCurrent(() -> committed.set(true)));
        }
        try (PanicPasswordService.Grant grant = authority.authenticate(MASTER.toCharArray(), DECOY.toCharArray())) {
            main(SafeKeySession::lock);
            rejects(() -> grant.commitIfCurrent(() -> committed.set(true)));
        }
        assertFalse(committed.get()); assertNull(proof.load());
    }

    @Test public void malformedEnvelopeIsAnErrorAndNeverAuthorizesProofCreation() throws Exception {
        prepare(true);
        assertTrue(context.getSharedPreferences("safekey_vault_key_envelope", Context.MODE_PRIVATE)
                .edit().putString("wrapped_database_key", "invalid-envelope").commit());
        rejects(() -> enroll(MASTER, DECOY)); assertNull(proof.load());
    }

    private static char[] code(byte[] secret) throws Exception {
        long counter = PanicEnrollmentVaultTestSupport.WALL_CLOCK_MILLIS / 30_000L;
        Mac mac = Mac.getInstance("HmacSHA1"); mac.init(new SecretKeySpec(secret, "HmacSHA1"));
        byte[] result = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
        try {
            int offset = result[result.length - 1] & 15;
            int number = ((result[offset] & 127) << 24) | ((result[offset + 1] & 255) << 16)
                    | ((result[offset + 2] & 255) << 8) | (result[offset + 3] & 255);
            return String.format(Locale.US, "%06d", number % 1_000_000).toCharArray();
        } finally { Arrays.fill(result, (byte) 0); }
    }

    private static void rejects(Checked action) throws Exception {
        boolean rejected = false;
        try { action.run(); } catch (Exception expected) { rejected = true; }
        assertTrue("Unauthorized operation was accepted", rejected);
    }

    private static VaultDataService.SimpleCallback callback(CountDownLatch done, AtomicReference<Exception> error) {
        return new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { done.countDown(); }
            @Override public void onError(Exception failure) { error.set(failure); done.countDown(); }
        };
    }
    private static void simple(Start action) throws Exception {
        CountDownLatch done = new CountDownLatch(1); AtomicReference<Exception> error = new AtomicReference<>();
        action.run(callback(done, error)); await(done, error);
    }
    private static void await(CountDownLatch done, AtomicReference<Exception> error) throws Exception {
        assertTrue("Vault callback timed out", done.await(10, TimeUnit.SECONDS));
        if (error.get() != null) { throw error.get(); }
    }
    private static void main(Runnable action) { InstrumentationRegistry.getInstrumentation().runOnMainSync(action); }

    private static final class ScopedContext extends ContextWrapper implements PanicRuntimeScope.Owner {
        final String prefix = "safekey_panic_test_" + UUID.randomUUID().toString().replace("-", "") + "_";
        final PanicRuntimeScope scope;
        final File directory;
        ScopedContext(Context base, PanicRuntimeScope scope) {
            super(base); this.scope = scope;
            directory = new File(base.getNoBackupFilesDir(), prefix);
            if (!directory.mkdir()) { throw new IllegalStateException("Unable to create isolated storage."); }
        }
        @Override public Context getApplicationContext() { return this; }
        @Override public PanicRuntimeScope getPanicRuntimeScope() { return scope; }
        @Override public File getNoBackupFilesDir() { return directory; }
        @Override public File getDatabasePath(String name) { return getBaseContext().getDatabasePath(prefix + name); }
        @Override public boolean deleteDatabase(String name) { return getBaseContext().deleteDatabase(prefix + name); }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) {
            return getBaseContext().getSharedPreferences(prefix + name, mode);
        }
        @Override public boolean deleteSharedPreferences(String name) {
            return getBaseContext().deleteSharedPreferences(prefix + name);
        }
    }
}

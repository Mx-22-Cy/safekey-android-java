package com.safekey.app.security.storage;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.panic.PanicAndroidRuntime;
import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWipeCoordinator;
import com.safekey.app.security.totp.TotpEnrollmentService;
import com.safekey.app.security.totp.TotpState;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/** Production queues and SQLCipher, using only uniquely named test storage. */
@RunWith(AndroidJUnit4.class)
public class PanicRuntimeShutdownInstrumentedTest {
    private PanicRuntimeScope scope;
    private ScopedContext context;
    private PanicAndroidRuntime runtime;
    private AtomicBoolean uiCleared;

    @Before public void setUp() {
        scope = new PanicRuntimeScope();
        Context app = InstrumentationRegistry.getInstrumentation().getTargetContext()
                .getApplicationContext();
        context = new ScopedContext(app, scope);
        uiCleared = new AtomicBoolean();
        runtime = new PanicAndroidRuntime(scope, new Handler(Looper.getMainLooper()), () -> {
            assertSame(Looper.getMainLooper(), Looper.myLooper());
            uiCleared.set(true);
        });
    }

    @After public void tearDown() throws Exception {
        try {
            runtime.lockAndClearSession();
            runtime.closeResources();
        } finally {
            context.deleteDatabase("safekey.db");
            context.deleteDatabase("safekey_secondary.db");
            context.deleteSharedPreferences("safekey_vault_key_envelope");
            context.deleteSharedPreferences("safekey_decoy_vault_key_envelope");
            File directory = context.getNoBackupFilesDir();
            assertTrue(directory.list() == null || directory.list().length == 0);
            directory.delete();
        }
    }

    @Test public void sharedRuntimeClosesBothVaultConnectionsAndWorkers() throws Exception {
        SecureVaultCoordinator real = new SecureVaultCoordinator(context);
        DecoyVaultCoordinator decoy = new DecoyVaultCoordinator(context);
        create(callback -> real.createVault("public real runtime test".toCharArray(), callback));
        create(callback -> decoy.createDecoyVault("public decoy runtime test".toCharArray(), callback));
        assertTrue(real.isVaultOpen());
        assertTrue(decoy.isDecoyVaultOpen());

        runtime.lockAndClearSession();
        runtime.closeResources();
        assertTrue(uiCleared.get());
        assertFalse(real.isVaultOpen());
        assertFalse(decoy.isDecoyVaultOpen());
        assertTrue(runtime.areResourcesClosed());
        // Closing alone must not delete a database.
        assertTrue(context.getDatabasePath("safekey.db").exists());
        assertTrue(context.getDatabasePath("safekey_secondary.db").exists());
    }

    @Test public void retainedEnvelopeCannotWriteAfterItsRuntimeStops() throws Exception {
        VaultKeyEnvelopeStore retained = VaultKeyEnvelopeStore.forDecoy(context);
        VaultKeyEnvelope value = new VaultKeyEnvelope(new byte[16], "public test envelope");
        retained.save(value);
        SharedPreferences cached = context.getSharedPreferences(
                "safekey_decoy_vault_key_envelope", Context.MODE_PRIVATE);
        Map<String, ?> before = cached.getAll();
        runtime.lockAndClearSession();
        runtime.closeResources();
        try { retained.save(value); fail("stopped store accepted a write"); }
        catch (CancellationException expected) { }
        assertEquals(before, cached.getAll());
    }

    @Test public void stoppingRuntimeClearsAbandonedTotpSetupSecret() throws Exception {
        TotpEnrollmentService service = new TotpEnrollmentService(
                new TotpEnrollmentService.EnrollmentStore() {
                    private final Object lock = new Object();
                    @Override public PanicRuntimeScope getPanicRuntimeScope() { return scope; }
                    @Override public Object getTransactionLock() { return lock; }
                    @Override public TotpState load() { return null; }
                    @Override public void save(TotpState value) { fail("unexpected save"); }
                    @Override public void clear() { fail("unexpected clear"); }
                });
        TotpEnrollmentService.PendingSetup pending = service.begin();
        Field field = pending.getClass().getDeclaredField("secret");
        field.setAccessible(true);
        byte[] ownedSecret = (byte[]) field.get(pending);
        assertTrue(pending.isActive());
        runtime.lockAndClearSession();
        runtime.closeResources();
        assertFalse(pending.isActive());
        assertArrayEquals(new byte[ownedSecret.length], ownedSecret);
    }

    @Test public void mainThreadCannotWaitForWorkerTermination() {
        AtomicBoolean rejected = new AtomicBoolean();
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            try { runtime.closeResources(); }
            catch (IllegalStateException expected) { rejected.set(true); }
            catch (Exception error) { throw new AssertionError(error); }
        });
        assertTrue(rejected.get());
    }

    @Test public void stoppedDataServiceRejectsNewWork() throws Exception {
        VaultDataService service = new VaultDataService(context);
        runtime.lockAndClearSession();
        runtime.closeResources();
        try {
            service.getCredentials(new VaultDataService.ResultCallback<java.util.List<com.safekey.app.data.model.Credential>>() {
                @Override public void onSuccess(java.util.List<com.safekey.app.data.model.Credential> result) {
                    fail("stopped service delivered data");
                }
                @Override public void onError(Exception error) { fail("work must be rejected at submission"); }
            });
            fail("stopped data service accepted work");
        } catch (CancellationException expected) { }
        assertFalse(service.isVaultOpen());
    }

    @Test public void queuedOpenIsDrainedAndClosedBeforeDatabaseDeletion() throws Exception {
        VaultDataService service = new VaultDataService(context);
        Field field = VaultDataService.class.getDeclaredField("executorService");
        field.setAccessible(true);
        ExecutorService queue = (ExecutorService) field.get(service);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch cancelledOnUi = new CountDownLatch(1);
        AtomicInteger delivered = new AtomicInteger();
        AtomicBoolean marker = new AtomicBoolean();
        queue.execute(() -> {
            entered.countDown();
            try { assertTrue(release.await(30L, TimeUnit.SECONDS)); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new AssertionError(error); }
        });
        CallbackTimeoutDiagnostics.await(entered, 30L);
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 41);
        try {
            service.openVault(key, new VaultDataService.SimpleCallback() {
                @Override public void onSuccess() { delivered.incrementAndGet(); }
                @Override public void onError(Exception error) { delivered.incrementAndGet(); }
            });
        } finally { Arrays.fill(key, (byte) 0); }

        PanicAndroidRuntime pendingRuntime = new PanicAndroidRuntime(scope,
                new Handler(Looper.getMainLooper()), cancelledOnUi::countDown);
        PanicWipeCoordinator wipe = new PanicWipeCoordinator(scope.getWorkGate(),
                new PanicWipeCoordinator.Journal() {
                    @Override public boolean isPending() { return marker.get(); }
                    @Override public void markPending() { marker.set(true); }
                    @Override public void clearPending() { marker.set(false); }
                }, pendingRuntime, Collections.singletonList(new PanicWipeCoordinator.Target() {
                    @Override public String name() { return "isolated runtime database"; }
                    @Override public void erase() {
                        assertTrue(scope.areResourcesClosed());
                        assertFalse(service.isVaultOpen());
                        context.deleteDatabase("safekey.db");
                    }
                    @Override public void verifyAbsent() {
                        assertFalse(context.getDatabasePath("safekey.db").exists());
                    }
                }));
        FutureTask<Void> wiping = new FutureTask<>(() -> { wipe.wipe(); return null; });
        new Thread(wiping, "SafeKey-isolated-runtime-wipe-test").start();
        try {
            CallbackTimeoutDiagnostics.await(cancelledOnUi, 30L);
            assertFalse(scope.areResourcesClosed());
            release.countDown();
            wiping.get(30L, TimeUnit.SECONDS);
            InstrumentationRegistry.getInstrumentation().waitForIdleSync();
            assertEquals(0, delivered.get());
            assertTrue(scope.areResourcesClosed());
            assertFalse(marker.get());
        } finally { release.countDown(); }
    }

    private interface Create { void run(VaultDataService.SimpleCallback callback); }
    private static void create(Create operation) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        operation.run(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { done.countDown(); }
            @Override public void onError(Exception failure) { error.set(failure); done.countDown(); }
        });
        CallbackTimeoutDiagnostics.await(done, 30L);
        if (error.get() != null) { throw error.get(); }
    }

    private static final class ScopedContext extends ContextWrapper implements PanicRuntimeScope.Owner {
        private final PanicRuntimeScope scope;
        private final String prefix = "safekey_panic_runtime_test_" + UUID.randomUUID().toString().replace("-", "") + "_";
        ScopedContext(Context base, PanicRuntimeScope scope) { super(base); this.scope = scope; }
        @Override public Context getApplicationContext() { return this; }
        @Override public PanicRuntimeScope getPanicRuntimeScope() { return scope; }
        @Override public File getDatabasePath(String name) { return super.getDatabasePath(prefix + name); }
        @Override public boolean deleteDatabase(String name) { return super.deleteDatabase(prefix + name); }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) {
            return super.getSharedPreferences(prefix + name, mode);
        }
        @Override public boolean deleteSharedPreferences(String name) {
            return super.deleteSharedPreferences(prefix + name);
        }
        @Override public File getNoBackupFilesDir() {
            File directory = new File(super.getNoBackupFilesDir(), prefix);
            if (!directory.exists() && !directory.mkdirs()) { throw new IllegalStateException("test directory unavailable"); }
            return directory;
        }
    }
}

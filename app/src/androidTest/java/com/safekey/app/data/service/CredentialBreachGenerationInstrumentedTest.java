package com.safekey.app.data.service;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.breach.PasswordBreachResult.Status;
import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class CredentialBreachGenerationInstrumentedTest {
    private static final String DATABASE = "t44_breach_generation_test.db";
    private static final String PASSWORD = "public generation fixture";
    private final byte[] key = new byte[32];
    private Context context;
    private VaultDataService service;
    private long id;

    @Before public void setUp() throws Exception {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        context.deleteDatabase(DATABASE);
        Arrays.fill(key, (byte) 43);
        service = new VaultDataService(new SafeKeyDatabase(context, DATABASE));
        success(callback -> service.openVault(key, callback));
        id = CredentialBreachGenerationInstrumentedTest.<Long>result(callback -> service.addCredential(new Credential("Fixture", "user", PASSWORD,
                "", "Work", ""), callback));
    }

    @After public void tearDown() throws Exception {
        success(service::closeVault);
        service.shutdown();
        context.deleteDatabase(DATABASE);
        Arrays.fill(key, (byte) 0);
    }

    @Test public void closeInvalidatesQueuedCacheWriteBeforeDatabaseWorkerRunsIt() throws Exception {
        Field field = VaultDataService.class.getDeclaredField("executorService");
        field.setAccessible(true);
        ExecutorService worker = (ExecutorService) field.get(service);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        worker.execute(() -> {
            entered.countDown();
            try { CallbackTimeoutDiagnostics.await(release, 30L); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        });
        CallbackTimeoutDiagnostics.await(entered, 30L);
        CountDownLatch persisted = new CountDownLatch(1);
        AtomicReference<Exception> rejected = new AtomicReference<>();
        CountDownLatch closed = new CountDownLatch(1);
        AtomicReference<Exception> closeError = new AtomicReference<>();
        try {
            long opening = service.getVaultGeneration();
            service.updateCredentialBreachStatus(opening, id, PASSWORD, Status.BREACHED,
                    new VaultDataService.ResultCallback<Status>() {
                        @Override public void onSuccess(Status value) { persisted.countDown(); }
                        @Override public void onError(Exception error) {
                            rejected.set(error);
                            persisted.countDown();
                        }
                    });
            service.closeVault(new VaultDataService.SimpleCallback() {
                @Override public void onSuccess() { closed.countDown(); }
                @Override public void onError(Exception error) { closeError.set(error); closed.countDown(); }
            });
        } finally { release.countDown(); }
        CallbackTimeoutDiagnostics.await(persisted, 30L);
        CallbackTimeoutDiagnostics.await(closed, 30L);
        assertNotNull(rejected.get());
        if (closeError.get() != null) { throw closeError.get(); }
        success(callback -> service.openVault(key, callback));
        Credential stored = CredentialBreachGenerationInstrumentedTest.<Credential>result(callback -> service.getCredential(id, callback));
        assertEquals(Status.NOT_CHECKED, stored.getBreachStatus());
    }

    @Test public void resultForEarlierOpeningCannotFollowCloseAndReopen() throws Exception {
        long old = service.getVaultGeneration();
        success(service::closeVault);
        success(callback -> service.openVault(key, callback));
        assertTrue(service.getVaultGeneration() != old);
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> rejected = new AtomicReference<>();
        service.updateCredentialBreachStatus(old, id, PASSWORD, Status.NOT_FOUND,
                new VaultDataService.ResultCallback<Status>() {
                    @Override public void onSuccess(Status value) { done.countDown(); }
                    @Override public void onError(Exception error) { rejected.set(error); done.countDown(); }
                });
        CallbackTimeoutDiagnostics.await(done, 30L);
        assertNotNull(rejected.get());
        Credential stored = CredentialBreachGenerationInstrumentedTest.<Credential>result(callback -> service.getCredential(id, callback));
        assertEquals(Status.NOT_CHECKED, stored.getBreachStatus());
    }

    private interface Simple { void run(VaultDataService.SimpleCallback callback); }
    private interface Result<T> { void run(VaultDataService.ResultCallback<T> callback); }

    private static void success(Simple operation) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        operation.run(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { done.countDown(); }
            @Override public void onError(Exception value) { error.set(value); done.countDown(); }
        });
        CallbackTimeoutDiagnostics.await(done, 30L);
        if (error.get() != null) { throw error.get(); }
    }

    private static <T> T result(Result<T> operation) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Exception> error = new AtomicReference<>();
        AtomicReference<T> value = new AtomicReference<>();
        operation.run(new VaultDataService.ResultCallback<T>() {
            @Override public void onSuccess(T result) { value.set(result); done.countDown(); }
            @Override public void onError(Exception failure) { error.set(failure); done.countDown(); }
        });
        CallbackTimeoutDiagnostics.await(done, 30L);
        if (error.get() != null) { throw error.get(); }
        return value.get();
    }
}

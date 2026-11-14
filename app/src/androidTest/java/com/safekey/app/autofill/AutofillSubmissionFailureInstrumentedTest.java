package com.safekey.app.autofill;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.content.Intent;
import android.view.autofill.AutofillManager;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.VaultOperations;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Exercises the production Autofill submission boundary using operations that
 * reject work synchronously. No vault is created, unlocked or modified.
 */
@RunWith(AndroidJUnit4.class)
public class AutofillSubmissionFailureInstrumentedTest {

    private static final class Result<T> implements VaultDataService.ResultCallback<T> {
        int successes;
        int errors;
        T value;
        Exception exception;

        @Override public void onSuccess(T value) {
            successes++;
            this.value = value;
        }
        @Override public void onError(Exception error) {
            errors++;
            exception = error;
        }

        void assertRejected(RuntimeException expected) {
            assertEquals(0, successes);
            assertEquals(1, errors);
            assertSame(expected, exception);
            assertNull(value);
        }
    }

    private static VaultOperations rejectAtSubmission(String methodName,
                                                       RuntimeException failure) {
        return (VaultOperations) Proxy.newProxyInstance(
                VaultOperations.class.getClassLoader(),
                new Class<?>[]{VaultOperations.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals(methodName)) {
                        throw failure;
                    }
                    throw new AssertionError("Unexpected vault access: " + method.getName());
                });
    }

    private static Credential sampleCredential() {
        return new Credential(11L, "test", "test-user", "test-password",
                "example.test", "test", "", false, 1L, 1L);
    }

    private static void verifySingleCredentialRejection(RuntimeException rejection) {
        Result<Credential> result = new Result<>();
        VaultOperations operations = rejectAtSubmission("getCredential", rejection);
        // If an exception escapes here, the test fails rather than silently passing.
        AutofillVaultSession.requestCredentialForSession(
                11L, () -> true, operations, result);
        result.assertRejected(rejection);
    }

    private static void verifyCredentialListRejection(RuntimeException rejection) {
        Result<List<Credential>> result = new Result<>();
        VaultOperations operations = rejectAtSubmission("getCredentials", rejection);
        AutofillVaultSession.requestCredentialsForSession(
                () -> true, operations, result);
        result.assertRejected(rejection);
    }

    @Test public void getCredentialCancellationReportsOneErrorWithoutEscaping() {
        verifySingleCredentialRejection(new CancellationException("runtime stopped"));
    }

    @Test public void getCredentialWorkerRejectionReportsOneErrorWithoutEscaping() {
        verifySingleCredentialRejection(new RejectedExecutionException("worker stopped"));
    }

    @Test public void getCredentialsCancellationReportsOneErrorWithoutEscaping() {
        verifyCredentialListRejection(new CancellationException("runtime stopped"));
    }

    @Test public void getCredentialsWorkerRejectionReportsOneErrorWithoutEscaping() {
        verifyCredentialListRejection(new RejectedExecutionException("worker stopped"));
    }

    @Test public void lateSuccessAfterRejectedSubmissionIsIgnored() {
        AtomicReference<VaultDataService.ResultCallback<Credential>> delayed =
                new AtomicReference<>();
        RejectedExecutionException rejection = new RejectedExecutionException("rejected");
        VaultOperations operations = (VaultOperations) Proxy.newProxyInstance(
                VaultOperations.class.getClassLoader(),
                new Class<?>[]{VaultOperations.class},
                (proxy, method, arguments) -> {
                    if (!"getCredential".equals(method.getName())) {
                        throw new AssertionError("Unexpected vault operation");
                    }
                    @SuppressWarnings("unchecked")
                    VaultDataService.ResultCallback<Credential> callback =
                            (VaultDataService.ResultCallback<Credential>) arguments[1];
                    delayed.set(callback);
                    throw rejection;
                });
        Result<Credential> result = new Result<>();
        AutofillVaultSession.requestCredentialForSession(11L, () -> true, operations, result);
        delayed.get().onSuccess(sampleCredential());
        delayed.get().onError(new CancellationException("late failure"));
        result.assertRejected(rejection);
    }

    @Test public void inlineSuccessFollowedByRejectionNeverReleasesCredentials() {
        CancellationException rejection = new CancellationException("failed after inline callback");
        VaultOperations operations = (VaultOperations) Proxy.newProxyInstance(
                VaultOperations.class.getClassLoader(),
                new Class<?>[]{VaultOperations.class},
                (proxy, method, arguments) -> {
                    if (!"getCredential".equals(method.getName())) {
                        throw new AssertionError("Unexpected vault operation");
                    }
                    @SuppressWarnings("unchecked")
                    VaultDataService.ResultCallback<Credential> callback =
                            (VaultDataService.ResultCallback<Credential>) arguments[1];
                    callback.onSuccess(sampleCredential());
                    throw rejection;
                });
        Result<Credential> result = new Result<>();
        AutofillVaultSession.requestCredentialForSession(11L, () -> true, operations, result);
        result.assertRejected(rejection);
    }

    @Test public void acceptedLookupCanStillDeliverExactlyOneResult() {
        Credential record = sampleCredential();
        VaultOperations operations = (VaultOperations) Proxy.newProxyInstance(
                VaultOperations.class.getClassLoader(),
                new Class<?>[]{VaultOperations.class},
                (proxy, method, arguments) -> {
                    if (!"getCredentials".equals(method.getName())) {
                        throw new AssertionError("Unexpected vault operation");
                    }
                    @SuppressWarnings("unchecked")
                    VaultDataService.ResultCallback<List<Credential>> callback =
                            (VaultDataService.ResultCallback<List<Credential>>) arguments[0];
                    callback.onSuccess(Collections.singletonList(record));
                    callback.onSuccess(Collections.emptyList());
                    return null;
                });
        Result<List<Credential>> result = new Result<>();
        AutofillVaultSession.requestCredentialsForSession(() -> true, operations, result);
        assertEquals(1, result.successes);
        assertEquals(0, result.errors);
        assertSame(record, result.value.get(0));
    }

    @Test public void sessionExpiryWhileLookupPendingDoesNotReleaseCredential() {
        AtomicReference<VaultDataService.ResultCallback<Credential>> pending =
                new AtomicReference<>();
        java.util.concurrent.atomic.AtomicBoolean current =
                new java.util.concurrent.atomic.AtomicBoolean(true);
        VaultOperations operations = (VaultOperations) Proxy.newProxyInstance(
                VaultOperations.class.getClassLoader(),
                new Class<?>[]{VaultOperations.class},
                (proxy, method, arguments) -> {
                    if (!"getCredential".equals(method.getName())) {
                        throw new AssertionError("Unexpected vault operation");
                    }
                    @SuppressWarnings("unchecked")
                    VaultDataService.ResultCallback<Credential> callback =
                            (VaultDataService.ResultCallback<Credential>) arguments[1];
                    pending.set(callback);
                    return null;
                });
        Result<Credential> result = new Result<>();
        AutofillVaultSession.requestCredentialForSession(11L, current::get, operations, result);
        current.set(false);
        pending.get().onSuccess(sampleCredential());
        assertEquals(0, result.successes);
        assertEquals(1, result.errors);
        assertTrue(result.exception instanceof IllegalStateException);
    }

    @Test public void activitySubmissionFallbackCancelsWithoutDataset() {
        for (RuntimeException rejection : new RuntimeException[]{
                new CancellationException("canceled"),
                new RejectedExecutionException("rejected")}) {
            AtomicInteger cancellations = new AtomicInteger();
            AtomicInteger datasetDeliveries = new AtomicInteger();
            AtomicReference<Intent> deliveredIntent = new AtomicReference<>();
            AtomicInteger resultCode = new AtomicInteger(Activity.RESULT_FIRST_USER);

            AutofillAuthActivity.submitLookupOrCancel(
                    callback -> { throw rejection; },
                    new VaultDataService.ResultCallback<Credential>() {
                        @Override public void onSuccess(Credential credential) {
                            datasetDeliveries.incrementAndGet();
                            deliveredIntent.set(new Intent());
                        }
                        @Override public void onError(Exception failure) {
                            throw new AssertionError("Fallback should cancel directly", failure);
                        }
                    },
                    () -> {
                        cancellations.incrementAndGet();
                        resultCode.set(Activity.RESULT_CANCELED);
                    });

            assertEquals(1, cancellations.get());
            assertEquals(Activity.RESULT_CANCELED, resultCode.get());
            assertEquals(0, datasetDeliveries.get());
            assertNull(deliveredIntent.get());
        }
    }

    @Test public void rejectedLookupErrorPathDoesNotBuildAutofillDataset() {
        for (RuntimeException rejection : new RuntimeException[]{
                new CancellationException("canceled"),
                new RejectedExecutionException("rejected")}) {
            AtomicInteger errors = new AtomicInteger();
            AtomicInteger successes = new AtomicInteger();
            AtomicInteger canceledResult = new AtomicInteger(Activity.RESULT_FIRST_USER);
            Intent result = new Intent();
            AutofillVaultSession.requestCredentialForSession(
                    11L, () -> true, rejectAtSubmission("getCredential", rejection),
                    new VaultDataService.ResultCallback<Credential>() {
                        @Override public void onSuccess(Credential credential) {
                            successes.incrementAndGet();
                            throw new AssertionError("Would construct a dataset here");
                        }
                        @Override public void onError(Exception error) {
                            errors.incrementAndGet();
                            canceledResult.set(Activity.RESULT_CANCELED);
                        }
                    });
            assertEquals(1, errors.get());
            assertEquals(0, successes.get());
            assertEquals(Activity.RESULT_CANCELED, canceledResult.get());
            assertFalse(result.hasExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT));
        }
    }
}

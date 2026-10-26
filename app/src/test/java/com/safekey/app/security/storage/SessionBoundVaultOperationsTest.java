
package com.safekey.app.security.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.VaultDataService;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

public class SessionBoundVaultOperationsTest {

    @Test
    public void lockedSession_rejectsRequestWithoutAccessingVault() {
        TestGuard guard = new TestGuard();
        guard.current = false;

        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<List<Credential>> callback =
                new TestCallback<>();

        operations.getCredentials(callback);

        assertEquals(0, fake.requestCount);
        assertEquals(0, callback.successCount);
        assertNotNull(callback.error);
        assertTrue(callback.error instanceof IllegalStateException);
    }

    @Test
    public void activeSession_allowsVaultOperation() {
        TestGuard guard = new TestGuard();
        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<List<Credential>> callback =
                new TestCallback<>();

        operations.getCredentials(callback);

        assertEquals(1, fake.requestCount);
        assertNotNull(fake.pendingCallback);

        List<Credential> expected = Collections.emptyList();

        fake.pendingCallback.onSuccess(expected);

        assertEquals(1, callback.successCount);
        assertSame(expected, callback.result);
        assertNull(callback.error);
    }

    @Test
    public void sessionLocksBeforeCallback_sensitiveResultIsRejected() {
        TestGuard guard = new TestGuard();
        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<List<Credential>> callback =
                new TestCallback<>();

        operations.getCredentials(callback);

        assertEquals(1, fake.requestCount);

        // Simulate locking while the database request is pending.
        guard.current = false;

        fake.pendingCallback.onSuccess(
                Collections.emptyList()
        );

        assertEquals(0, callback.successCount);
        assertNull(callback.result);
        assertNotNull(callback.error);
        assertTrue(callback.error instanceof IllegalStateException);
    }

    @Test
    public void expiredSession_rejectsDelayedDatabaseError() {
        TestGuard guard = new TestGuard();
        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<List<Credential>> callback =
                new TestCallback<>();

        operations.getCredentials(callback);

        guard.current = false;

        fake.pendingCallback.onError(
                new IllegalStateException("Database unavailable")
        );

        assertEquals(0, callback.successCount);
        assertNotNull(callback.error);
        assertEquals(
                "The authenticated vault session is no longer active.",
                callback.error.getMessage()
        );
    }

    private static final class TestGuard
            implements SessionBoundVaultOperations.SessionGuard {

        boolean current = true;

        @Override
        public boolean isCurrent() {
            return current;
        }

        @Override
        public boolean runIfCurrent(Runnable action) {
            if (!current) {
                return false;
            }

            action.run();
            return true;
        }
    }

    private static final class TestCallback<T>
            implements VaultDataService.ResultCallback<T> {

        int successCount;
        T result;
        Exception error;

        @Override
        public void onSuccess(T value) {
            successCount++;
            result = value;
        }

        @Override
        public void onError(Exception exception) {
            error = exception;
        }
    }

    private static final class FakeVaultOperations
            implements VaultOperations {

        int requestCount;

        VaultDataService.ResultCallback<List<Credential>>
                pendingCallback;

        @Override
        public void getCredentials(
                VaultDataService.ResultCallback<List<Credential>> callback
        ) {
            requestCount++;
            pendingCallback = callback;
        }

        @Override
        public void getCredential(
                long id,
                VaultDataService.ResultCallback<Credential> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void addCredential(
                Credential credential,
                VaultDataService.ResultCallback<Long> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void updateCredential(
                Credential credential,
                VaultDataService.ResultCallback<Integer> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteCredential(
                long id,
                VaultDataService.ResultCallback<Integer> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setCredentialFavorite(
                long id,
                boolean favorite,
                VaultDataService.ResultCallback<Integer> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void getVaultCounts(
                VaultDataService.ResultCallback<VaultCounts> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void getSecureNote(
                long id,
                VaultDataService.ResultCallback<SecureNote> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void addSecureNote(
                SecureNote note,
                VaultDataService.ResultCallback<Long> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void updateSecureNote(
                SecureNote note,
                VaultDataService.ResultCallback<Integer> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteSecureNote(
                long id,
                VaultDataService.ResultCallback<Integer> callback
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void getSecureNotes(
                VaultDataService.ResultCallback<List<SecureNote>> callback
        ) {
            throw new UnsupportedOperationException();
        }
    }
}

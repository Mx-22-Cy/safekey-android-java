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

        TestCallback<List<Credential>> callback = new TestCallback<>();

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

        TestCallback<List<Credential>> callback = new TestCallback<>();

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

        TestCallback<List<Credential>> callback = new TestCallback<>();

        operations.getCredentials(callback);

        assertEquals(1, fake.requestCount);

        guard.current = false;

        fake.pendingCallback.onSuccess(Collections.emptyList());

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

        TestCallback<List<Credential>> callback = new TestCallback<>();

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

    @Test
    public void activeSession_canReadVaultDisplayName() {
        TestGuard guard = new TestGuard();
        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<String> callback = new TestCallback<>();

        operations.getVaultDisplayName(callback);

        assertEquals(1, fake.displayNameReadCount);
        assertNotNull(fake.pendingNameCallback);

        fake.pendingNameCallback.onSuccess("Local Vault");

        assertEquals(1, callback.successCount);
        assertEquals("Local Vault", callback.result);
        assertNull(callback.error);
    }

    @Test
    public void activeSession_canRequestVaultRename() {
        TestGuard guard = new TestGuard();
        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<Integer> callback = new TestCallback<>();

        operations.updateVaultDisplayName("My Vault", callback);

        assertEquals(1, fake.displayNameUpdateCount);
        assertEquals("My Vault", fake.requestedDisplayName);
        assertNotNull(fake.pendingUpdateCallback);

        fake.pendingUpdateCallback.onSuccess(1);

        assertEquals(1, callback.successCount);
        assertEquals(Integer.valueOf(1), callback.result);
        assertNull(callback.error);
    }

    @Test
    public void lockedSession_rejectsDisplayNameOperations() {
        TestGuard guard = new TestGuard();
        guard.current = false;

        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<String> readCallback = new TestCallback<>();
        TestCallback<Integer> updateCallback = new TestCallback<>();

        operations.getVaultDisplayName(readCallback);

        operations.updateVaultDisplayName(
                "Should Not Be Saved",
                updateCallback
        );

        assertEquals(0, fake.displayNameReadCount);
        assertEquals(0, fake.displayNameUpdateCount);

        assertEquals(0, readCallback.successCount);
        assertEquals(0, updateCallback.successCount);

        assertNotNull(readCallback.error);
        assertNotNull(updateCallback.error);

        assertTrue(
                readCallback.error instanceof IllegalStateException
        );

        assertTrue(
                updateCallback.error instanceof IllegalStateException
        );
    }

    @Test
    public void expiredSession_rejectsDelayedDisplayNameResult() {
        TestGuard guard = new TestGuard();
        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<String> callback = new TestCallback<>();

        operations.getVaultDisplayName(callback);

        assertEquals(1, fake.displayNameReadCount);

        guard.current = false;

        fake.pendingNameCallback.onSuccess("Private Vault");

        assertEquals(0, callback.successCount);
        assertNull(callback.result);
        assertNotNull(callback.error);

        assertEquals(
                "The authenticated vault session is no longer active.",
                callback.error.getMessage()
        );
    }

    @Test
    public void expiredSession_rejectsDelayedRenameCallback() {
        TestGuard guard = new TestGuard();
        FakeVaultOperations fake = new FakeVaultOperations();

        SessionBoundVaultOperations operations =
                new SessionBoundVaultOperations(fake, guard);

        TestCallback<Integer> callback = new TestCallback<>();

        operations.updateVaultDisplayName("Old Session Name", callback);

        assertEquals(1, fake.displayNameUpdateCount);

        guard.current = false;

        fake.pendingUpdateCallback.onSuccess(1);

        assertEquals(0, callback.successCount);
        assertNull(callback.result);
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
        int displayNameReadCount;
        int displayNameUpdateCount;

        String requestedDisplayName;

        VaultDataService.ResultCallback<List<Credential>>
                pendingCallback;

        VaultDataService.ResultCallback<String>
                pendingNameCallback;

        VaultDataService.ResultCallback<Integer>
                pendingUpdateCallback;

        @Override
        public void getVaultDisplayName(
                VaultDataService.ResultCallback<String> callback
        ) {
            displayNameReadCount++;
            pendingNameCallback = callback;
        }

        @Override
        public void updateVaultDisplayName(
                String displayName,
                VaultDataService.ResultCallback<Integer> callback
        ) {
            displayNameUpdateCount++;
            requestedDisplayName = displayName;
            pendingUpdateCallback = callback;
        }

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

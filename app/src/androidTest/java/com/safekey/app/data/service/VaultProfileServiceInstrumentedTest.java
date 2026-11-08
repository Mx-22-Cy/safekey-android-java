package com.safekey.app.data.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.database.SafeKeyDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class VaultProfileServiceInstrumentedTest {

    private static final int CALLBACK_TIMEOUT_SECONDS = 10;

    private Context context;
    private String databaseName;
    private byte[] databaseKey;
    private VaultDataService service;

    @Before
    public void setUp() {
        context = InstrumentationRegistry
                .getInstrumentation()
                .getTargetContext();

        databaseName = "profile_service_"
                + UUID.randomUUID()
                + ".db";

        databaseKey =
                new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];

        Arrays.fill(databaseKey, (byte) 47);

        service = new VaultDataService(
                new SafeKeyDatabase(context, databaseName)
        );
    }

    @After
    public void tearDown() throws Exception {
        if (service != null) {
            service.shutdown();

            // Ensure shutdown has finished before deleting the test database.
            long deadline = System.nanoTime()
                    + TimeUnit.SECONDS.toNanos(CALLBACK_TIMEOUT_SECONDS);

            while (service.isVaultOpen()
                    && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }

            assertTrue(
                    "Vault did not close during test cleanup.",
                    !service.isVaultOpen()
            );
        }

        if (databaseKey != null) {
            Arrays.fill(databaseKey, (byte) 0);
        }

        if (context != null && databaseName != null) {
            context.deleteDatabase(databaseName);
        }
    }

    @Test
    public void openVault_canReadAndUpdateDisplayName()
            throws Exception {

        openVault();

        assertEquals("Local Vault", readDisplayName());

        updateDisplayName("Study Vault");

        assertEquals("Study Vault", readDisplayName());
    }

    @Test
    public void closeAndReopen_preservesDisplayName()
            throws Exception {

        openVault();

        updateDisplayName("Private Vault");

        closeVault();

        openVault();

        assertEquals("Private Vault", readDisplayName());
    }

    @Test
    public void closedVault_rejectsDisplayNameUpdate()
            throws Exception {

        openVault();
        closeVault();

        AwaitResult<Integer> callback = new AwaitResult<>();

        service.updateVaultDisplayName(
                "Should Not Be Saved",
                callback
        );

        Exception error = callback.awaitError();

        assertTrue(error instanceof IllegalStateException);
        assertEquals("Vault is not open.", error.getMessage());

        openVault();

        assertEquals("Local Vault", readDisplayName());
    }

    @Test
    public void renameSubmittedAfterCloseRequest_isRejected()
            throws Exception {

        openVault();

        // Closing invalidates the current vault generation immediately.
        AwaitSimple closeCallback = new AwaitSimple();

        service.closeVault(closeCallback);

        AwaitResult<Integer> renameCallback = new AwaitResult<>();

        // Attempt to rename after the close request.
        service.updateVaultDisplayName(
                "Should Not Be Saved",
                renameCallback
        );

        // Wait for the database to close.
        closeCallback.awaitSuccess();

        // Verify that the rename was rejected.
        Exception error = renameCallback.awaitError();

        assertTrue(error instanceof IllegalStateException);

        // Reopen and verify that the rejected name was not saved.
        openVault();

        assertEquals("Local Vault", readDisplayName());
    }

    private void openVault() throws Exception {
        AwaitSimple callback = new AwaitSimple();

        service.openVault(databaseKey, callback);

        callback.awaitSuccess();
    }

    private void closeVault() throws Exception {
        AwaitSimple callback = new AwaitSimple();

        service.closeVault(callback);

        callback.awaitSuccess();
    }

    private String readDisplayName() throws Exception {
        AwaitResult<String> callback = new AwaitResult<>();

        service.getVaultDisplayName(callback);

        return callback.awaitSuccess();
    }

    private void updateDisplayName(String name) throws Exception {
        AwaitResult<Integer> callback = new AwaitResult<>();

        service.updateVaultDisplayName(name, callback);

        assertEquals(
                Integer.valueOf(1),
                callback.awaitSuccess()
        );
    }

    private static final class AwaitSimple
            implements VaultDataService.SimpleCallback {

        private final CountDownLatch latch = new CountDownLatch(1);

        private final AtomicReference<Exception> error =
                new AtomicReference<>();

        @Override
        public void onSuccess() {
            latch.countDown();
        }

        @Override
        public void onError(Exception exception) {
            error.set(exception);
            latch.countDown();
        }

        void awaitSuccess() throws Exception {
            assertTrue(
                    "Simple callback timed out.",
                    latch.await(
                            CALLBACK_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS
                    )
            );

            if (error.get() != null) {
                throw error.get();
            }
        }
    }

    private static final class AwaitResult<T>
            implements VaultDataService.ResultCallback<T> {

        private final CountDownLatch latch = new CountDownLatch(1);

        private T result;
        private Exception error;

        @Override
        public void onSuccess(T value) {
            result = value;
            latch.countDown();
        }

        @Override
        public void onError(Exception exception) {
            error = exception;
            latch.countDown();
        }

        T awaitSuccess() throws Exception {
            awaitCompletion();

            if (error != null) {
                throw error;
            }

            assertNotNull(result);

            return result;
        }

        Exception awaitError() throws Exception {
            awaitCompletion();

            assertNotNull("Expected an error callback.", error);

            return error;
        }

        private void awaitCompletion() throws InterruptedException {
            assertTrue(
                    "Result callback timed out.",
                    latch.await(
                            CALLBACK_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS
                    )
            );
        }
    }
}

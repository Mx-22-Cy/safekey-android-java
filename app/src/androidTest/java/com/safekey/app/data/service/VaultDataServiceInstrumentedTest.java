package com.safekey.app.data.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class VaultDataServiceInstrumentedTest {

    private static final String TEST_DATABASE_NAME =
            "safekey_service_instrumented_test.db";

    /*
     * Creates a fresh 32-byte test database key.
     */
    private static byte[] newTestDatabaseKey() {

        byte[] databaseKey =
                new byte[
                        SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES
                        ];

        for (
                int index = 0;
                index < databaseKey.length;
                index++
        ) {
            databaseKey[index] =
                    (byte) (
                            index + 1
                    );
        }

        return databaseKey;
    }

    private static final long CALLBACK_TIMEOUT_SECONDS =
            5;

    private Context context;

    private VaultDataService service;

    @Before
    public void setUp() {

        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        context.deleteDatabase(
                TEST_DATABASE_NAME
        );

        SafeKeyDatabase testDatabase =
                new SafeKeyDatabase(
                        context,
                        TEST_DATABASE_NAME
                );

        service =
                new VaultDataService(
                        testDatabase
                );
    }

    @After
    public void tearDown()
            throws Exception {

        if (service != null) {

            service.shutdown();

            waitForVaultToClose();

            service = null;
        }

        context.deleteDatabase(
                TEST_DATABASE_NAME
        );
    }

    @Test
    public void credentialCanBeReadByIdAndPersistsAfterCloseAndReopen()
            throws Exception {

        /*
         * OPEN
         */
        awaitSimpleSuccess(
                callback ->
                        service.openVault(
                                newTestDatabaseKey(),
                                callback
                        )
        );

        assertTrue(
                service.isVaultOpen()
        );

        /*
         * ADD CREDENTIAL
         */
        Credential credential =
                new Credential(
                        "Persistent Service Credential",
                        "persistent-user",
                        "persistent-password",
                        "persistent.example.test",
                        "Work",
                        "Persistent credential note"
                );

        long credentialId =
                awaitResultSuccess(
                        callback ->
                                service.addCredential(
                                        credential,
                                        callback
                                )
                );

        assertTrue(
                credentialId > 0
        );

        /*
         * READ THE SINGLE CREDENTIAL BY ID
         */
        Credential storedCredential =
                awaitResultSuccess(
                        callback ->
                                service.getCredential(
                                        credentialId,
                                        callback
                                )
                );

        assertNotNull(
                storedCredential
        );

        assertEquals(
                credentialId,
                storedCredential.getId()
        );

        assertEquals(
                "Persistent Service Credential",
                storedCredential.getTitle()
        );

        assertEquals(
                "persistent-user",
                storedCredential.getUsername()
        );

        assertEquals(
                "persistent-password",
                storedCredential.getPassword()
        );

        assertEquals(
                "persistent.example.test",
                storedCredential.getWebsite()
        );

        assertEquals(
                "Work",
                storedCredential.getCategory()
        );

        assertEquals(
                "Persistent credential note",
                storedCredential.getNotes()
        );

        /*
         * CLOSE THE VAULT
         */
        awaitSimpleSuccess(
                service::closeVault
        );

        assertFalse(
                service.isVaultOpen()
        );

        /*
         * REOPEN WITH THE SAME RAW DATABASE KEY
         */
        awaitSimpleSuccess(
                callback ->
                        service.openVault(
                                newTestDatabaseKey(),
                                callback
                        )
        );

        assertTrue(
                service.isVaultOpen()
        );

        /*
         * VERIFY THE SAME STORED RECORD IS STILL PRESENT
         */
        Credential reopenedCredential =
                awaitResultSuccess(
                        callback ->
                                service.getCredential(
                                        credentialId,
                                        callback
                                )
                );

        assertNotNull(
                reopenedCredential
        );

        assertEquals(
                credentialId,
                reopenedCredential.getId()
        );

        assertEquals(
                "Persistent Service Credential",
                reopenedCredential.getTitle()
        );

        assertEquals(
                "persistent-user",
                reopenedCredential.getUsername()
        );

        assertEquals(
                "persistent-password",
                reopenedCredential.getPassword()
        );

        assertEquals(
                "persistent.example.test",
                reopenedCredential.getWebsite()
        );

        assertEquals(
                "Work",
                reopenedCredential.getCategory()
        );

        assertEquals(
                "Persistent credential note",
                reopenedCredential.getNotes()
        );
    }

    @Test
    public void serviceSupportsOpenCrudSearchCloseAndShutdown()
            throws Exception {

        /*
         * OPEN
         */
        awaitSimpleSuccess(
                callback ->
                        service.openVault(
                                newTestDatabaseKey(),
                                callback
                        )
        );

        assertTrue(
                service.isVaultOpen()
        );

        /*
         * ADD CREDENTIAL
         */
        Credential credential =
                new Credential(
                        "Service Credential",
                        "service-user",
                        "service-password",
                        "service.example.test",
                        "Work",
                        "Service credential note"
                );

        long credentialId =
                awaitResultSuccess(
                        callback ->
                                service.addCredential(
                                        credential,
                                        callback
                                )
                );

        assertTrue(
                credentialId > 0
        );

        /*
         * READ CREDENTIAL
         */
        List<Credential> credentials =
                awaitResultSuccess(
                        service::getCredentials
                );

        assertEquals(
                1,
                credentials.size()
        );

        Credential savedCredential =
                credentials.get(0);

        assertEquals(
                credentialId,
                savedCredential.getId()
        );

        assertEquals(
                "Service Credential",
                savedCredential.getTitle()
        );

        assertEquals(
                "service-user",
                savedCredential.getUsername()
        );

        assertEquals(
                "service-password",
                savedCredential.getPassword()
        );

        assertEquals(
                "Service credential note",
                savedCredential.getNotes()
        );

        /*
         * UPDATE CREDENTIAL
         */
        savedCredential.setTitle(
                "Updated Service Credential"
        );

        savedCredential.setPassword(
                "updated-service-password"
        );

        savedCredential.setNotes(
                "Updated service credential note"
        );

        int credentialRowsUpdated =
                awaitResultSuccess(
                        callback ->
                                service.updateCredential(
                                        savedCredential,
                                        callback
                                )
                );

        assertEquals(
                1,
                credentialRowsUpdated
        );

        /*
         * SEARCH CREDENTIAL
         */
        List<Credential> credentialSearchResults =
                awaitResultSuccess(
                        callback ->
                                service.searchCredentials(
                                        "Updated Service",
                                        callback
                                )
                );

        assertEquals(
                1,
                credentialSearchResults.size()
        );

        assertEquals(
                "updated-service-password",
                credentialSearchResults
                        .get(0)
                        .getPassword()
        );

        assertEquals(
                "Updated service credential note",
                credentialSearchResults
                        .get(0)
                        .getNotes()
        );

        /*
         * ADD SECURE NOTE
         */
        SecureNote secureNote =
                new SecureNote(
                        "Service Secure Note",
                        "Service secure note content"
                );

        long noteId =
                awaitResultSuccess(
                        callback ->
                                service.addSecureNote(
                                        secureNote,
                                        callback
                                )
                );

        assertTrue(
                noteId > 0
        );

        /*
         * READ SECURE NOTE
         */
        List<SecureNote> secureNotes =
                awaitResultSuccess(
                        service::getSecureNotes
                );

        assertEquals(
                1,
                secureNotes.size()
        );

        SecureNote savedNote =
                secureNotes.get(0);

        assertEquals(
                noteId,
                savedNote.getId()
        );

        assertEquals(
                "Service Secure Note",
                savedNote.getTitle()
        );

        assertEquals(
                "Service secure note content",
                savedNote.getContent()
        );

        /*
         * UPDATE SECURE NOTE
         */
        savedNote.setTitle(
                "Updated Service Secure Note"
        );

        savedNote.setContent(
                "Updated service secure note content"
        );

        int noteRowsUpdated =
                awaitResultSuccess(
                        callback ->
                                service.updateSecureNote(
                                        savedNote,
                                        callback
                                )
                );

        assertEquals(
                1,
                noteRowsUpdated
        );

        /*
         * SEARCH SECURE NOTE
         */
        List<SecureNote> noteSearchResults =
                awaitResultSuccess(
                        callback ->
                                service.searchSecureNotes(
                                        "Updated service secure",
                                        callback
                                )
                );

        assertEquals(
                1,
                noteSearchResults.size()
        );

        assertEquals(
                "Updated Service Secure Note",
                noteSearchResults
                        .get(0)
                        .getTitle()
        );

        assertEquals(
                "Updated service secure note content",
                noteSearchResults
                        .get(0)
                        .getContent()
        );

        /*
         * DELETE CREDENTIAL
         */
        int credentialRowsDeleted =
                awaitResultSuccess(
                        callback ->
                                service.deleteCredential(
                                        credentialId,
                                        callback
                                )
                );

        assertEquals(
                1,
                credentialRowsDeleted
        );

        /*
         * DELETE SECURE NOTE
         */
        int noteRowsDeleted =
                awaitResultSuccess(
                        callback ->
                                service.deleteSecureNote(
                                        noteId,
                                        callback
                                )
                );

        assertEquals(
                1,
                noteRowsDeleted
        );

        List<Credential> credentialsAfterDelete =
                awaitResultSuccess(
                        service::getCredentials
                );

        assertTrue(
                credentialsAfterDelete.isEmpty()
        );

        List<SecureNote> notesAfterDelete =
                awaitResultSuccess(
                        service::getSecureNotes
                );

        assertTrue(
                notesAfterDelete.isEmpty()
        );

        /*
         * CLOSE
         */
        awaitSimpleSuccess(
                service::closeVault
        );

        assertFalse(
                service.isVaultOpen()
        );

        Exception closedVaultError =
                awaitResultError(
                        service::getCredentials
                );

        assertTrue(
                closedVaultError
                        instanceof IllegalStateException
        );

        assertEquals(
                "Vault is not open.",
                closedVaultError.getMessage()
        );

        /*
         * REOPEN BEFORE SHUTDOWN
         */
        awaitSimpleSuccess(
                callback ->
                        service.openVault(
                                newTestDatabaseKey(),
                                callback
                        )
        );

        assertTrue(
                service.isVaultOpen()
        );

        /*
         * SHUTDOWN
         */
        service.shutdown();

        waitForVaultToClose();

        assertFalse(
                service.isVaultOpen()
        );

        /*
         * Executor must reject new work
         * after shutdown.
         */
        try {

            service.getCredentials(
                    new VaultDataService.ResultCallback<List<Credential>>() {

                        @Override
                        public void onSuccess(
                                List<Credential> result
                        ) {
                            // No action required.
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {
                            // No action required.
                        }
                    }
            );

            fail(
                    "Expected operation after shutdown to be rejected."
            );

        } catch (RejectedExecutionException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    private void awaitSimpleSuccess(
            SimpleOperation operation
    ) throws Exception {

        CountDownLatch latch =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        AtomicBoolean callbackOnMainThread =
                new AtomicBoolean(
                        false
                );

        operation.run(
                new VaultDataService.SimpleCallback() {

                    @Override
                    public void onSuccess() {

                        callbackOnMainThread.set(
                                Looper.myLooper()
                                        == Looper.getMainLooper()
                        );

                        latch.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        callbackOnMainThread.set(
                                Looper.myLooper()
                                        == Looper.getMainLooper()
                        );

                        error.set(
                                exception
                        );

                        latch.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for service callback.",
                latch.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertTrue(
                "Service callback must run on the Android main thread.",
                callbackOnMainThread.get()
        );

        if (error.get() != null) {
            throw error.get();
        }
    }

    private <T> T awaitResultSuccess(
            ResultOperation<T> operation
    ) throws Exception {

        CountDownLatch latch =
                new CountDownLatch(
                        1
                );

        AtomicReference<T> result =
                new AtomicReference<>();

        AtomicReference<Exception> error =
                new AtomicReference<>();

        AtomicBoolean callbackOnMainThread =
                new AtomicBoolean(
                        false
                );

        operation.run(
                new VaultDataService.ResultCallback<T>() {

                    @Override
                    public void onSuccess(
                            T callbackResult
                    ) {

                        callbackOnMainThread.set(
                                Looper.myLooper()
                                        == Looper.getMainLooper()
                        );

                        result.set(
                                callbackResult
                        );

                        latch.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        callbackOnMainThread.set(
                                Looper.myLooper()
                                        == Looper.getMainLooper()
                        );

                        error.set(
                                exception
                        );

                        latch.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for service callback.",
                latch.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertTrue(
                "Service callback must run on the Android main thread.",
                callbackOnMainThread.get()
        );

        if (error.get() != null) {
            throw error.get();
        }

        return result.get();
    }

    private <T> Exception awaitResultError(
            ResultOperation<T> operation
    ) throws Exception {

        CountDownLatch latch =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        AtomicBoolean successCalled =
                new AtomicBoolean(
                        false
                );

        AtomicBoolean callbackOnMainThread =
                new AtomicBoolean(
                        false
                );

        operation.run(
                new VaultDataService.ResultCallback<T>() {

                    @Override
                    public void onSuccess(
                            T result
                    ) {

                        callbackOnMainThread.set(
                                Looper.myLooper()
                                        == Looper.getMainLooper()
                        );

                        successCalled.set(
                                true
                        );

                        latch.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        callbackOnMainThread.set(
                                Looper.myLooper()
                                        == Looper.getMainLooper()
                        );

                        error.set(
                                exception
                        );

                        latch.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for service callback.",
                latch.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertTrue(
                "Service callback must run on the Android main thread.",
                callbackOnMainThread.get()
        );

        assertFalse(
                "Success callback must not run when an error is expected.",
                successCalled.get()
        );

        assertNotNull(
                "Expected service error callback.",
                error.get()
        );

        return error.get();
    }

    private void waitForVaultToClose()
            throws Exception {

        long deadline =
                System.currentTimeMillis()
                        + TimeUnit.SECONDS.toMillis(
                        CALLBACK_TIMEOUT_SECONDS
                );

        while (
                service != null
                        && service.isVaultOpen()
                        && System.currentTimeMillis() < deadline
        ) {

            Thread.sleep(
                    25
            );
        }

        if (service != null) {

            assertFalse(
                    "Vault did not close before timeout.",
                    service.isVaultOpen()
            );
        }
    }

    private interface SimpleOperation {

        void run(
                VaultDataService.SimpleCallback callback
        );
    }

    private interface ResultOperation<T> {

        void run(
                VaultDataService.ResultCallback<T> callback
        );
    }
}
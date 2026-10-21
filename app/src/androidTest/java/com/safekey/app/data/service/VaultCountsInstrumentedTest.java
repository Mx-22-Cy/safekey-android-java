package com.safekey.app.data.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.VaultCounts;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@RunWith(AndroidJUnit4.class)
public class VaultCountsInstrumentedTest {

    private Context context;
    private String databaseName;
    private byte[] databaseKey;
    private SafeKeyDatabase databaseManager;
    private VaultDataService service;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        databaseName = "safekey_counts_" + UUID.randomUUID() + ".db";
        databaseKey = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
        Arrays.fill(databaseKey, (byte) 57);

        databaseManager = new SafeKeyDatabase(context, databaseName);
        service = new VaultDataService(databaseManager);
    }

    @After
    public void tearDown() throws InterruptedException {
        try {
            if (service != null) {
                awaitSimple(service::closeVault);
            }
        } finally {
            if (service != null) {
                service.shutdown();
            }

            if (databaseKey != null) {
                Arrays.fill(databaseKey, (byte) 0);
            }

            if (context != null && databaseName != null) {
                context.deleteDatabase(databaseName);
            }
        }
    }

    @Test
    public void emptyVault_returnsZeroCounts() throws InterruptedException {
        openVault();
        assertCounts(0, 0, 0);
    }

    @Test
    public void mixedVault_returnsCredentialFavoriteAndNoteCounts()
            throws InterruptedException {
        seedMixedVault();
        openVault();
        assertCounts(2, 1, 2);
    }

    @Test
    public void mutations_areReflectedInTheNextCountsQuery()
            throws InterruptedException {
        seedMixedVault();
        openVault();

        expectOneRow(callback -> service.setCredentialFavorite(17, false, callback));
        assertCounts(2, 0, 2);

        long addedId = awaitId(callback -> service.addCredential(
                new Credential(
                        "Added credential",
                        "fixture-user",
                        "fixture-password",
                        "https://fixture.example",
                        "Work",
                        "fixture-notes"
                ),
                callback
        ));
        assertTrue(addedId > 0);
        assertCounts(3, 0, 2);

        expectOneRow(callback -> service.setCredentialFavorite(addedId, true, callback));
        assertCounts(3, 1, 2);

        expectOneRow(callback -> service.deleteCredential(18, callback));
        assertCounts(2, 1, 2);

        expectOneRow(callback -> service.deleteCredential(addedId, callback));
        assertCounts(1, 0, 2);

        expectOneRow(callback -> service.deleteSecureNote(9, callback));
        assertCounts(1, 0, 1);

        expectOneRow(callback -> service.deleteSecureNote(10, callback));
        assertCounts(1, 0, 0);

        expectOneRow(callback -> service.deleteCredential(17, callback));
        assertCounts(0, 0, 0);
    }

    @Test
    public void closedVault_reportsAnErrorInsteadOfZeroCounts()
            throws InterruptedException {
        assertClosedVaultError();

        openVault();
        assertCounts(0, 0, 0);

        awaitSimple(service::closeVault);
        assertClosedVaultError();
    }

    @Test
    public void reopeningVault_preservesCounts() throws InterruptedException {
        seedMixedVault();
        openVault();
        assertCounts(2, 1, 2);

        awaitSimple(service::closeVault);
        openVault();
        assertCounts(2, 1, 2);
    }

    @Test
    public void countsQueuedAfterAnInsert_includeTheInsertedCredential()
            throws InterruptedException {
        openVault();

        AwaitResult<Long> insertion = new AwaitResult<>();
        service.addCredential(
                new Credential(
                        "Queued credential",
                        "fixture-user",
                        "fixture-password",
                        "",
                        "Work",
                        ""
                ),
                insertion
        );

        AwaitResult<VaultCounts> counts = new AwaitResult<>();
        service.getVaultCounts(counts);

        assertTrue(insertion.awaitSuccess() > 0);
        VaultCounts result = counts.awaitSuccess();
        assertEquals(1L, result.getCredentialCount());
        assertEquals(0L, result.getFavoriteCount());
        assertEquals(0L, result.getSecureNoteCount());
    }

    private void openVault() throws InterruptedException {
        awaitSimple(callback -> service.openVault(databaseKey, callback));
    }

    private void assertCounts(long credentials, long favorites, long notes)
            throws InterruptedException {
        AwaitResult<VaultCounts> receiver = new AwaitResult<>();
        service.getVaultCounts(receiver);
        VaultCounts counts = receiver.awaitSuccess();

        assertEquals(credentials, counts.getCredentialCount());
        assertEquals(favorites, counts.getFavoriteCount());
        assertEquals(notes, counts.getSecureNoteCount());
    }

    private void assertClosedVaultError() throws InterruptedException {
        AwaitResult<VaultCounts> receiver = new AwaitResult<>();
        service.getVaultCounts(receiver);
        Exception error = receiver.awaitError();

        assertTrue(error instanceof IllegalStateException);
        assertEquals("Vault is not open.", error.getMessage());
    }

    private void awaitSimple(Consumer<VaultDataService.SimpleCallback> action)
            throws InterruptedException {
        AwaitResult<Boolean> receiver = new AwaitResult<>();

        action.accept(new VaultDataService.SimpleCallback() {
            @Override
            public void onSuccess() {
                receiver.onSuccess(true);
            }

            @Override
            public void onError(Exception exception) {
                receiver.onError(exception);
            }
        });

        receiver.awaitSuccess();
    }

    private long awaitId(Consumer<VaultDataService.ResultCallback<Long>> action)
            throws InterruptedException {
        AwaitResult<Long> receiver = new AwaitResult<>();
        action.accept(receiver);
        return receiver.awaitSuccess();
    }

    private void expectOneRow(
            Consumer<VaultDataService.ResultCallback<Integer>> action
    ) throws InterruptedException {
        AwaitResult<Integer> receiver = new AwaitResult<>();
        action.accept(receiver);
        assertEquals(Integer.valueOf(1), receiver.awaitSuccess());
    }

    private void seedMixedVault() {
        SQLiteDatabase database = databaseManager.open(databaseKey);

        try {
            database.execSQL(
                    "INSERT INTO credentials "
                            + "(id, title, username, password_ciphertext, favorite, created_at, updated_at) "
                            + "VALUES (17, 'First', 'fixture-user', 'fixture-password', 1, 1, 1)"
            );
            database.execSQL(
                    "INSERT INTO credentials "
                            + "(id, title, username, password_ciphertext, favorite, created_at, updated_at) "
                            + "VALUES (18, 'Second', 'fixture-user', 'fixture-password', 0, 1, 1)"
            );
            database.execSQL(
                    "INSERT INTO secure_notes "
                            + "(id, title, content_ciphertext, created_at, updated_at) "
                            + "VALUES (9, 'First note', 'fixture-content', 1, 1)"
            );
            database.execSQL(
                    "INSERT INTO secure_notes "
                            + "(id, title, content_ciphertext, created_at, updated_at) "
                            + "VALUES (10, 'Second note', 'fixture-content', 1, 1)"
            );
        } finally {
            databaseManager.close();
        }
    }

    private static final class AwaitResult<T>
            implements VaultDataService.ResultCallback<T> {

        private final CountDownLatch completed = new CountDownLatch(1);
        private T value;
        private Exception error;
        private boolean onMainThread;

        @Override
        public void onSuccess(T result) {
            value = result;
            onMainThread = Looper.myLooper() == Looper.getMainLooper();
            completed.countDown();
        }

        @Override
        public void onError(Exception exception) {
            error = exception;
            onMainThread = Looper.myLooper() == Looper.getMainLooper();
            completed.countDown();
        }

        T awaitSuccess() throws InterruptedException {
            awaitCompletion();
            assertNull(error);
            assertNotNull(value);
            return value;
        }

        Exception awaitError() throws InterruptedException {
            awaitCompletion();
            assertNotNull(error);
            assertNull(value);
            return error;
        }

        private void awaitCompletion() throws InterruptedException {
            assertTrue("Callback timed out.", completed.await(10, TimeUnit.SECONDS));
            assertTrue("Callback must run on the main thread.", onMainThread);
        }
    }
}

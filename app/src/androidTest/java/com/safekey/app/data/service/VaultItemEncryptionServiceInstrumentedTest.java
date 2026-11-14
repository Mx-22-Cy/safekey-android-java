package com.safekey.app.data.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.database.Cursor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Exercises real VaultDataService opening on disposable SQLCipher databases.
 * Never uses the normal safekey.db or safekey_secondary.db.
 */
@RunWith(AndroidJUnit4.class)
public class VaultItemEncryptionServiceInstrumentedTest {

    private Context context;
    private String name;
    private byte[] key;
    private SafeKeyDatabase manager;
    private VaultDataService service;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        name = "israa_v4_service_" + UUID.randomUUID() + ".db";
        key = key(19);
        manager = new SafeKeyDatabase(context, name);
        service = new VaultDataService(manager);
    }

    @After
    public void tearDown() throws Exception {
        try {
            if (service != null) {
                service.shutdown();
                awaitClose(service);
            }
        } finally {
            if (manager != null) {
                manager.close();
            }
            if (context != null && name != null) {
                context.deleteDatabase(name);
            }
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    @Test
    public void encryptedServiceCrudSearchAndReopen() throws Exception {
        open(service, key);
        assertTrue(service.isVaultOpen());
        Long id = result(callback -> service.addCredential(new Credential(
                "University", "student", "test-password-123", "example.test",
                "Work", "credential-notes"), callback));
        Long noteId = result(callback -> service.addSecureNote(new SecureNote(
                "Recovery", "secret recovery phrase fixture"), callback));
        assertTrue(id > 0);
        assertTrue(noteId > 0);

        Credential fromService = result(callback -> service.getCredential(id, callback));
        assertEquals("test-password-123", fromService.getPassword());
        assertEquals("credential-notes", fromService.getNotes());
        SecureNote noteFromService = result(callback -> service.getSecureNote(noteId, callback));
        assertEquals("secret recovery phrase fixture", noteFromService.getContent());
        List<SecureNote> found = result(callback -> service.searchSecureNotes(
                "recovery phrase", callback));
        assertEquals(1, found.size());

        try (VaultItemCipher inspectionCipher = new VaultItemCipher(key)) {
            SQLiteDatabase db = manager.openForItemEncryption(key, inspectionCipher);
            assertEquals(4, db.getVersion());
            assertNotEquals("test-password-123", read(db,
                    "SELECT password_ciphertext FROM credentials WHERE id = " + id));
            assertNotEquals("credential-notes", read(db,
                    "SELECT notes_ciphertext FROM credentials WHERE id = " + id));
            assertNotEquals("secret recovery phrase fixture", read(db,
                    "SELECT content_ciphertext FROM secure_notes WHERE id = " + noteId));
            assertEquals("1", read(db,
                    "SELECT field_encryption_version FROM credentials WHERE id = " + id));
        }

        VaultItemCipher firstCipher = currentCipher(service);
        assertNotNull(firstCipher);
        close(service);
        assertFalse(service.isVaultOpen());
        assertTrue(firstCipher.isClosed());
        open(service, key);
        assertEquals("test-password-123",
                VaultItemEncryptionServiceInstrumentedTest.<Credential>result(
                        callback -> service.getCredential(id, callback)).getPassword());
    }

    @Test
    public void version3RecordsAreMigratedBeforeServiceExposesVault() throws Exception {
        SQLiteDatabase legacy = manager.open(key);
        legacy.execSQL("INSERT INTO credentials "
                        + "(id, title, username, password_ciphertext, notes_ciphertext, "
                        + "created_at, updated_at, favorite, breach_status) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                new Object[]{17L, "Original", "fixture", "legacy-secret", "legacy-note",
                        111L, 222L, 1, "BREACHED"});
        legacy.execSQL("INSERT INTO secure_notes "
                        + "(id, title, content_ciphertext, created_at, updated_at) "
                        + "VALUES (?, ?, ?, ?, ?)",
                new Object[]{9L, "Original note", "legacy-content", 333L, 444L});
        manager.close();

        open(service, key);
        Credential migrated = result(callback -> service.getCredential(17L, callback));
        assertEquals("legacy-secret", migrated.getPassword());
        assertEquals("legacy-note", migrated.getNotes());
        assertEquals(17L, migrated.getId());
        assertEquals(111L, migrated.getCreatedAt());
        assertEquals(222L, migrated.getUpdatedAt());
        assertTrue(migrated.isFavorite());
        assertEquals("BREACHED", migrated.getBreachStatus().name());
        SecureNote migratedNote = result(callback -> service.getSecureNote(9L, callback));
        assertEquals("legacy-content", migratedNote.getContent());
        assertEquals(333L, migratedNote.getCreatedAt());
        assertEquals(444L, migratedNote.getUpdatedAt());

        try (VaultItemCipher inspectionCipher = new VaultItemCipher(key)) {
            SQLiteDatabase db = manager.openForItemEncryption(key, inspectionCipher);
            assertEquals(4, db.getVersion());
            assertNotEquals("legacy-secret", read(db,
                    "SELECT password_ciphertext FROM credentials WHERE id = 17"));
            assertNotEquals("legacy-content", read(db,
                    "SELECT content_ciphertext FROM secure_notes WHERE id = 9"));
        }
    }

    @Test
    public void failedOpenDiscardsDatabaseHandleAndCipher() throws Exception {
        open(service, key);
        Long id = result(callback -> service.addCredential(new Credential(
                "A", "B", "C", "", "Work", ""), callback));
        assertTrue(id > 0);
        VaultItemCipher previouslyOpen = currentCipher(service);
        assertNotNull(previouslyOpen);
        byte[] wrongKey = key(95);
        try {
            Exception failure = openError(service, wrongKey);
            assertNotNull(failure);
            assertTrue(previouslyOpen.isClosed());
            assertFalse(service.isVaultOpen());
            assertFalse(manager.isOpen());
            assertEquals(null, currentCipher(service));
            open(service, key);
            Credential saved = result(callback -> service.getCredential(id, callback));
            assertEquals("C", saved.getPassword());
        } finally {
            Arrays.fill(wrongKey, (byte) 0);
        }
    }

    @Test
    public void distinctRealAndDecoyServicesNeverShareRecordsOrKeys() throws Exception {
        String secondName = "israa_v4_decoy_" + UUID.randomUUID() + ".db";
        byte[] decoyKey = key(77);
        DecoyVaultDataService decoy = new DecoyVaultDataService(context, secondName);
        try {
            open(service, key);
            open(decoy, decoyKey);
            Long realId = result(callback -> service.addCredential(new Credential(
                    "Real secret", "real", "real-pwd", "", "Work", ""), callback));
            Long decoyId = result(callback -> decoy.addCredential(new Credential(
                    "Decoy secret", "decoy", "decoy-pwd", "", "Work", ""), callback));
            assertTrue(realId > 0);
            assertTrue(decoyId > 0);
            List<Credential> real = result(service::getCredentials);
            List<Credential> disguised = result(decoy::getCredentials);
            assertEquals(1, real.size());
            assertEquals(1, disguised.size());
            assertEquals("real-pwd", real.get(0).getPassword());
            assertEquals("decoy-pwd", disguised.get(0).getPassword());
            assertEquals("Real secret", real.get(0).getTitle());
            assertEquals("Decoy secret", disguised.get(0).getTitle());
            close(service);
            close(decoy);
            open(decoy, decoyKey);
            assertEquals("decoy-pwd", VaultItemEncryptionServiceInstrumentedTest
                    .<Credential>result(callback -> decoy.getCredential(decoyId, callback))
                    .getPassword());
            assertEquals(1, VaultItemEncryptionServiceInstrumentedTest
                    .<List<Credential>>result(decoy::getCredentials).size());
        } finally {
            decoy.shutdown();
            awaitClose(decoy);
            context.deleteDatabase(secondName);
            Arrays.fill(decoyKey, (byte) 0);
        }
    }

    private static byte[] key(int firstByte) {
        byte[] result = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (firstByte + i);
        }
        return result;
    }

    private static VaultItemCipher currentCipher(VaultDataService source) throws Exception {
        Field f = VaultDataService.class.getDeclaredField("itemCipher");
        f.setAccessible(true);
        return (VaultItemCipher) f.get(source);
    }

    private static String read(SQLiteDatabase database, String sql) {
        Cursor cursor = database.rawQuery(sql, null);
        try {
            assertTrue(cursor.moveToFirst());
            return cursor.getString(0);
        } finally {
            cursor.close();
        }
    }

    private interface SimpleOperation {
        void run(VaultDataService.SimpleCallback callback);
    }

    private interface ResultOperation<T> {
        void run(VaultDataService.ResultCallback<T> callback);
    }

    private static void open(VaultDataService service, byte[] key) throws Exception {
        simple(callback -> service.openVault(key, callback));
    }

    private static void close(VaultDataService service) throws Exception {
        simple(service::closeVault);
    }

    private static void simple(SimpleOperation operation) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        operation.run(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { latch.countDown(); }
            @Override public void onError(Exception error) {
                failure.set(error); latch.countDown();
            }
        });
        assertTrue("Timed out waiting for callback", latch.await(20L, TimeUnit.SECONDS));
        if (failure.get() != null) { throw failure.get(); }
    }

    private static Exception openError(VaultDataService service, byte[] key)
            throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        service.openVault(key, new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { latch.countDown(); }
            @Override public void onError(Exception error) {
                failure.set(error); latch.countDown();
            }
        });
        assertTrue("Timed out waiting for failed open", latch.await(20L, TimeUnit.SECONDS));
        return failure.get();
    }

    private static <T> T result(ResultOperation<T> operation) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        AtomicReference<T> value = new AtomicReference<>();
        operation.run(new VaultDataService.ResultCallback<T>() {
            @Override public void onSuccess(T result) {
                value.set(result); latch.countDown();
            }
            @Override public void onError(Exception error) {
                failure.set(error); latch.countDown();
            }
        });
        assertTrue("Timed out waiting for result", latch.await(20L, TimeUnit.SECONDS));
        if (failure.get() != null) { throw failure.get(); }
        return value.get();
    }

    private static void awaitClose(VaultDataService service) throws Exception {
        Field workerField = VaultDataService.class.getDeclaredField("executorService");
        workerField.setAccessible(true);
        ExecutorService worker = (ExecutorService) workerField.get(service);
        assertTrue("Vault worker did not terminate", worker.awaitTermination(
                20L, TimeUnit.SECONDS));
        assertFalse("Vault remained open after shutdown", service.isVaultOpen());
    }
}

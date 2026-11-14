package com.safekey.app.data.database;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.database.Cursor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Arrays;
import java.util.UUID;

/**
 * Migration tests use disposable SQLCipher databases. This tests the v3->v4
 * conversion helper in isolation; it does not activate database version 4 in
 * the production opening path until repository integration is complete.
 */
@RunWith(AndroidJUnit4.class)
public class VaultItemEncryptionMigrationInstrumentedTest {

    private Context context;
    private String databaseName;
    private byte[] key;
    private SafeKeyDatabase manager;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        databaseName = "item_encryption_migration_" + UUID.randomUUID() + ".db";
        key = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 31);
        }
        manager = new SafeKeyDatabase(context, databaseName);
        SQLiteDatabase original = manager.open(key);
        assertEquals(3, original.getVersion());
        original.execSQL("INSERT INTO credentials (id, title, username, password_ciphertext, "
                        + "website, category, notes_ciphertext, favorite, created_at, updated_at, "
                        + "breach_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                new Object[]{17L, "Test credential", "user", "legacy-password",
                        "https://example.test", "Personal", "legacy-notes", 1,
                        123L, 456L, "BREACHED"});
        original.execSQL("INSERT INTO secure_notes "
                        + "(id, title, content_ciphertext, created_at, updated_at) "
                        + "VALUES (?, ?, ?, ?, ?)",
                new Object[]{9L, "Test note", "legacy-secret", 789L, 987L});
        manager.close();
    }

    @After
    public void tearDown() {
        try {
            if (manager != null) {
                manager.close();
            }
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
            if (context != null && databaseName != null) {
                context.deleteDatabase(databaseName);
            }
        }
    }

    @Test
    public void version3DataConvertsWithoutLosingMetadata() throws AesGcmException {
        SQLiteDatabase database = openRaw();
        try (VaultItemCipher cipher = new VaultItemCipher(key)) {
            database.beginTransaction();
            try {
                VaultItemEncryptionMigration.migrateVersion3(database, cipher);
                database.setVersion(4);
                database.setTransactionSuccessful();
            } finally {
                database.endTransaction();
            }

            assertEquals(4, database.getVersion());
            Cursor credential = database.rawQuery(
                    "SELECT id, title, username, password_ciphertext, website, category, "
                            + "notes_ciphertext, favorite, created_at, updated_at, "
                            + "breach_status, record_uuid, field_encryption_version "
                            + "FROM credentials WHERE id = 17", null);
            try {
                assertTrue(credential.moveToFirst());
                assertEquals(17L, credential.getLong(0));
                assertEquals("Test credential", credential.getString(1));
                assertEquals("user", credential.getString(2));
                assertNotEquals("legacy-password", credential.getString(3));
                assertEquals("https://example.test", credential.getString(4));
                assertEquals("Personal", credential.getString(5));
                assertNotEquals("legacy-notes", credential.getString(6));
                assertEquals(1, credential.getInt(7));
                assertEquals(123L, credential.getLong(8));
                assertEquals(456L, credential.getLong(9));
                assertEquals("BREACHED", credential.getString(10));
                String uuid = credential.getString(11);
                assertEquals(UUID.fromString(uuid).toString(), uuid);
                assertEquals(1, credential.getInt(12));
                assertEquals("legacy-password", cipher.decrypt(
                        VaultItemCipher.Field.CREDENTIAL_PASSWORD, uuid,
                        credential.getString(3)));
                assertEquals("legacy-notes", cipher.decrypt(
                        VaultItemCipher.Field.CREDENTIAL_NOTES, uuid,
                        credential.getString(6)));
                assertThrows(AesGcmException.class, () -> cipher.decrypt(
                        VaultItemCipher.Field.SECURE_NOTE_CONTENT, uuid,
                        credential.getString(3)));
            } finally {
                credential.close();
            }

            Cursor note = database.rawQuery(
                    "SELECT id, title, content_ciphertext, created_at, updated_at, "
                            + "record_uuid, field_encryption_version "
                            + "FROM secure_notes WHERE id = 9", null);
            try {
                assertTrue(note.moveToFirst());
                assertEquals(9L, note.getLong(0));
                assertEquals("Test note", note.getString(1));
                assertNotEquals("legacy-secret", note.getString(2));
                assertEquals(789L, note.getLong(3));
                assertEquals(987L, note.getLong(4));
                assertEquals(1, note.getInt(6));
                assertEquals("legacy-secret", cipher.decrypt(
                        VaultItemCipher.Field.SECURE_NOTE_CONTENT,
                        note.getString(5), note.getString(2)));
            } finally {
                note.close();
            }
        } finally {
            database.close();
        }
    }

    @Test
    public void failedMigrationRollsBackAndCanBeRetried() throws AesGcmException {
        SQLiteDatabase database = openRaw();
        try (VaultItemCipher cipher = new VaultItemCipher(key)) {
            // The trigger makes note encryption fail after credentials were updated.
            database.execSQL("CREATE TRIGGER fail_note_migration "
                    + "BEFORE UPDATE OF content_ciphertext ON secure_notes "
                    + "BEGIN SELECT RAISE(ABORT, 'injected failure'); END");
            database.beginTransaction();
            try {
                assertThrows(RuntimeException.class, () ->
                        VaultItemEncryptionMigration.migrateVersion3(database, cipher));
            } finally {
                database.endTransaction(); // no success -> rollback DDL and writes
            }
            assertEquals(3, database.getVersion());
            assertEquals("legacy-password", readOne(database,
                    "SELECT password_ciphertext FROM credentials WHERE id = 17"));
            assertEquals("legacy-secret", readOne(database,
                    "SELECT content_ciphertext FROM secure_notes WHERE id = 9"));
            assertFalse(hasColumn(database, "credentials", "record_uuid"));
            assertFalse(hasColumn(database, "secure_notes", "field_encryption_version"));

            database.execSQL("DROP TRIGGER fail_note_migration");
            database.beginTransaction();
            try {
                VaultItemEncryptionMigration.migrateVersion3(database, cipher);
                database.setVersion(4);
                database.setTransactionSuccessful();
            } finally {
                database.endTransaction();
            }
            assertEquals(4, database.getVersion());
            assertNotEquals("legacy-password", readOne(database,
                    "SELECT password_ciphertext FROM credentials WHERE id = 17"));
        } finally {
            database.close();
        }
    }

    @Test
    public void migrationRequiresTransactionAndRejectsRepeatedConversion() throws AesGcmException {
        SQLiteDatabase database = openRaw();
        try (VaultItemCipher cipher = new VaultItemCipher(key)) {
            assertThrows(IllegalStateException.class, () ->
                    VaultItemEncryptionMigration.migrateVersion3(database, cipher));
            assertEquals(3, database.getVersion());
            database.beginTransaction();
            try {
                VaultItemEncryptionMigration.migrateVersion3(database, cipher);
                // A second invocation must not misidentify encrypted values as legacy.
                assertThrows(RuntimeException.class, () ->
                        VaultItemEncryptionMigration.migrateVersion3(database, cipher));
            } finally {
                database.endTransaction(); // intentionally rollback
            }
            assertEquals("legacy-password", readOne(database,
                    "SELECT password_ciphertext FROM credentials WHERE id = 17"));
        } finally {
            database.close();
        }
    }

    private SQLiteDatabase openRaw() {
        File file = context.getDatabasePath(databaseName);
        byte[] encoded = SqlCipherKeyEncoder.encode(key);
        try {
            return SQLiteDatabase.openOrCreateDatabase(file, encoded,
                    null, null, null);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static String readOne(SQLiteDatabase database, String query) {
        Cursor cursor = database.rawQuery(query, null);
        try {
            if (!cursor.moveToFirst()) {
                fail("Test fixture row not found");
            }
            return cursor.getString(0);
        } finally {
            cursor.close();
        }
    }

    private static boolean hasColumn(SQLiteDatabase database, String table, String name) {
        Cursor cursor = database.rawQuery("PRAGMA table_info(" + table + ")", null);
        try {
            while (cursor.moveToNext()) {
                if (name.equals(cursor.getString(cursor.getColumnIndexOrThrow("name")))) {
                    return true;
                }
            }
            return false;
        } finally {
            cursor.close();
        }
    }
}

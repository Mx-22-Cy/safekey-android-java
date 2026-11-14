package com.safekey.app.data.database;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

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

import java.util.Arrays;
import java.util.UUID;

/** The v4 opening seam is tested only with disposable SQLCipher vaults. */
@RunWith(AndroidJUnit4.class)
public class SafeKeyDatabaseV4OpenInstrumentedTest {

    private Context context;
    private String databaseName;
    private byte[] databaseKey;
    private SafeKeyDatabase manager;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        databaseName = "item_open_v4_" + UUID.randomUUID() + ".db";
        databaseKey = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
        for (int i = 0; i < databaseKey.length; i++) {
            databaseKey[i] = (byte) (45 + i);
        }
        manager = new SafeKeyDatabase(context, databaseName);
        SQLiteDatabase database = manager.open(databaseKey);
        assertEquals(3, database.getVersion());
        database.execSQL("INSERT INTO credentials (id, title, username, "
                        + "password_ciphertext, notes_ciphertext, favorite, "
                        + "created_at, updated_at, breach_status) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                new Object[]{17L, "v3 fixture", "user", "legacy password",
                        "legacy notes", 1, 111L, 222L, "BREACHED"});
        database.execSQL("INSERT INTO secure_notes "
                        + "(id, title, content_ciphertext, created_at, updated_at) "
                        + "VALUES (?, ?, ?, ?, ?)",
                new Object[]{9L, "note fixture", "legacy content", 333L, 444L});
        manager.close();
    }

    @After
    public void tearDown() {
        try {
            if (manager != null) {
                manager.close();
            }
        } finally {
            if (databaseKey != null) {
                Arrays.fill(databaseKey, (byte) 0);
            }
            if (context != null && databaseName != null) {
                context.deleteDatabase(databaseName);
            }
        }
    }

    @Test
    public void openingWithCipherUpgradesAndCanReopen() throws AesGcmException {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey)) {
            SQLiteDatabase database = manager.openForItemEncryption(databaseKey, cipher);
            assertEquals(4, database.getVersion());

            String uuid = readString(database,
                    "SELECT record_uuid FROM credentials WHERE id = 17");
            assertEquals(UUID.fromString(uuid).toString(), uuid);
            String encryptedPassword = readString(database,
                    "SELECT password_ciphertext FROM credentials WHERE id = 17");
            assertNotEquals("legacy password", encryptedPassword);
            assertEquals("legacy password", cipher.decrypt(
                    VaultItemCipher.Field.CREDENTIAL_PASSWORD, uuid, encryptedPassword));
            assertEquals("BREACHED", readString(database,
                    "SELECT breach_status FROM credentials WHERE id = 17"));
            assertEquals(1L, readLong(database,
                    "SELECT favorite FROM credentials WHERE id = 17"));
            assertEquals(222L, readLong(database,
                    "SELECT updated_at FROM credentials WHERE id = 17"));

            String noteUuid = readString(database,
                    "SELECT record_uuid FROM secure_notes WHERE id = 9");
            assertEquals("legacy content", cipher.decrypt(
                    VaultItemCipher.Field.SECURE_NOTE_CONTENT,
                    noteUuid, readString(database,
                            "SELECT content_ciphertext FROM secure_notes WHERE id = 9")));

            manager.close();
            SQLiteDatabase reopened = manager.openForItemEncryption(databaseKey, cipher);
            assertEquals(4, reopened.getVersion());
            assertEquals(uuid, readString(reopened,
                    "SELECT record_uuid FROM credentials WHERE id = 17"));
        }
    }

    @Test
    public void failedUpgradeLeavesVersion3AndAllowsRetry() throws AesGcmException {
        SQLiteDatabase database = manager.open(databaseKey);
        database.execSQL("CREATE TRIGGER block_v4 "
                + "BEFORE UPDATE OF content_ciphertext ON secure_notes "
                + "BEGIN SELECT RAISE(ABORT, 'injected failure'); END");
        manager.close();

        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey)) {
            assertThrows(RuntimeException.class,
                    () -> manager.openForItemEncryption(databaseKey, cipher));
            assertFalse(manager.isOpen());

            SQLiteDatabase unchanged = manager.open(databaseKey);
            assertEquals(3, unchanged.getVersion());
            assertEquals("legacy password", readString(unchanged,
                    "SELECT password_ciphertext FROM credentials WHERE id = 17"));
            assertEquals("legacy content", readString(unchanged,
                    "SELECT content_ciphertext FROM secure_notes WHERE id = 9"));
            manager.close();

            SQLiteDatabase old = manager.open(databaseKey);
            old.execSQL("DROP TRIGGER block_v4");
            manager.close();

            SQLiteDatabase upgraded = manager.openForItemEncryption(databaseKey, cipher);
            assertEquals(4, upgraded.getVersion());
            assertNotEquals("legacy password", readString(upgraded,
                    "SELECT password_ciphertext FROM credentials WHERE id = 17"));
        }
    }

    @Test
    public void legacyOpenCannotExposeAnEncryptedDatabase() {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey)) {
            assertEquals(4, manager.openForItemEncryption(databaseKey, cipher).getVersion());
            assertThrows(IllegalStateException.class, () -> manager.open(databaseKey));
            assertFalse(manager.isOpen());
        }
    }

    @Test
    public void closedCipherCannotStartUpgrade() {
        VaultItemCipher cipher = new VaultItemCipher(databaseKey);
        cipher.close();
        assertThrows(IllegalStateException.class,
                () -> manager.openForItemEncryption(databaseKey, cipher));
        assertFalse(manager.isOpen());
    }

    private static String readString(SQLiteDatabase database, String sql) {
        Cursor cursor = database.rawQuery(sql, null);
        try {
            assertTrue(cursor.moveToFirst());
            return cursor.getString(0);
        } finally {
            cursor.close();
        }
    }

    private static long readLong(SQLiteDatabase database, String sql) {
        Cursor cursor = database.rawQuery(sql, null);
        try {
            assertTrue(cursor.moveToFirst());
            return cursor.getLong(0);
        } finally {
            cursor.close();
        }
    }
}

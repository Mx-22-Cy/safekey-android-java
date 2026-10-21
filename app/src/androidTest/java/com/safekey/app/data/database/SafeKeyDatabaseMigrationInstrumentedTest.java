package com.safekey.app.data.database;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.database.Cursor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Arrays;
import java.util.UUID;

@RunWith(AndroidJUnit4.class)
public class SafeKeyDatabaseMigrationInstrumentedTest {

    // Frozen version 1 schema: fixtures must not use the current schema creator.
    private static final String VERSION_1_CREDENTIALS =
            "CREATE TABLE credentials ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "title TEXT NOT NULL, "
                    + "username TEXT NOT NULL, "
                    + "password_ciphertext TEXT NOT NULL, "
                    + "website TEXT NOT NULL DEFAULT '', "
                    + "category TEXT NOT NULL DEFAULT 'Work', "
                    + "notes_ciphertext TEXT NOT NULL DEFAULT '', "
                    + "favorite INTEGER NOT NULL DEFAULT 0, "
                    + "created_at INTEGER NOT NULL, "
                    + "updated_at INTEGER NOT NULL)";

    private static final String VERSION_1_NOTES =
            "CREATE TABLE secure_notes ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "title TEXT NOT NULL, "
                    + "content_ciphertext TEXT NOT NULL, "
                    + "created_at INTEGER NOT NULL, "
                    + "updated_at INTEGER NOT NULL)";

    private Context context;
    private String databaseName;
    private byte[] databaseKey;
    private SafeKeyDatabase manager;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        databaseName = "safekey_breach_migration_" + UUID.randomUUID() + ".db";
        databaseKey = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];

        for (int index = 0; index < databaseKey.length; index++) {
            databaseKey[index] = (byte) (53 + index);
        }

        // Also loads SQLCipher's native library before creating old fixtures.
        manager = new SafeKeyDatabase(context, databaseName);
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
    public void freshDatabase_hasVersion2AndNotCheckedDefault() {
        SQLiteDatabase database = manager.open(databaseKey);
        assertEquals(2, database.getVersion());
        assertBreachColumn(database);
        insertFixtureRows(database);
        assertEquals("NOT_CHECKED", readStatus(database));
        assertFixtureRowsPreserved(database);
    }

    @Test
    public void version1Upgrade_preservesAllCredentialAndNoteFields() {
        createLegacyDatabase(1, false);
        SQLiteDatabase database = manager.open(databaseKey);
        assertEquals(2, database.getVersion());
        assertBreachColumn(database);
        assertFixtureRowsPreserved(database);
        assertEquals("NOT_CHECKED", readStatus(database));
    }

    @Test
    public void version0ExistingTables_areUpgradedWithoutDataLoss() {
        createLegacyDatabase(0, false);
        SQLiteDatabase database = manager.open(databaseKey);
        assertEquals(2, database.getVersion());
        assertFixtureRowsPreserved(database);
        assertEquals("NOT_CHECKED", readStatus(database));
    }

    @Test
    public void version2Reopen_preservesSavedBreachStatus() {
        createLegacyDatabase(1, false);
        SQLiteDatabase database = manager.open(databaseKey);
        database.execSQL(
                "UPDATE credentials SET breach_status = ? WHERE id = ?",
                new Object[]{"BREACHED", 17L}
        );
        manager.close();

        SQLiteDatabase reopened = manager.open(databaseKey);
        assertEquals(2, reopened.getVersion());
        assertEquals("BREACHED", readStatus(reopened));
        assertFixtureRowsPreserved(reopened);
    }

    @Test
    public void breachStatus_acceptsAllFourResultNames() {
        SQLiteDatabase database = manager.open(databaseKey);
        insertFixtureRows(database);

        for (String status : new String[]{
                "NOT_CHECKED", "NOT_FOUND", "BREACHED", "ERROR"
        }) {
            database.execSQL(
                    "UPDATE credentials SET breach_status = ? WHERE id = ?",
                    new Object[]{status, 17L}
            );
            assertEquals(status, readStatus(database));
        }
    }

    @Test
    public void breachStatus_rejectsNullAndUnknownValues() {
        SQLiteDatabase database = manager.open(databaseKey);
        insertFixtureRows(database);

        for (String invalid : new String[]{null, "SAFE", ""}) {
            try {
                database.execSQL(
                        "UPDATE credentials SET breach_status = ? WHERE id = ?",
                        new Object[]{invalid, 17L}
                );
                fail("Invalid breach status was accepted.");
            } catch (RuntimeException expected) {
                assertEquals("NOT_CHECKED", readStatus(database));
            }
        }
    }

    @Test
    public void failedUpgrade_keepsOldVersionAndExistingData() {
        // An inconsistent fixture forces ADD COLUMN to fail with a duplicate.
        createLegacyDatabase(1, true);

        try {
            manager.open(databaseKey);
            fail("Expected the inconsistent version 1 schema to be rejected.");
        } catch (RuntimeException expected) {
            assertFalse(manager.isOpen());
        }

        SQLiteDatabase unchanged = openRawDatabase();
        try {
            assertEquals(1, unchanged.getVersion());
            assertFixtureRowsPreserved(unchanged);
            assertEquals("BREACHED", readStatus(unchanged));
        } finally {
            unchanged.close();
        }
    }

    private void createLegacyDatabase(int version, boolean duplicateColumn) {
        SQLiteDatabase database = openRawDatabase();
        try {
            database.beginTransaction();
            try {
                database.execSQL(VERSION_1_CREDENTIALS);
                database.execSQL(VERSION_1_NOTES);
                insertFixtureRows(database);

                if (duplicateColumn) {
                    database.execSQL(
                            "ALTER TABLE credentials ADD COLUMN "
                                    + "breach_status TEXT NOT NULL DEFAULT 'BREACHED'"
                    );
                }

                database.setVersion(version);
                database.setTransactionSuccessful();
            } finally {
                database.endTransaction();
            }
        } finally {
            database.close();
        }
    }

    private SQLiteDatabase openRawDatabase() {
        File databaseFile = context.getDatabasePath(databaseName);
        File parent = databaseFile.getParentFile();

        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("Cannot create test database directory.");
        }

        byte[] encodedKey = SqlCipherKeyEncoder.encode(databaseKey);
        try {
            return SQLiteDatabase.openOrCreateDatabase(
                    databaseFile, encodedKey, null, null, null
            );
        } finally {
            Arrays.fill(encodedKey, (byte) 0);
        }
    }

    private static void insertFixtureRows(SQLiteDatabase database) {
        database.execSQL(
                "INSERT INTO credentials ("
                        + "id, title, username, password_ciphertext, website, "
                        + "category, notes_ciphertext, favorite, created_at, updated_at"
                        + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                new Object[]{
                        17L, "Migration credential", "fixture-user",
                        "fixture-password", "https://fixture.example", "Personal",
                        "fixture-credential-notes", 1, 123L, 456L
                }
        );
        database.execSQL(
                "INSERT INTO secure_notes ("
                        + "id, title, content_ciphertext, created_at, updated_at"
                        + ") VALUES (?, ?, ?, ?, ?)",
                new Object[]{9L, "Migration note", "fixture-note-content", 789L, 987L}
        );
    }

    private static void assertBreachColumn(SQLiteDatabase database) {
        Cursor cursor = database.rawQuery("PRAGMA table_info(credentials)", null);
        try {
            while (cursor.moveToNext()) {
                if ("breach_status".equals(
                        cursor.getString(cursor.getColumnIndexOrThrow("name"))
                )) {
                    assertEquals("TEXT", cursor.getString(cursor.getColumnIndexOrThrow("type")));
                    assertEquals(1, cursor.getInt(cursor.getColumnIndexOrThrow("notnull")));
                    assertEquals("'NOT_CHECKED'", cursor.getString(cursor.getColumnIndexOrThrow("dflt_value")));
                    return;
                }
            }
            fail("Missing breach_status column.");
        } finally {
            cursor.close();
        }
    }

    private static String readStatus(SQLiteDatabase database) {
        Cursor cursor = database.rawQuery(
                "SELECT breach_status FROM credentials WHERE id = ?",
                new String[]{"17"}
        );
        try {
            assertTrue(cursor.moveToFirst());
            return cursor.getString(0);
        } finally {
            cursor.close();
        }
    }

    private static void assertFixtureRowsPreserved(SQLiteDatabase database) {
        Cursor credentials = database.rawQuery("SELECT * FROM credentials", null);
        try {
            assertTrue(credentials.moveToFirst());
            assertEquals(17L, credentials.getLong(credentials.getColumnIndexOrThrow("id")));
            assertEquals("Migration credential", credentials.getString(credentials.getColumnIndexOrThrow("title")));
            assertEquals("fixture-user", credentials.getString(credentials.getColumnIndexOrThrow("username")));
            assertEquals("fixture-password", credentials.getString(credentials.getColumnIndexOrThrow("password_ciphertext")));
            assertEquals("https://fixture.example", credentials.getString(credentials.getColumnIndexOrThrow("website")));
            assertEquals("Personal", credentials.getString(credentials.getColumnIndexOrThrow("category")));
            assertEquals("fixture-credential-notes", credentials.getString(credentials.getColumnIndexOrThrow("notes_ciphertext")));
            assertEquals(1, credentials.getInt(credentials.getColumnIndexOrThrow("favorite")));
            assertEquals(123L, credentials.getLong(credentials.getColumnIndexOrThrow("created_at")));
            assertEquals(456L, credentials.getLong(credentials.getColumnIndexOrThrow("updated_at")));
            assertFalse(credentials.moveToNext());
        } finally {
            credentials.close();
        }

        Cursor notes = database.rawQuery("SELECT * FROM secure_notes", null);
        try {
            assertTrue(notes.moveToFirst());
            assertEquals(9L, notes.getLong(notes.getColumnIndexOrThrow("id")));
            assertEquals("Migration note", notes.getString(notes.getColumnIndexOrThrow("title")));
            assertEquals("fixture-note-content", notes.getString(notes.getColumnIndexOrThrow("content_ciphertext")));
            assertEquals(789L, notes.getLong(notes.getColumnIndexOrThrow("created_at")));
            assertEquals(987L, notes.getLong(notes.getColumnIndexOrThrow("updated_at")));
            assertFalse(notes.moveToNext());
        } finally {
            notes.close();
        }
    }
}

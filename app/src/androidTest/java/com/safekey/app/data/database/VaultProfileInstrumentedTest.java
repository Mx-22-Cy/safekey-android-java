package com.safekey.app.data.database;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.database.Cursor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.repository.VaultProfileRepository;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Arrays;
import java.util.UUID;

@RunWith(AndroidJUnit4.class)
public class VaultProfileInstrumentedTest {

    private Context context;
    private String realDatabaseName;
    private String decoyDatabaseName;
    private byte[] realKey;
    private byte[] decoyKey;
    private SafeKeyDatabase realManager;
    private SafeKeyDatabase decoyManager;

    @Before
    public void setUp() {
        context = InstrumentationRegistry
                .getInstrumentation()
                .getTargetContext();

        String testId = UUID.randomUUID().toString();

        realDatabaseName = "profile_real_" + testId + ".db";
        decoyDatabaseName = "profile_decoy_" + testId + ".db";

        realKey = createKey(31);
        decoyKey = createKey(73);

        realManager = new SafeKeyDatabase(
                context, realDatabaseName
        );

        decoyManager = new SafeKeyDatabase(
                context, decoyDatabaseName
        );
    }

    @After
    public void tearDown() {
        try {
            if (realManager != null) {
                realManager.close();
            }

            if (decoyManager != null) {
                decoyManager.close();
            }
        } finally {
            if (realKey != null) {
                Arrays.fill(realKey, (byte) 0);
            }

            if (decoyKey != null) {
                Arrays.fill(decoyKey, (byte) 0);
            }

            if (context != null) {
                if (realDatabaseName != null) {
                    context.deleteDatabase(realDatabaseName);
                }

                if (decoyDatabaseName != null) {
                    context.deleteDatabase(decoyDatabaseName);
                }
            }
        }
    }

    @Test
    public void freshDatabase_hasDefaultDisplayName() {
        SQLiteDatabase database = realManager.open(realKey);

        assertEquals(3, database.getVersion());

        VaultProfileRepository repository =
                new VaultProfileRepository(database);

        assertEquals(
                "Local Vault",
                repository.getDisplayName()
        );
    }

    @Test
    public void updateDisplayName_savesTrimmedName() {
        SQLiteDatabase database = realManager.open(realKey);

        VaultProfileRepository repository =
                new VaultProfileRepository(database);

        assertEquals(
                1,
                repository.updateDisplayName("  My Personal Vault  ")
        );

        assertEquals(
                "My Personal Vault",
                repository.getDisplayName()
        );
    }

    @Test
    public void closeAndReopen_preservesDisplayName() {
        SQLiteDatabase database = realManager.open(realKey);

        VaultProfileRepository repository =
                new VaultProfileRepository(database);

        repository.updateDisplayName("University Vault");

        realManager.close();

        SQLiteDatabase reopened = realManager.open(realKey);

        VaultProfileRepository reopenedRepository =
                new VaultProfileRepository(reopened);

        assertEquals(
                "University Vault",
                reopenedRepository.getDisplayName()
        );
    }

    @Test
    public void realAndDecoyVaults_keepIndependentNames() {
        SQLiteDatabase realDatabase =
                realManager.open(realKey);

        SQLiteDatabase decoyDatabase =
                decoyManager.open(decoyKey);

        VaultProfileRepository realRepository =
                new VaultProfileRepository(realDatabase);

        VaultProfileRepository decoyRepository =
                new VaultProfileRepository(decoyDatabase);

        realRepository.updateDisplayName("Private Vault");
        decoyRepository.updateDisplayName("Study Vault");

        assertEquals(
                "Private Vault",
                realRepository.getDisplayName()
        );

        assertEquals(
                "Study Vault",
                decoyRepository.getDisplayName()
        );

        realManager.close();
        decoyManager.close();

        VaultProfileRepository reopenedReal =
                new VaultProfileRepository(
                        realManager.open(realKey)
                );

        VaultProfileRepository reopenedDecoy =
                new VaultProfileRepository(
                        decoyManager.open(decoyKey)
                );

        assertEquals(
                "Private Vault",
                reopenedReal.getDisplayName()
        );

        assertEquals(
                "Study Vault",
                reopenedDecoy.getDisplayName()
        );
    }

    @Test
    public void invalidDisplayNames_areRejected() {
        SQLiteDatabase database = realManager.open(realKey);

        VaultProfileRepository repository =
                new VaultProfileRepository(database);

        assertInvalidName(repository, null);
        assertInvalidName(repository, "");
        assertInvalidName(repository, "    ");

        char[] characters = new char[65];
        Arrays.fill(characters, 'A');

        assertInvalidName(
                repository,
                new String(characters)
        );

        assertEquals(
                "Local Vault",
                repository.getDisplayName()
        );
    }

    @Test
    public void version2Migration_preservesCredentialsAndNotes() {
        createVersion2Database();

        SQLiteDatabase upgraded = realManager.open(realKey);

        assertEquals(3, upgraded.getVersion());

        VaultProfileRepository repository =
                new VaultProfileRepository(upgraded);

        assertEquals(
                "Local Vault",
                repository.getDisplayName()
        );

        assertEquals(
                "Existing credential",
                readSingleValue(
                        upgraded,
                        "SELECT title FROM credentials WHERE id = 17"
                )
        );

        assertEquals(
                "Existing note",
                readSingleValue(
                        upgraded,
                        "SELECT title FROM secure_notes WHERE id = 9"
                )
        );

        assertEquals(
                "NOT_CHECKED",
                readSingleValue(
                        upgraded,
                        "SELECT breach_status FROM credentials WHERE id = 17"
                )
        );
    }

    private void createVersion2Database() {
        File databaseFile =
                context.getDatabasePath(realDatabaseName);

        File directory = databaseFile.getParentFile();

        if (directory != null
                && !directory.isDirectory()
                && !directory.mkdirs()) {
            throw new IllegalStateException(
                    "Cannot create test database directory."
            );
        }

        byte[] encodedKey =
                SqlCipherKeyEncoder.encode(realKey);

        SQLiteDatabase database;

        try {
            database = SQLiteDatabase.openOrCreateDatabase(
                    databaseFile,
                    encodedKey,
                    null,
                    null,
                    null
            );
        } finally {
            Arrays.fill(encodedKey, (byte) 0);
        }

        try {
            database.beginTransaction();

            try {
                database.execSQL(
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
                                + "updated_at INTEGER NOT NULL, "
                                + "breach_status TEXT NOT NULL "
                                + "DEFAULT 'NOT_CHECKED')"
                );

                database.execSQL(
                        "CREATE TABLE secure_notes ("
                                + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                + "title TEXT NOT NULL, "
                                + "content_ciphertext TEXT NOT NULL, "
                                + "created_at INTEGER NOT NULL, "
                                + "updated_at INTEGER NOT NULL)"
                );

                database.execSQL(
                        "INSERT INTO credentials "
                                + "(id, title, username, "
                                + "password_ciphertext, "
                                + "created_at, updated_at) "
                                + "VALUES (?, ?, ?, ?, ?, ?)",
                        new Object[]{
                                17L,
                                "Existing credential",
                                "test-user",
                                "encrypted-password-fixture",
                                1L,
                                1L
                        }
                );

                database.execSQL(
                        "INSERT INTO secure_notes "
                                + "(id, title, content_ciphertext, "
                                + "created_at, updated_at) "
                                + "VALUES (?, ?, ?, ?, ?)",
                        new Object[]{
                                9L,
                                "Existing note",
                                "encrypted-note-fixture",
                                1L,
                                1L
                        }
                );

                database.setVersion(2);
                database.setTransactionSuccessful();

            } finally {
                database.endTransaction();
            }
        } finally {
            database.close();
        }
    }

    private static void assertInvalidName(
            VaultProfileRepository repository,
            String invalidName
    ) {
        try {
            repository.updateDisplayName(invalidName);
            fail("Invalid display name was accepted.");
        } catch (IllegalArgumentException expected) {
            // Expected validation failure.
        }
    }

    private static String readSingleValue(
            SQLiteDatabase database,
            String query
    ) {
        try (Cursor cursor = database.rawQuery(query, null)) {
            assertTrue(cursor.moveToFirst());
            String value = cursor.getString(0);
            assertTrue("Expected exactly one row.", !cursor.moveToNext());
            return value;
        }
    }

    private static byte[] createKey(int startingValue) {
        byte[] key = new byte[
                SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES
                ];

        for (int index = 0; index < key.length; index++) {
            key[index] = (byte) (startingValue + index);
        }

        return key;
    }
}

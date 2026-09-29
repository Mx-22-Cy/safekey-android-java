package com.safekey.app.data.database;

import static org.junit.Assert.assertArrayEquals;
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

import java.util.Arrays;

@RunWith(AndroidJUnit4.class)
public class SafeKeyDatabaseRawKeyInstrumentedTest {

    private static final String DATABASE_NAME =
            "safekey_raw_key_test.db";

    private Context context;

    @Before
    public void setUp() {
        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        context.deleteDatabase(
                DATABASE_NAME
        );
    }

    @After
    public void tearDown() {
        if (context != null) {
            context.deleteDatabase(
                    DATABASE_NAME
            );
        }
    }

    @Test
    public void rawKey_canCreateCloseAndReopenDatabase() {
        byte[] databaseKey =
                createDatabaseKey(
                        17
                );

        SafeKeyDatabase firstManager =
                new SafeKeyDatabase(
                        context,
                        DATABASE_NAME
                );

        SafeKeyDatabase secondManager =
                new SafeKeyDatabase(
                        context,
                        DATABASE_NAME
                );

        try {
            SQLiteDatabase createdDatabase =
                    firstManager.open(
                            databaseKey
                    );

            createdDatabase.execSQL(
                    "INSERT INTO secure_notes ("
                            + "title, content_ciphertext, "
                            + "created_at, updated_at"
                            + ") VALUES (?, ?, ?, ?)",
                    new Object[]{
                            "Raw-key test note",
                            "encrypted-test-content",
                            1L,
                            1L
                    }
            );

            firstManager.close();

            SQLiteDatabase reopenedDatabase =
                    secondManager.open(
                            databaseKey
                    );

            Cursor cursor =
                    reopenedDatabase.rawQuery(
                            "SELECT content_ciphertext "
                                    + "FROM secure_notes "
                                    + "WHERE title = ?",
                            new String[]{
                                    "Raw-key test note"
                            }
                    );

            try {
                assertTrue(
                        cursor.moveToFirst()
                );

                assertEquals(
                        "encrypted-test-content",
                        cursor.getString(
                                0
                        )
                );

            } finally {
                cursor.close();
            }

        } finally {
            firstManager.close();
            secondManager.close();

            Arrays.fill(
                    databaseKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void wrongRawKey_cannotOpenExistingDatabase() {
        byte[] correctDatabaseKey =
                createDatabaseKey(
                        29
                );

        byte[] wrongDatabaseKey =
                createDatabaseKey(
                        93
                );

        SafeKeyDatabase creatorManager =
                new SafeKeyDatabase(
                        context,
                        DATABASE_NAME
                );

        SafeKeyDatabase wrongKeyManager =
                new SafeKeyDatabase(
                        context,
                        DATABASE_NAME
                );

        try {
            creatorManager.open(
                    correctDatabaseKey
            );

            creatorManager.close();

            try {
                wrongKeyManager.open(
                        wrongDatabaseKey
                );

                fail(
                        "Expected the wrong raw database key to be rejected."
                );

            } catch (RuntimeException expected) {
                assertFalse(
                        wrongKeyManager.isOpen()
                );
            }

        } finally {
            creatorManager.close();
            wrongKeyManager.close();

            Arrays.fill(
                    correctDatabaseKey,
                    (byte) 0
            );

            Arrays.fill(
                    wrongDatabaseKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void open_doesNotModifyCallerDatabaseKey() {
        byte[] databaseKey =
                createDatabaseKey(
                        41
                );

        byte[] originalDatabaseKey =
                Arrays.copyOf(
                        databaseKey,
                        databaseKey.length
                );

        SafeKeyDatabase databaseManager =
                new SafeKeyDatabase(
                        context,
                        DATABASE_NAME
                );

        try {
            databaseManager.open(
                    databaseKey
            );

            assertArrayEquals(
                    originalDatabaseKey,
                    databaseKey
            );

        } finally {
            databaseManager.close();

            Arrays.fill(
                    databaseKey,
                    (byte) 0
            );

            Arrays.fill(
                    originalDatabaseKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void callerCanClearKeyAfterOpen_databaseRemainsUsable() {
        byte[] databaseKey =
                createDatabaseKey(
                        57
                );

        SafeKeyDatabase databaseManager =
                new SafeKeyDatabase(
                        context,
                        DATABASE_NAME
                );

        try {
            SQLiteDatabase database =
                    databaseManager.open(
                            databaseKey
                    );

            Arrays.fill(
                    databaseKey,
                    (byte) 0
            );

            assertTrue(
                    databaseManager.isOpen()
            );

            assertEquals(
                    1,
                    database.getVersion()
            );

            Cursor cursor =
                    database.rawQuery(
                            "SELECT 1",
                            null
                    );

            try {
                assertTrue(
                        cursor.moveToFirst()
                );

                assertEquals(
                        1,
                        cursor.getInt(
                                0
                        )
                );

            } finally {
                cursor.close();
            }

        } finally {
            databaseManager.close();

            Arrays.fill(
                    databaseKey,
                    (byte) 0
            );
        }
    }

    private byte[] createDatabaseKey(
            int startingValue
    ) {
        byte[] databaseKey =
                new byte[
                        SqlCipherKeyEncoder
                                .DATABASE_KEY_LENGTH_BYTES
                        ];

        for (
                int index = 0;
                index < databaseKey.length;
                index++
        ) {
            databaseKey[index] =
                    (byte) (
                            startingValue
                                    + index
                    );
        }

        return databaseKey;
    }
}

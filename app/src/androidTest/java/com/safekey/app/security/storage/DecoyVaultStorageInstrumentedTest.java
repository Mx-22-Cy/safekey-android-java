package com.safekey.app.security.storage;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.database.Cursor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.database.SafeKeyDatabase;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Arrays;

@RunWith(AndroidJUnit4.class)
public class DecoyVaultStorageInstrumentedTest {

    private static final String PRIMARY_DATABASE_NAME =
            "safekey.db";

    private Context context;

    @Before
    public void setUp() {
        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        context.deleteDatabase(
                DecoyVaultStorage.DATABASE_NAME
        );
    }

    @After
    public void tearDown() {
        if (context != null) {
            context.deleteDatabase(
                    DecoyVaultStorage.DATABASE_NAME
            );
        }

        context = null;
    }

    @Test
    public void ensureDatabaseFile_createsSecondaryDatabase() {
        assertFalse(
                DecoyVaultStorage.databaseFileExists(
                        context
                )
        );

        DecoyVaultStorage.ensureDatabaseFile(
                context
        );

        assertTrue(
                DecoyVaultStorage.databaseFileExists(
                        context
                )
        );

        File databaseFile =
                context.getDatabasePath(
                        DecoyVaultStorage.DATABASE_NAME
                );

        assertTrue(
                databaseFile.length() > 0L
        );
    }

    @Test
    public void secondaryDatabase_isEncryptedNotPlaintextSQLite()
            throws Exception {

        DecoyVaultStorage.ensureDatabaseFile(
                context
        );

        File databaseFile =
                context.getDatabasePath(
                        DecoyVaultStorage.DATABASE_NAME
                );

        byte[] header =
                new byte[16];

        try (
                FileInputStream inputStream =
                        new FileInputStream(
                                databaseFile
                        )
        ) {
            int read =
                    inputStream.read(
                            header
                    );

            assertEquals(
                    header.length,
                    read
            );
        }

        byte[] plaintextSqliteHeader =
                new byte[]{
                        'S', 'Q', 'L', 'i',
                        't', 'e', ' ', 'f',
                        'o', 'r', 'm', 'a',
                        't', ' ', '3', 0
                };

        assertFalse(
                Arrays.equals(
                        plaintextSqliteHeader,
                        header
                )
        );

        Arrays.fill(
                header,
                (byte) 0
        );
    }

    @Test
    public void ensureDatabaseFile_calledAgain_doesNotReplaceDatabase()
            throws Exception {

        DecoyVaultStorage.ensureDatabaseFile(
                context
        );

        File databaseFile =
                context.getDatabasePath(
                        DecoyVaultStorage.DATABASE_NAME
                );

        byte[] beforeHash =
                sha256(
                        databaseFile
                );

        long beforeLength =
                databaseFile.length();

        DecoyVaultStorage.ensureDatabaseFile(
                context
        );

        byte[] afterHash =
                sha256(
                        databaseFile
                );

        try {
            assertEquals(
                    beforeLength,
                    databaseFile.length()
            );

            assertArrayEquals(
                    beforeHash,
                    afterHash
            );

        } finally {
            Arrays.fill(
                    beforeHash,
                    (byte) 0
            );

            Arrays.fill(
                    afterHash,
                    (byte) 0
            );
        }
    }

    @Test
    public void randomWrongKey_cannotOpenSecondaryDatabase() {
        DecoyVaultStorage.ensureDatabaseFile(
                context
        );

        byte[] wrongKey =
                createDatabaseKey(
                        81
                );

        SafeKeyDatabase wrongKeyManager =
                new SafeKeyDatabase(
                        context,
                        DecoyVaultStorage.DATABASE_NAME
                );

        try {
            try {
                wrongKeyManager.open(
                        wrongKey
                );

                fail(
                        "Expected the secondary database to reject an unrelated key."
                );

            } catch (RuntimeException expected) {
                assertFalse(
                        wrongKeyManager.isOpen()
                );
            }

        } finally {
            wrongKeyManager.close();

            Arrays.fill(
                    wrongKey,
                    (byte) 0
            );
        }
    }

    @Test
    public void creatingSecondaryDatabase_doesNotModifyPrimaryVault()
            throws Exception {

        byte[] primaryKey =
                createDatabaseKey(
                        21
                );

        SafeKeyDatabase primaryManager =
                new SafeKeyDatabase(
                        context,
                        PRIMARY_DATABASE_NAME
                );

        try {
            SQLiteDatabase primaryDatabase =
                    primaryManager.open(
                            primaryKey
                    );

            primaryDatabase.execSQL(
                    "INSERT INTO secure_notes ("
                            + "title, content_ciphertext, "
                            + "created_at, updated_at"
                            + ") VALUES (?, ?, ?, ?)",
                    new Object[]{
                            "Primary-only note",
                            "primary-encrypted-content",
                            1L,
                            1L
                    }
            );

            primaryManager.close();

            DecoyVaultStorage.ensureDatabaseFile(
                    context
            );

            SafeKeyDatabase reopenedPrimaryManager =
                    new SafeKeyDatabase(
                            context,
                            PRIMARY_DATABASE_NAME
                    );

            try {
                SQLiteDatabase reopenedPrimary =
                        reopenedPrimaryManager.open(
                                primaryKey
                        );

                Cursor cursor =
                        reopenedPrimary.rawQuery(
                                "SELECT content_ciphertext "
                                        + "FROM secure_notes "
                                        + "WHERE title = ?",
                                new String[]{
                                        "Primary-only note"
                                }
                        );

                try {
                    assertTrue(
                            cursor.moveToFirst()
                    );

                    assertEquals(
                            "primary-encrypted-content",
                            cursor.getString(
                                    0
                            )
                    );

                } finally {
                    cursor.close();
                }

            } finally {
                reopenedPrimaryManager.close();
            }

        } finally {
            primaryManager.close();

            Arrays.fill(
                    primaryKey,
                    (byte) 0
            );

            /*
             * This test temporarily creates the real database
             * using a test key, so always remove it afterwards.
             */
            context.deleteDatabase(
                    PRIMARY_DATABASE_NAME
            );
        }
    }

    private static byte[] createDatabaseKey(
            int startingValue
    ) {
        byte[] databaseKey =
                new byte[
                        SafeKeyDatabase
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

    private static byte[] sha256(
            File file
    ) throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance(
                        "SHA-256"
                );

        byte[] buffer =
                new byte[4096];

        try (
                FileInputStream inputStream =
                        new FileInputStream(
                                file
                        )
        ) {
            int count;

            while (
                    (count = inputStream.read(
                            buffer
                    )) != -1
            ) {
                digest.update(
                        buffer,
                        0,
                        count
                );
            }

        } finally {
            Arrays.fill(
                    buffer,
                    (byte) 0
            );
        }

        return digest.digest();
    }
}

package com.safekey.app.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.repository.CredentialRepository;
import com.safekey.app.data.repository.SecureNoteRepository;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;

@RunWith(AndroidJUnit4.class)
public class SafeKeyDataInstrumentedTest {

    private static final String TEST_DATABASE_NAME =
            "safekey_instrumented_test.db";

    private static final String NULL_KEY_DATABASE_NAME =
            "safekey_null_key_test.db";

    private static final String EMPTY_KEY_DATABASE_NAME =
            "safekey_empty_key_test.db";

    private static final String WRONG_KEY_DATABASE_NAME =
            "safekey_wrong_key_test.db";

    private static final String FUTURE_VERSION_DATABASE_NAME =
            "safekey_future_version_test.db";

    /*
     * The production database currently supports
     * schema version 1.
     *
     * This value intentionally represents a database
     * created by a newer, unsupported application.
     */
    private static final int FUTURE_DATABASE_VERSION = 99;

    /*
     * Returns fresh deterministic test key material.
     * These values exist only under src/androidTest
     * and are not production secrets.
     */
    private static byte[] newTestDatabaseKey() {

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
                            index + 1
                    );
        }

        return databaseKey;
    }

    private static byte[] newWrongDatabaseKey() {

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
                            0xA5 ^ index
                    );
        }

        return databaseKey;
    }

    private Context context;

    private SafeKeyDatabase databaseManager;

    private SQLiteDatabase database;

    private CredentialRepository credentialRepository;

    private SecureNoteRepository secureNoteRepository;

    @Before
    public void setUp() {

        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        deleteTestDatabase();

        context.deleteDatabase(
                NULL_KEY_DATABASE_NAME
        );

        context.deleteDatabase(
                EMPTY_KEY_DATABASE_NAME
        );

        context.deleteDatabase(
                WRONG_KEY_DATABASE_NAME
        );

        context.deleteDatabase(
                FUTURE_VERSION_DATABASE_NAME
        );

        openTestDatabase();
    }

    @After
    public void tearDown() {

        if (databaseManager != null) {
            databaseManager.close();
        }

        database = null;
        credentialRepository = null;
        secureNoteRepository = null;
        databaseManager = null;

        deleteTestDatabase();

        context.deleteDatabase(
                NULL_KEY_DATABASE_NAME
        );

        context.deleteDatabase(
                EMPTY_KEY_DATABASE_NAME
        );

        context.deleteDatabase(
                WRONG_KEY_DATABASE_NAME
        );

        context.deleteDatabase(
                FUTURE_VERSION_DATABASE_NAME
        );
    }

    private void openTestDatabase() {

        databaseManager =
                new SafeKeyDatabase(
                        context,
                        TEST_DATABASE_NAME
                );

        database =
                databaseManager.open(
                        newTestDatabaseKey()
                );

        credentialRepository =
                new CredentialRepository(
                        database
                );

        secureNoteRepository =
                new SecureNoteRepository(
                        database
                );
    }

    private void deleteTestDatabase() {

        context.deleteDatabase(
                TEST_DATABASE_NAME
        );
    }

    @Test
    public void nullDatabaseKeyIsRejected() {

        SafeKeyDatabase nullKeyDatabase =
                new SafeKeyDatabase(
                        context,
                        NULL_KEY_DATABASE_NAME
                );

        assertFalse(
                context
                        .getDatabasePath(
                                NULL_KEY_DATABASE_NAME
                        )
                        .exists()
        );

        try {

            nullKeyDatabase.open(
                    (byte[]) null
            );

            fail(
                    "Expected null database key to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertEquals(
                    "Database key cannot be null.",
                    expected.getMessage()
            );

            assertFalse(
                    nullKeyDatabase.isOpen()
            );

            assertFalse(
                    context
                            .getDatabasePath(
                                    NULL_KEY_DATABASE_NAME
                            )
                            .exists()
            );

        } finally {

            nullKeyDatabase.close();

            context.deleteDatabase(
                    NULL_KEY_DATABASE_NAME
            );
        }
    }

    @Test
    public void emptyDatabaseKeyIsRejected() {

        SafeKeyDatabase emptyKeyDatabase =
                new SafeKeyDatabase(
                        context,
                        EMPTY_KEY_DATABASE_NAME
                );

        assertFalse(
                context
                        .getDatabasePath(
                                EMPTY_KEY_DATABASE_NAME
                        )
                        .exists()
        );

        try {

            emptyKeyDatabase.open(
                    new byte[0]
            );

            fail(
                    "Expected an empty database key to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertEquals(
                    "Database key must contain exactly 32 bytes.",
                    expected.getMessage()
            );

            assertFalse(
                    emptyKeyDatabase.isOpen()
            );

            assertFalse(
                    context
                            .getDatabasePath(
                                    EMPTY_KEY_DATABASE_NAME
                            )
                            .exists()
            );

        } finally {

            emptyKeyDatabase.close();

            context.deleteDatabase(
                    EMPTY_KEY_DATABASE_NAME
            );
        }
    }

    @Test
    public void wrongDatabaseKeyIsRejectedAndCorrectKeyStillWorks() {

        SafeKeyDatabase correctDatabaseManager =
                new SafeKeyDatabase(
                        context,
                        WRONG_KEY_DATABASE_NAME
                );

        SQLiteDatabase correctDatabase =
                correctDatabaseManager.open(
                        newTestDatabaseKey()
                );

        CredentialRepository correctRepository =
                new CredentialRepository(
                        correctDatabase
                );

        Credential credential =
                new Credential(
                        "Wrong Key Test",
                        "wrong-key-user",
                        "wrong-key-secret",
                        "wrong-key.test",
                        "Work",
                        "Wrong key test note"
                );

        long credentialId =
                correctRepository.insert(
                        credential
                );

        assertTrue(
                credentialId > 0
        );

        correctDatabaseManager.close();

        assertFalse(
                correctDatabaseManager.isOpen()
        );

        SafeKeyDatabase wrongDatabaseManager =
                new SafeKeyDatabase(
                        context,
                        WRONG_KEY_DATABASE_NAME
                );

        try {

            wrongDatabaseManager.open(
                    newWrongDatabaseKey()
            );

            fail(
                    "Expected the wrong database key to fail."
            );

        } catch (RuntimeException expected) {

            assertFalse(
                    wrongDatabaseManager.isOpen()
            );

        } finally {

            wrongDatabaseManager.close();
        }

        SafeKeyDatabase reopenedDatabaseManager =
                new SafeKeyDatabase(
                        context,
                        WRONG_KEY_DATABASE_NAME
                );

        try {

            SQLiteDatabase reopenedDatabase =
                    reopenedDatabaseManager.open(
                            newTestDatabaseKey()
                    );

            CredentialRepository reopenedRepository =
                    new CredentialRepository(
                            reopenedDatabase
                    );

            Credential reopenedCredential =
                    reopenedRepository.getById(
                            credentialId
                    );

            assertNotNull(
                    reopenedCredential
            );

            assertEquals(
                    credentialId,
                    reopenedCredential.getId()
            );

            assertEquals(
                    "Wrong Key Test",
                    reopenedCredential.getTitle()
            );

            assertEquals(
                    "wrong-key-user",
                    reopenedCredential.getUsername()
            );

            assertEquals(
                    "wrong-key-secret",
                    reopenedCredential.getPassword()
            );

            assertEquals(
                    "Wrong key test note",
                    reopenedCredential.getNotes()
            );

        } finally {

            reopenedDatabaseManager.close();

            context.deleteDatabase(
                    WRONG_KEY_DATABASE_NAME
            );
        }
    }

    @Test
    public void newerDatabaseVersionIsRejectedAndManagerRemainsClosed() {

        /*
         * First create a normal supported version-1
         * SQLCipher database using the production
         * database manager.
         */
        SafeKeyDatabase creatorDatabaseManager =
                new SafeKeyDatabase(
                        context,
                        FUTURE_VERSION_DATABASE_NAME
                );

        SQLiteDatabase creatorDatabase =
                creatorDatabaseManager.open(
                        newTestDatabaseKey()
                );

        assertTrue(
                creatorDatabaseManager.isOpen()
        );

        /*
         * Simulate a database written by a newer
         * application version by changing its stored
         * user_version to an unsupported schema version.
         */
        creatorDatabase.setVersion(
                FUTURE_DATABASE_VERSION
        );

        assertEquals(
                FUTURE_DATABASE_VERSION,
                creatorDatabase.getVersion()
        );

        creatorDatabaseManager.close();

        assertFalse(
                creatorDatabaseManager.isOpen()
        );

        /*
         * A fresh manager represents an older version
         * of the application trying to open the newer
         * database.
         */
        SafeKeyDatabase futureVersionDatabaseManager =
                new SafeKeyDatabase(
                        context,
                        FUTURE_VERSION_DATABASE_NAME
                );

        try {

            futureVersionDatabaseManager.open(
                    newTestDatabaseKey()
            );

            fail(
                    "Expected a newer unsupported database version to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertEquals(
                    "Database version "
                            + FUTURE_DATABASE_VERSION
                            + " is newer than supported version 3.",
                    expected.getMessage()
            );

            /*
             * SafeKeyDatabase.open() must close the
             * temporary SQLCipher connection after
             * initialization rejects the version.
             */
            assertFalse(
                    futureVersionDatabaseManager.isOpen()
            );

        } finally {

            futureVersionDatabaseManager.close();

            context.deleteDatabase(
                    FUTURE_VERSION_DATABASE_NAME
            );
        }
    }

    @Test
    public void databaseCanOpenAndClose() {

        assertNotNull(
                database
        );

        assertTrue(
                databaseManager.isOpen()
        );

        databaseManager.close();

        assertFalse(
                databaseManager.isOpen()
        );
    }

    @Test
    public void credentialCanBeAddedReadUpdatedAndDeleted() {

        Credential credential =
                new Credential(
                        "Credential CRUD Test",
                        "test-user",
                        "test-secret",
                        "example.test",
                        "Work",
                        "Test-only note"
                );

        long credentialId =
                credentialRepository.insert(
                        credential
                );

        assertTrue(
                credentialId > 0
        );

        Credential savedCredential =
                credentialRepository.getById(
                        credentialId
                );

        assertNotNull(
                savedCredential
        );

        assertEquals(
                credentialId,
                savedCredential.getId()
        );

        assertEquals(
                "Credential CRUD Test",
                savedCredential.getTitle()
        );

        assertEquals(
                "test-user",
                savedCredential.getUsername()
        );

        assertEquals(
                "test-secret",
                savedCredential.getPassword()
        );

        assertEquals(
                "Test-only note",
                savedCredential.getNotes()
        );

        assertEquals(
                "example.test",
                savedCredential.getWebsite()
        );

        assertEquals(
                "Work",
                savedCredential.getCategory()
        );

        savedCredential.setTitle(
                "Updated Credential CRUD Test"
        );

        savedCredential.setWebsite(
                "updated.example.test"
        );

        savedCredential.setPassword(
                "updated-test-secret"
        );

        savedCredential.setNotes(
                "Updated test-only note"
        );

        int updatedRows =
                credentialRepository.update(
                        savedCredential
                );

        assertEquals(
                1,
                updatedRows
        );

        Credential updatedCredential =
                credentialRepository.getById(
                        credentialId
                );

        assertNotNull(
                updatedCredential
        );

        assertEquals(
                "Updated Credential CRUD Test",
                updatedCredential.getTitle()
        );

        assertEquals(
                "updated.example.test",
                updatedCredential.getWebsite()
        );

        assertEquals(
                "updated-test-secret",
                updatedCredential.getPassword()
        );

        assertEquals(
                "Updated test-only note",
                updatedCredential.getNotes()
        );

        int deletedRows =
                credentialRepository.delete(
                        credentialId
                );

        assertEquals(
                1,
                deletedRows
        );

        Credential deletedCredential =
                credentialRepository.getById(
                        credentialId
                );

        assertNull(
                deletedCredential
        );
    }

    @Test
    public void credentialsCanBeSearched() {

        Credential firstCredential =
                new Credential(
                        "GitHub Search Test",
                        "first-user",
                        "first-test-secret",
                        "github.test",
                        "Work",
                        ""
                );

        Credential secondCredential =
                new Credential(
                        "University Account",
                        "second-user",
                        "second-test-secret",
                        "university.test",
                        "University",
                        ""
                );

        credentialRepository.insert(
                firstCredential
        );

        credentialRepository.insert(
                secondCredential
        );

        List<Credential> results =
                credentialRepository.search(
                        "GitHub"
                );

        assertEquals(
                1,
                results.size()
        );

        assertEquals(
                "GitHub Search Test",
                results.get(0).getTitle()
        );
    }

    @Test
    public void credentialFavoriteStatusCanBeChangedAndRead() {

        Credential credential =
                new Credential(
                        "Favorite Test",
                        "favorite-user",
                        "favorite-test-secret",
                        "favorite.test",
                        "Work",
                        ""
                );

        long credentialId =
                credentialRepository.insert(
                        credential
                );

        Credential beforeFavorite =
                credentialRepository.getById(
                        credentialId
                );

        assertNotNull(
                beforeFavorite
        );

        assertFalse(
                beforeFavorite.isFavorite()
        );

        int updatedRows =
                credentialRepository.setFavorite(
                        credentialId,
                        true
                );

        assertEquals(
                1,
                updatedRows
        );

        Credential afterFavorite =
                credentialRepository.getById(
                        credentialId
                );

        assertNotNull(
                afterFavorite
        );

        assertTrue(
                afterFavorite.isFavorite()
        );
    }

    @Test
    public void secureNoteCanBeAddedReadUpdatedAndDeleted() {

        SecureNote secureNote =
                new SecureNote(
                        "Secure Note CRUD Test",
                        "Test-only secure note content"
                );

        long noteId =
                secureNoteRepository.insert(
                        secureNote
                );

        assertTrue(
                noteId > 0
        );

        SecureNote savedNote =
                secureNoteRepository.getById(
                        noteId
                );

        assertNotNull(
                savedNote
        );

        assertEquals(
                noteId,
                savedNote.getId()
        );

        assertEquals(
                "Secure Note CRUD Test",
                savedNote.getTitle()
        );

        assertEquals(
                "Test-only secure note content",
                savedNote.getContent()
        );

        savedNote.setTitle(
                "Updated Secure Note CRUD Test"
        );

        savedNote.setContent(
                "Updated test-only secure note content"
        );

        int updatedRows =
                secureNoteRepository.update(
                        savedNote
                );

        assertEquals(
                1,
                updatedRows
        );

        SecureNote updatedNote =
                secureNoteRepository.getById(
                        noteId
                );

        assertNotNull(
                updatedNote
        );

        assertEquals(
                "Updated Secure Note CRUD Test",
                updatedNote.getTitle()
        );

        assertEquals(
                "Updated test-only secure note content",
                updatedNote.getContent()
        );

        int deletedRows =
                secureNoteRepository.delete(
                        noteId
                );

        assertEquals(
                1,
                deletedRows
        );

        SecureNote deletedNote =
                secureNoteRepository.getById(
                        noteId
                );

        assertNull(
                deletedNote
        );
    }

    @Test
    public void secureNotesCanBeSearched() {

        SecureNote firstNote =
                new SecureNote(
                        "Recovery Codes",
                        "Backup recovery codes for testing"
                );

        SecureNote secondNote =
                new SecureNote(
                        "University Reminder",
                        "Submit the project report"
                );

        long firstNoteId =
                secureNoteRepository.insert(
                        firstNote
                );

        long secondNoteId =
                secureNoteRepository.insert(
                        secondNote
                );

        assertTrue(
                firstNoteId > 0
        );

        assertTrue(
                secondNoteId > 0
        );

        List<SecureNote> titleResults =
                secureNoteRepository.search(
                        "Recovery"
                );

        assertEquals(
                1,
                titleResults.size()
        );

        assertEquals(
                "Recovery Codes",
                titleResults.get(0).getTitle()
        );

        assertEquals(
                "Backup recovery codes for testing",
                titleResults.get(0).getContent()
        );

        List<SecureNote> contentResults =
                secureNoteRepository.search(
                        "project report"
                );

        assertEquals(
                1,
                contentResults.size()
        );

        assertEquals(
                "University Reminder",
                contentResults.get(0).getTitle()
        );

        assertEquals(
                "Submit the project report",
                contentResults.get(0).getContent()
        );
    }

    @Test
    public void dataRemainsAfterDatabaseIsClosedAndReopened() {

        Credential credential =
                new Credential(
                        "Persistence Credential",
                        "persistence-user",
                        "persistence-test-secret",
                        "persistence.test",
                        "Work",
                        "Persistence credential note"
                );

        SecureNote secureNote =
                new SecureNote(
                        "Persistence Secure Note",
                        "Persistence test-only content"
                );

        long credentialId =
                credentialRepository.insert(
                        credential
                );

        long noteId =
                secureNoteRepository.insert(
                        secureNote
                );

        assertTrue(
                credentialId > 0
        );

        assertTrue(
                noteId > 0
        );

        databaseManager.close();

        assertFalse(
                databaseManager.isOpen()
        );

        openTestDatabase();

        Credential reopenedCredential =
                credentialRepository.getById(
                        credentialId
                );

        SecureNote reopenedNote =
                secureNoteRepository.getById(
                        noteId
                );

        assertNotNull(
                reopenedCredential
        );

        assertNotNull(
                reopenedNote
        );

        assertEquals(
                "Persistence Credential",
                reopenedCredential.getTitle()
        );

        assertEquals(
                "persistence-user",
                reopenedCredential.getUsername()
        );

        assertEquals(
                "persistence-test-secret",
                reopenedCredential.getPassword()
        );

        assertEquals(
                "Persistence credential note",
                reopenedCredential.getNotes()
        );

        assertEquals(
                "Persistence Secure Note",
                reopenedNote.getTitle()
        );

        assertEquals(
                "Persistence test-only content",
                reopenedNote.getContent()
        );
    }
}

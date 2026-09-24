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

    private static final String NULL_PASSPHRASE_DATABASE_NAME =
            "safekey_null_passphrase_test.db";

    private static final String EMPTY_PASSPHRASE_DATABASE_NAME =
            "safekey_empty_passphrase_test.db";

    private static final String WRONG_PASSPHRASE_DATABASE_NAME =
            "safekey_wrong_passphrase_test.db";

    private static final String FUTURE_VERSION_DATABASE_NAME =
            "safekey_future_version_test.db";

    /*
     * The production database currently supports
     * schema version 1.
     *
     * This value intentionally represents a database
     * created by a newer, unsupported application.
     */
    private static final int FUTURE_DATABASE_VERSION = 2;

    /*
     * Test-only SQLCipher passphrase.
     * This value exists only under src/androidTest.
     * It must never be moved into src/main.
     */
    private static final String TEST_DATABASE_PASSPHRASE =
            "SafeKey-Instrumented-Test-Passphrase-2026";

    /*
     * Test-only incorrect SQLCipher passphrase.
     * Used only to verify that a database cannot
     * be opened with the wrong key.
     */
    private static final String WRONG_DATABASE_PASSPHRASE =
            "SafeKey-Incorrect-Test-Passphrase-2026";

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
                NULL_PASSPHRASE_DATABASE_NAME
        );

        context.deleteDatabase(
                EMPTY_PASSPHRASE_DATABASE_NAME
        );

        context.deleteDatabase(
                WRONG_PASSPHRASE_DATABASE_NAME
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
                NULL_PASSPHRASE_DATABASE_NAME
        );

        context.deleteDatabase(
                EMPTY_PASSPHRASE_DATABASE_NAME
        );

        context.deleteDatabase(
                WRONG_PASSPHRASE_DATABASE_NAME
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
                        TEST_DATABASE_PASSPHRASE
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
    public void nullDatabasePassphraseIsRejected() {

        SafeKeyDatabase nullPassphraseDatabase =
                new SafeKeyDatabase(
                        context,
                        NULL_PASSPHRASE_DATABASE_NAME
                );

        assertFalse(
                context
                        .getDatabasePath(
                                NULL_PASSPHRASE_DATABASE_NAME
                        )
                        .exists()
        );

        try {

            nullPassphraseDatabase.open(
                    null
            );

            fail(
                    "Expected null database passphrase to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertEquals(
                    "Database passphrase cannot be null or empty.",
                    expected.getMessage()
            );

            assertFalse(
                    nullPassphraseDatabase.isOpen()
            );

            assertFalse(
                    context
                            .getDatabasePath(
                                    NULL_PASSPHRASE_DATABASE_NAME
                            )
                            .exists()
            );

        } finally {

            nullPassphraseDatabase.close();

            context.deleteDatabase(
                    NULL_PASSPHRASE_DATABASE_NAME
            );
        }
    }

    @Test
    public void emptyDatabasePassphraseIsRejected() {

        SafeKeyDatabase emptyPassphraseDatabase =
                new SafeKeyDatabase(
                        context,
                        EMPTY_PASSPHRASE_DATABASE_NAME
                );

        assertFalse(
                context
                        .getDatabasePath(
                                EMPTY_PASSPHRASE_DATABASE_NAME
                        )
                        .exists()
        );

        try {

            emptyPassphraseDatabase.open(
                    ""
            );

            fail(
                    "Expected empty database passphrase to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertEquals(
                    "Database passphrase cannot be null or empty.",
                    expected.getMessage()
            );

            assertFalse(
                    emptyPassphraseDatabase.isOpen()
            );

            assertFalse(
                    context
                            .getDatabasePath(
                                    EMPTY_PASSPHRASE_DATABASE_NAME
                            )
                            .exists()
            );

        } finally {

            emptyPassphraseDatabase.close();

            context.deleteDatabase(
                    EMPTY_PASSPHRASE_DATABASE_NAME
            );
        }
    }

    @Test
    public void wrongDatabasePassphraseIsRejectedAndCorrectPassphraseStillWorks() {

        SafeKeyDatabase correctDatabaseManager =
                new SafeKeyDatabase(
                        context,
                        WRONG_PASSPHRASE_DATABASE_NAME
                );

        SQLiteDatabase correctDatabase =
                correctDatabaseManager.open(
                        TEST_DATABASE_PASSPHRASE
                );

        CredentialRepository correctRepository =
                new CredentialRepository(
                        correctDatabase
                );

        Credential credential =
                new Credential(
                        "Wrong Passphrase Test",
                        "wrong-passphrase-user",
                        "wrong-passphrase-secret",
                        "wrong-passphrase.test",
                        "Work",
                        "Wrong passphrase test note"
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
                        WRONG_PASSPHRASE_DATABASE_NAME
                );

        try {

            wrongDatabaseManager.open(
                    WRONG_DATABASE_PASSPHRASE
            );

            fail(
                    "Expected the wrong database passphrase to fail."
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
                        WRONG_PASSPHRASE_DATABASE_NAME
                );

        try {

            SQLiteDatabase reopenedDatabase =
                    reopenedDatabaseManager.open(
                            TEST_DATABASE_PASSPHRASE
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
                    "Wrong Passphrase Test",
                    reopenedCredential.getTitle()
            );

            assertEquals(
                    "wrong-passphrase-user",
                    reopenedCredential.getUsername()
            );

            assertEquals(
                    "wrong-passphrase-secret",
                    reopenedCredential.getPassword()
            );

            assertEquals(
                    "Wrong passphrase test note",
                    reopenedCredential.getNotes()
            );

        } finally {

            reopenedDatabaseManager.close();

            context.deleteDatabase(
                    WRONG_PASSPHRASE_DATABASE_NAME
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
                        TEST_DATABASE_PASSPHRASE
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
                    TEST_DATABASE_PASSPHRASE
            );

            fail(
                    "Expected a newer unsupported database version to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertEquals(
                    "Database version "
                            + FUTURE_DATABASE_VERSION
                            + " is newer than supported version 1.",
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
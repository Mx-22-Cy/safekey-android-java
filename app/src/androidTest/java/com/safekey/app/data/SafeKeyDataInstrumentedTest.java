package com.safekey.app.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

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

    /*
     * Test-only SQLCipher passphrase.
     * This value exists only under src/androidTest.
     * It must never be moved into src/main.
     */
    private static final String TEST_DATABASE_PASSPHRASE =
            "SafeKey-Instrumented-Test-Passphrase-2026";

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

        savedCredential.setTitle(
                "Updated Credential CRUD Test"
        );

        savedCredential.setWebsite(
                "updated.example.test"
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
    public void dataRemainsAfterDatabaseIsClosedAndReopened() {

        Credential credential =
                new Credential(
                        "Persistence Credential",
                        "persistence-user",
                        "persistence-test-secret",
                        "persistence.test",
                        "Work",
                        ""
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
                "Persistence Secure Note",
                reopenedNote.getTitle()
        );
    }
}
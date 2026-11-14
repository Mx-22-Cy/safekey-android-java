package com.safekey.app.data.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.SecureNote;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@RunWith(AndroidJUnit4.class)
public class SecureNoteSearchInstrumentedTest {

    private Context context;
    private String databaseName;
    private byte[] databaseKey;
    private SafeKeyDatabase databaseManager;
    private SecureNoteRepository repository;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        databaseName = "safekey_note_search_" + UUID.randomUUID() + ".db";
        databaseKey = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
        Arrays.fill(databaseKey, (byte) 61);

        databaseManager = new SafeKeyDatabase(context, databaseName);
        repository = new SecureNoteRepository(databaseManager.open(databaseKey));
    }

    @After
    public void tearDown() {
        try {
            if (databaseManager != null) {
                databaseManager.close();
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
    public void searchFindsContentEvenWhenTitleDoesNotMatch() {
        long wantedId = repository.insert(new SecureNote(
                "Unrelated title", "Fictional recovery phrase for test only"));
        repository.insert(new SecureNote(
                "Another title", "Different fictional content"));

        List<SecureNote> found = repository.search("ReCoVeRy PhRaSe");

        assertEquals(1, found.size());
        assertEquals(wantedId, found.get(0).getId());
        assertEquals("Fictional recovery phrase for test only",
                found.get(0).getContent());
    }

    @Test
    public void searchFindsTitleWithoutMatchingContent() {
        long wantedId = repository.insert(new SecureNote(
                "Library Access", "fictional note A"));
        repository.insert(new SecureNote(
                "Account Details", "fictional note B"));

        List<SecureNote> found = repository.search("library");

        assertEquals(1, found.size());
        assertEquals(wantedId, found.get(0).getId());
    }

    @Test
    public void searchTreatsSqlLikeWildcardsAsLiteralCharacters() {
        repository.insert(new SecureNote("ordinary", "one hundred percent"));
        long wantedId = repository.insert(new SecureNote("literal %", "literal _"));

        List<SecureNote> percent = repository.search("%");
        assertEquals(1, percent.size());
        assertEquals(wantedId, percent.get(0).getId());

        List<SecureNote> underscore = repository.search("_");
        assertEquals(1, underscore.size());
        assertEquals(wantedId, underscore.get(0).getId());
    }

    @Test
    public void blankSearchReturnsAllNotes() {
        repository.insert(new SecureNote("First", "first fictional body"));
        repository.insert(new SecureNote("Second", "second fictional body"));

        List<SecureNote> found = repository.search("   ");
        assertEquals(2, found.size());
        boolean sawFirst = false;
        boolean sawSecond = false;
        for (SecureNote note : found) {
            sawFirst |= "First".equals(note.getTitle());
            sawSecond |= "Second".equals(note.getTitle());
        }
        assertTrue(sawFirst);
        assertTrue(sawSecond);
    }
}

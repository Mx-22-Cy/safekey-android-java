package com.safekey.app.data.repository;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.breach.PasswordBreachResult.Status;
import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

@RunWith(AndroidJUnit4.class)
public class CredentialBreachStatusInstrumentedTest {
    private static final String DATABASE = "t44_breach_status_test.db";
    private static final String PASSWORD = "public credential fixture";
    private final byte[] key = new byte[32];
    private Context context;
    private SafeKeyDatabase manager;
    private CredentialRepository repository;
    private long id;

    @Before public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        context.deleteDatabase(DATABASE);
        Arrays.fill(key, (byte) 37);
        reopen();
        id = repository.insert(new Credential("Fixture", "test@example.com", PASSWORD,
                "https://example.com", "Work", ""));
    }

    @After public void tearDown() {
        if (manager != null) { manager.close(); }
        context.deleteDatabase(DATABASE);
        Arrays.fill(key, (byte) 0);
    }

    @Test public void newCredentialStartsUncheckedRegardlessOfCallerStatus() {
        Credential candidate = new Credential("Other", "test", "another fixture password",
                "", "Work", "");
        candidate.setBreachStatus(Status.NOT_FOUND);
        long other = repository.insert(candidate);
        assertEquals(Status.NOT_CHECKED, repository.getById(other).getBreachStatus());
    }

    @Test public void savedBreachSurvivesDatabaseCloseAndReopen() {
        assertEquals(Status.BREACHED, repository.updateBreachStatus(id, PASSWORD, Status.BREACHED));
        manager.close();
        reopen();
        assertEquals(Status.BREACHED, repository.getById(id).getBreachStatus());
    }

    @Test public void savedNoMatchIsReadByAllCredentialQueries() {
        repository.updateBreachStatus(id, PASSWORD, Status.NOT_FOUND);
        assertEquals(Status.NOT_FOUND, repository.getById(id).getBreachStatus());
        assertEquals(Status.NOT_FOUND, repository.getAll().get(0).getBreachStatus());
        assertEquals(Status.NOT_FOUND, repository.search("Fixture").get(0).getBreachStatus());
    }

    @Test public void passwordEditInvalidatesSavedBreachResult() {
        repository.updateBreachStatus(id, PASSWORD, Status.BREACHED);
        Credential edited = repository.getById(id);
        edited.setPassword("different public fixture");
        repository.update(edited);
        assertEquals(Status.NOT_CHECKED, repository.getById(id).getBreachStatus());
    }

    @Test public void titleEditKeepsCompletedResult() {
        repository.updateBreachStatus(id, PASSWORD, Status.BREACHED);
        Credential edited = repository.getById(id);
        edited.setTitle("Renamed fixture");
        edited.setBreachStatus(Status.NOT_FOUND);
        repository.update(edited);
        assertEquals(Status.BREACHED, repository.getById(id).getBreachStatus());
    }

    @Test public void favoriteChangeKeepsCompletedResult() {
        repository.updateBreachStatus(id, PASSWORD, Status.NOT_FOUND);
        repository.setFavorite(id, true);
        assertEquals(Status.NOT_FOUND, repository.getById(id).getBreachStatus());
    }

    @Test public void oldPasswordResultCannotDescribeEditedPassword() {
        Credential edited = repository.getById(id);
        edited.setPassword("new public fixture password");
        repository.update(edited);
        assertNull(repository.updateBreachStatus(id, PASSWORD, Status.BREACHED));
        assertEquals(Status.NOT_CHECKED, repository.getById(id).getBreachStatus());
    }

    @Test public void failedRefreshCannotEraseKnownBreach() {
        repository.updateBreachStatus(id, PASSWORD, Status.BREACHED);
        assertEquals(Status.BREACHED, repository.updateBreachStatus(id, PASSWORD, Status.ERROR));
    }

    @Test public void olderNoMatchCannotEraseKnownBreachForSamePassword() {
        repository.updateBreachStatus(id, PASSWORD, Status.BREACHED);
        assertEquals(Status.BREACHED, repository.updateBreachStatus(id, PASSWORD, Status.NOT_FOUND));
    }

    @Test public void failedRefreshKeepsSavedNoMatch() {
        repository.updateBreachStatus(id, PASSWORD, Status.NOT_FOUND);
        assertEquals(Status.NOT_FOUND, repository.updateBreachStatus(id, PASSWORD, Status.ERROR));
    }

    @Test public void failureWithoutCompletedResultIsStoredAsError() {
        assertEquals(Status.ERROR, repository.updateBreachStatus(id, PASSWORD, Status.ERROR));
        assertEquals(Status.ERROR, repository.getById(id).getBreachStatus());
    }

    @Test public void deletedCredentialCannotReceiveLateResult() {
        repository.delete(id);
        assertNull(repository.updateBreachStatus(id, PASSWORD, Status.BREACHED));
    }

    @Test public void passwordComparisonIsCaseSensitive() {
        assertNull(repository.updateBreachStatus(id, PASSWORD.toUpperCase(java.util.Locale.US),
                Status.NOT_FOUND));
        assertEquals(Status.NOT_CHECKED, repository.getById(id).getBreachStatus());
    }

    private void reopen() {
        manager = new SafeKeyDatabase(context, DATABASE);
        repository = new CredentialRepository(manager.open(key));
    }
}

package com.safekey.app.security.panic;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PanicWipeInstrumentedTest {
    private Context context() {
        return InstrumentationRegistry.getInstrumentation().getTargetContext();
    }

    @Test public void verifiedPanicRemovesBothEncryptedDatabasesEnvelopesKeysAndSession() throws Exception {
        try (PanicInstrumentedFixture f = new PanicInstrumentedFixture(context())) {
            for (String name : f.names.databases) {
                byte[] header = new byte[16];
                try (DataInputStream input = new DataInputStream(
                        new FileInputStream(f.context.getDatabasePath(name)))) {
                    input.readFully(header);
                }
                assertFalse(new String(header, StandardCharsets.ISO_8859_1).startsWith("SQLite format 3"));
            }
            PanicWorkGate.Operation previous = f.gate.begin();
            PanicWorkGate.Ticket queuedSuccess = previous.ticket();
            previous.close();
            assertTrue(f.service.checkAndWipe(PanicInstrumentedFixture.PANIC.toCharArray()));
            f.assertWiped();
            assertFalse(queuedSuccess.isCurrent());
            try { f.gate.begin(); fail("Old runtime accepted work."); }
            catch (CancellationException expected) { }
        }
    }

    @Test public void masterDecoyAndIncorrectPasswordsDoNotTriggerWipe() throws Exception {
        try (PanicInstrumentedFixture f = new PanicInstrumentedFixture(context())) {
            for (String password : new String[]{PanicInstrumentedFixture.MASTER,
                    PanicInstrumentedFixture.DECOY, "An unrelated test password"}) {
                assertFalse(f.service.checkAndWipe(password.toCharArray()));
                assertTrue(f.unlocked);
                assertFalse(f.gate.isBlocked());
                assertFalse(f.journal.isPending());
                for (String database : f.names.databases) { assertTrue(f.context.getDatabasePath(database).isFile()); }
                for (String alias : f.names.aliases) { assertTrue(PanicInstrumentedFixture.keyStore().containsAlias(alias)); }
            }
        }
    }

    @Test public void unrelatedFilesPreferencesDatabaseAndAliasArePreserved() throws Exception {
        try (PanicInstrumentedFixture f = new PanicInstrumentedFixture(context())) {
            String alias = f.prefix + "unrelated_key";
            String preference = f.prefix + "unrelated_preferences";
            File file = new File(f.context.getNoBackupFilesDir(), f.prefix + "unrelated.txt");
            File database = f.context.getDatabasePath(f.prefix + "unrelated.db");
            SharedPreferences prefs = f.context.getSharedPreferences(preference, Context.MODE_PRIVATE);
            try {
                PanicInstrumentedFixture.write(file, new byte[]{4, 5, 6});
                PanicInstrumentedFixture.write(database, new byte[]{7, 8, 9});
                PanicInstrumentedFixture.generateKey(alias);
                assertTrue(prefs.edit().putString("sentinel", "keep").commit());
                assertTrue(f.service.checkAndWipe(PanicInstrumentedFixture.PANIC.toCharArray()));
                f.assertWiped();
                assertTrue(file.isFile());
                assertTrue(database.isFile());
                assertEquals("keep", prefs.getString("sentinel", null));
                assertTrue(PanicInstrumentedFixture.keyStore().containsAlias(alias));
            } finally {
                try { PanicFiles.deleteAll(new File[]{file, database}); }
                finally {
                    try { f.context.deleteSharedPreferences(preference); }
                    finally { PanicInstrumentedFixture.keyStore().deleteEntry(alias); }
                }
            }
        }
    }

    @Test public void pendingEnrollmentWriteDrainsBeforeAnyOwnedStorageIsDeleted() throws Exception {
        try (PanicInstrumentedFixture f = new PanicInstrumentedFixture(context())) {
            PanicWorkGate.Operation pendingEnrollment = f.gate.begin();
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<Boolean> result = executor.submit(() ->
                        f.service.checkAndWipe(PanicInstrumentedFixture.PANIC.toCharArray()));
                assertTrue(f.markerArmed.await(10, TimeUnit.SECONDS));
                assertFalse(result.isDone());
                assertTrue(f.cachedPreferences.get(0).edit()
                        .putString("late_enrollment", "must be erased").commit());
                pendingEnrollment.close();
                assertTrue(result.get(15, TimeUnit.SECONDS));
                f.assertWiped();
                assertFalse(pendingEnrollment.ticket().isCurrent());
            } finally {
                pendingEnrollment.close();
                executor.shutdownNow();
                assertTrue(executor.awaitTermination(15, TimeUnit.SECONDS));
            }
        }
    }

    @Test public void partialWipeKeepsDurableMarkerAndFreshCoordinatorFinishes() throws Exception {
        try (PanicInstrumentedFixture f = new PanicInstrumentedFixture(context())) {
            f.injectDeletionFailure = true;
            try {
                f.service.checkAndWipe(PanicInstrumentedFixture.PANIC.toCharArray());
                fail("Incomplete wipe reported success.");
            } catch (java.io.IOException expected) { }
            assertTrue(f.journal.isPending());
            assertTrue(f.gate.isBlocked());
            assertTrue(f.context.getDatabasePath(f.names.databases[0]).isFile());
            assertFalse(f.context.getDatabasePath(f.names.databases[1]).exists());
            for (String alias : f.names.aliases) { assertFalse(PanicInstrumentedFixture.keyStore().containsAlias(alias)); }
            PanicWorkGate restartedGate = new PanicWorkGate();
            PanicWipeCoordinator recovered = new PanicWipeCoordinator(restartedGate,
                    new PanicWipeJournal(f.context, f.names.journalFile), f.runtime(),
                    PanicWipeTargets.create(f.context, f.names));
            assertTrue(recovered.resumeIfPending());
            assertTrue(restartedGate.isBlocked());
            f.assertWiped();
        }
    }

    @Test public void failedCloseRetainsStorageUntilCloseAndRecoverySucceed() throws Exception {
        try (PanicInstrumentedFixture f = new PanicInstrumentedFixture(context())) {
            f.failClose = true;
            try {
                f.service.checkAndWipe(PanicInstrumentedFixture.PANIC.toCharArray());
                fail("Failed close reported wipe success.");
            } catch (Exception expected) {
                assertTrue(f.journal.isPending());
                assertTrue(f.context.getDatabasePath(f.names.databases[0]).isFile());
                assertTrue(PanicInstrumentedFixture.keyStore().containsAlias(f.names.aliases[0]));
            }
            f.failClose = false;
            assertTrue(f.coordinator.resumeIfPending());
            f.assertWiped();
        }
    }

    @Test public void partialMarkerAfterRestartRequiresRecoveryWithoutAnotherPassword() throws Exception {
        try (PanicInstrumentedFixture f = new PanicInstrumentedFixture(context())) {
            File partial = new File(f.context.getNoBackupFilesDir(), f.names.journalFile + ".new");
            PanicInstrumentedFixture.write(partial, new byte[]{1});
            assertTrue(f.journal.isPending());
            assertTrue(f.coordinator.resumeIfPending());
            f.assertWiped();
        }
    }
}

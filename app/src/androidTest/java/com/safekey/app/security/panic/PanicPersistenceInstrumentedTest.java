package com.safekey.app.security.panic;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PanicPersistenceInstrumentedTest {
    private Context context() { return InstrumentationRegistry.getInstrumentation().getTargetContext(); }
    private String prefix() { return "safekey_panic_test_" + UUID.randomUUID().toString().replace("-", "") + "_"; }

    @Test public void savedProofSurvivesNewStoreInstanceAndStillVerifies() throws Exception {
        Context context = context();
        String name = prefix() + "panic.enc";
        File file = new File(context.getNoBackupFilesDir(), name);
        try {
            PanicPasswordCrypto crypto = new PanicPasswordCrypto();
            PanicPasswordStore first = new PanicPasswordStore(context, name);
            assertNull(first.load());
            first.save(crypto.create(PanicInstrumentedFixture.PANIC.toCharArray()));
            PanicPasswordCrypto.Record record = new PanicPasswordStore(context, name).load();
            assertNotNull(record);
            assertTrue(crypto.matches(PanicInstrumentedFixture.PANIC.toCharArray(), record));
            assertFalse(crypto.matches(PanicInstrumentedFixture.MASTER.toCharArray(), record));
        } finally { PanicFiles.deleteAll(PanicFiles.atomicArtifacts(file)); }
    }

    @Test public void truncatedOversizedAndUnknownVersionProofsAreErrorsNotDisabled() throws Exception {
        Context context = context();
        String name = prefix() + "panic.enc";
        File file = new File(context.getNoBackupFilesDir(), name);
        PanicPasswordStore store = new PanicPasswordStore(context, name);
        try {
            byte[] valid = new PanicPasswordCrypto().create(PanicInstrumentedFixture.PANIC.toCharArray()).encode();
            byte[] invalidVersion = valid.clone(); invalidVersion[3] = 2;
            for (byte[] bad : new byte[][]{Arrays.copyOf(valid, valid.length - 1),
                    Arrays.copyOf(valid, valid.length + 1), invalidVersion}) {
                PanicInstrumentedFixture.write(file, bad);
                try { store.load(); fail("Corrupt proof was accepted."); }
                catch (IOException expected) { }
            }
        } finally { PanicFiles.deleteAll(PanicFiles.atomicArtifacts(file)); }
    }

    @Test public void incompleteAtomicWriteIsNotTreatedAsMissingPanicConfiguration() throws Exception {
        Context context = context();
        String name = prefix() + "panic.enc";
        File base = new File(context.getNoBackupFilesDir(), name);
        try {
            PanicInstrumentedFixture.write(new File(base.getPath() + ".new"), new byte[]{1});
            try { new PanicPasswordStore(context, name).load(); fail("Partial proof was ignored."); }
            catch (IOException expected) { }
        } finally { PanicFiles.deleteAll(PanicFiles.atomicArtifacts(base)); }
    }

    @Test public void everyPartialMarkerArtifactRequiresRecoveryAndCanBeCleared() throws Exception {
        Context context = context();
        String name = prefix() + "wipe.pending";
        File base = new File(context.getNoBackupFilesDir(), name);
        PanicWipeJournal journal = new PanicWipeJournal(context, name);
        try {
            for (File artifact : PanicFiles.atomicArtifacts(base)) {
                assertFalse(journal.isPending());
                PanicInstrumentedFixture.write(artifact, new byte[]{1});
                assertTrue(new PanicWipeJournal(context, name).isPending());
                journal.clearPending();
                assertFalse(journal.isPending());
            }
            journal.markPending();
            assertTrue(new PanicWipeJournal(context, name).isPending());
        } finally { journal.clearPending(); }
    }

    @Test public void testStorageNamesCannotSelectProductionOrEscapeDirectories() throws Exception {
        Context context = context();
        try { PanicWipeTargets.Names.forTests("safekey_"); fail("Unsafe test profile."); }
        catch (IllegalArgumentException expected) { }
        try { new PanicPasswordStore(context, "../panic.enc"); fail("Unsafe proof name."); }
        catch (IllegalArgumentException expected) { }
        try { new PanicWipeJournal(context, "../wipe.pending"); fail("Unsafe marker name."); }
        catch (IllegalArgumentException expected) { }
    }
}

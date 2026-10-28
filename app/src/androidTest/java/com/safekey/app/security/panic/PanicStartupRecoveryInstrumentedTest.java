package com.safekey.app.security.panic;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;

/** Real marker/targets and the production shutdown adapter, with isolated names only. */
@RunWith(AndroidJUnit4.class)
public class PanicStartupRecoveryInstrumentedTest {
    private static final class Fixture implements AutoCloseable {
        final Context context = InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
        final String prefix = "safekey_panic_test_"
                + UUID.randomUUID().toString().replace("-", "") + "_";
        final PanicWipeTargets.Names names = PanicWipeTargets.Names.forTests(prefix);
        final PanicWipeJournal journal = new PanicWipeJournal(context, names.journalFile);
        final PanicRuntimeScope oldScope = new PanicRuntimeScope();
        final Handler main = new Handler(Looper.getMainLooper());
        final ExecutorService worker = Executors.newSingleThreadExecutor();
        final List<PanicWipeCoordinator.Target> targets = PanicWipeTargets.create(context, names);
        final AtomicBoolean uiCleared = new AtomicBoolean();
        final AtomicBoolean initialized = new AtomicBoolean();
        final CountDownLatch terminal = new CountDownLatch(1);
        PanicRuntimeScope freshScope;
        boolean failDelete;
        PanicStartupGate startup;

        Fixture() throws Exception {
            for (String database : names.databases) {
                File base = context.getDatabasePath(database);
                for (String suffix : new String[]{"", "-wal", "-shm", "-journal"}) {
                    PanicInstrumentedFixture.write(new File(base.getPath() + suffix), new byte[]{1, 2});
                }
            }
            for (String preference : names.preferences) {
                assertTrue(context.getSharedPreferences(preference, Context.MODE_PRIVATE)
                        .edit().putString("sentinel", "owned").commit());
            }
            for (String alias : names.aliases) { PanicInstrumentedFixture.generateKey(alias); }
            for (String file : new String[]{names.totpFile, names.panicFile}) {
                for (File artifact : PanicFiles.atomicArtifacts(new File(context.getNoBackupFilesDir(), file))) {
                    PanicInstrumentedFixture.write(artifact, new byte[]{3, 4});
                }
            }
        }

        void start() {
            PanicAndroidRuntime runtime = new PanicAndroidRuntime(oldScope, main, () -> {
                assertSame(Looper.getMainLooper(), Looper.myLooper());
                uiCleared.set(true);
            });
            List<PanicWipeCoordinator.Target> plan = new ArrayList<>(targets);
            if (failDelete) {
                plan.add(new PanicWipeCoordinator.Target() {
                    @Override public String name() { return "injected failure"; }
                    @Override public void erase() throws IOException { throw new IOException("injected"); }
                    @Override public void verifyAbsent() { }
                });
            }
            PanicWipeCoordinator wipe = new PanicWipeCoordinator(oldScope.getWorkGate(), journal, runtime, plan);
            startup = new PanicStartupGate(new PanicStartupGate.Recovery() {
                @Override public boolean isPending() throws Exception { return journal.isPending(); }
                @Override public void recover() throws Exception {
                    assertNotSame(Looper.getMainLooper(), Looper.myLooper());
                    assertTrue(wipe.resumeIfPending());
                }
            }, new PanicStartupGate.Runtime() {
                @Override public void block() { oldScope.getWorkGate().blockNewWork(); }
                @Override public void initialize(boolean recovered) throws Exception {
                    assertSame(Looper.getMainLooper(), Looper.myLooper());
                    if (recovered) {
                        assertTrue(uiCleared.get());
                        assertTrue(oldScope.areResourcesClosed());
                        assertFalse(journal.isPending());
                        for (PanicWipeCoordinator.Target target : targets) { target.verifyAbsent(); }
                        freshScope = new PanicRuntimeScope();
                    }
                    initialized.set(true);
                }
            }, worker, action -> {
                if (!main.post(action)) { throw new IllegalStateException("UI dispatcher unavailable."); }
            });
            startup.observe(() -> {
                if (startup.getState() == PanicStartupGate.State.READY
                        || startup.getState() == PanicStartupGate.State.FAILED) { terminal.countDown(); }
            });
            InstrumentationRegistry.getInstrumentation().runOnMainSync(startup::start);
        }

        void awaitTerminal() throws InterruptedException {
            assertTrue("Startup did not reach a terminal state", terminal.await(15, TimeUnit.SECONDS));
        }

        @Override public void close() throws Exception {
            worker.shutdownNow();
            assertTrue(worker.awaitTermination(20, TimeUnit.SECONDS));
            for (PanicWipeCoordinator.Target target : targets) { target.erase(); }
            for (PanicWipeCoordinator.Target target : targets) { target.verifyAbsent(); }
            journal.clearPending();
        }
    }

    @Test public void noMarkerPreservesOwnedFilesAndDoesNotStopRuntime() throws Exception {
        try (Fixture f = new Fixture()) {
            f.start(); f.awaitTerminal();
            assertEquals(PanicStartupGate.State.READY, f.startup.getState());
            assertTrue(f.initialized.get());
            assertFalse(f.oldScope.isStopped());
            assertFalse(f.uiCleared.get());
            assertFalse(f.startup.wasRecovered());
            for (String database : f.names.databases) { assertTrue(f.context.getDatabasePath(database).isFile()); }
            for (String alias : f.names.aliases) { assertTrue(PanicInstrumentedFixture.keyStore().containsAlias(alias)); }
        }
    }

    @Test public void pendingCleanupFinishesBeforeFreshRuntimeIsAllowed() throws Exception {
        try (Fixture f = new Fixture()) {
            f.journal.markPending(); f.start(); f.awaitTerminal();
            assertEquals(PanicStartupGate.State.READY, f.startup.getState());
            assertTrue(f.initialized.get());
            assertTrue(f.startup.wasRecovered());
            assertTrue(f.oldScope.isStopped());
            assertNotNull(f.freshScope);
            assertFalse(f.freshScope.isStopped());
            assertFalse(f.journal.isPending());
        }
    }

    @Test public void partialMarkerAuthorizesRecoveryWithoutAnotherPassword() throws Exception {
        try (Fixture f = new Fixture()) {
            PanicInstrumentedFixture.write(new File(f.context.getNoBackupFilesDir(),
                    f.names.journalFile + ".new"), new byte[]{9});
            f.start(); f.awaitTerminal();
            assertEquals(PanicStartupGate.State.READY, f.startup.getState());
            assertTrue(f.startup.wasRecovered());
            assertFalse(f.journal.isPending());
        }
    }

    @Test public void incompleteCleanupKeepsMarkerAndPreventsFreshRuntime() throws Exception {
        try (Fixture f = new Fixture()) {
            f.journal.markPending(); f.failDelete = true; f.start(); f.awaitTerminal();
            assertEquals(PanicStartupGate.State.FAILED, f.startup.getState());
            assertFalse(f.initialized.get());
            assertNull(f.freshScope);
            assertTrue(f.oldScope.isStopped());
            assertTrue(f.journal.isPending());
        }
    }
}

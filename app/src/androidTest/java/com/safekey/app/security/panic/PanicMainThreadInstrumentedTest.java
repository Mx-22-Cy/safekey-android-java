package com.safekey.app.security.panic;

import android.os.Handler;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PanicMainThreadInstrumentedTest {
    @Test public void interruptedQueuedCommitCannotRunLater() throws Exception {
        Handler main = new Handler(Looper.getMainLooper());
        CountDownLatch mainEntered = new CountDownLatch(1);
        CountDownLatch releaseMain = new CountDownLatch(1);
        CountDownLatch callerDone = new CountDownLatch(1);
        AtomicBoolean committed = new AtomicBoolean();
        AtomicBoolean interrupted = new AtomicBoolean();
        AtomicReference<Throwable> unexpected = new AtomicReference<>();
        assertTrue(main.post(() -> {
            mainEntered.countDown();
            try { assertTrue(releaseMain.await(10, TimeUnit.SECONDS)); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        }));
        Thread caller = new Thread(() -> {
            try { new PanicMainThread().call(() -> { committed.set(true); return null; }); }
            catch (InterruptedException expected) { interrupted.set(Thread.currentThread().isInterrupted()); }
            catch (Throwable error) { unexpected.set(error); }
            finally { callerDone.countDown(); }
        }, "panic-enrollment-queued-test");
        try {
            assertTrue(mainEntered.await(10, TimeUnit.SECONDS));
            caller.start();
            // Interrupting before await begins is also required to cancel a queued action.
            caller.interrupt();
            assertTrue(callerDone.await(10, TimeUnit.SECONDS));
        } finally {
            releaseMain.countDown();
            caller.join(10_000L);
            InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        }
        assertNull(unexpected.get()); assertTrue(interrupted.get());
        assertFalse(committed.get()); assertFalse(caller.isAlive());
    }

    @Test public void interruptedCallerWaitsUntilExecutingCommitActuallyFinishes() throws Exception {
        CountDownLatch commitEntered = new CountDownLatch(1);
        CountDownLatch releaseCommit = new CountDownLatch(1);
        CountDownLatch callerDone = new CountDownLatch(1);
        AtomicBoolean result = new AtomicBoolean();
        AtomicBoolean interruptRestored = new AtomicBoolean();
        AtomicReference<Throwable> unexpected = new AtomicReference<>();
        Thread caller = new Thread(() -> {
            try {
                result.set(new PanicMainThread().call(() -> {
                    commitEntered.countDown();
                    assertTrue(releaseCommit.await(10, TimeUnit.SECONDS));
                    return true;
                }));
                interruptRestored.set(Thread.currentThread().isInterrupted());
            } catch (Throwable error) { unexpected.set(error); }
            finally { callerDone.countDown(); }
        }, "panic-enrollment-running-test");
        try {
            caller.start();
            assertTrue(commitEntered.await(10, TimeUnit.SECONDS));
            caller.interrupt();
            assertFalse("Caller exited while its commit was still executing",
                    callerDone.await(100, TimeUnit.MILLISECONDS));
        } finally {
            releaseCommit.countDown();
            assertTrue(callerDone.await(10, TimeUnit.SECONDS));
            caller.join(10_000L);
        }
        assertNull(unexpected.get()); assertTrue(result.get());
        assertTrue(interruptRestored.get()); assertFalse(caller.isAlive());
    }
}

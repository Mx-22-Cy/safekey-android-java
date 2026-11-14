package com.safekey.app.security.panic;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class PanicTerminalHandoffTest {
    private static final class Fixture {
        final Object backend = new Object();
        volatile Object current = backend;
        volatile boolean stopped;
        volatile boolean completed;
        volatile boolean closed;
        final AtomicInteger restarts = new AtomicInteger();
        final AtomicInteger failures = new AtomicInteger();
        Exception lastError;
        Runnable afterWiped = () -> { };
        final PanicTerminalHandoff.Runtime<Object> runtime =
                new PanicTerminalHandoff.Runtime<Object>() {
                    @Override public boolean isCurrent(Object source) { return source == current; }
                    @Override public boolean isStopped() { return stopped; }
                    @Override public boolean wasWipeCompleted(Object source) { return completed; }
                    @Override public boolean areResourcesClosed() { return closed; }
                    @Override public void onWiped(Object source) {
                        restarts.incrementAndGet();
                        afterWiped.run();
                    }
                    @Override public void onFailed(Object source, Exception error) {
                        failures.incrementAndGet();
                        lastError = error;
                    }
                };
        final PanicTerminalHandoff<Object> owner = new PanicTerminalHandoff<>(backend, runtime);

        void completeWipe() { stopped = true; completed = true; closed = true; }
        void assertNoHandoff() { assertEquals(0, restarts.get()); assertEquals(0, failures.get()); }
    }

    @Test public void verifiedCompletionStartsFreshRuntimeOnlyOnce() {
        Fixture f = new Fixture(); f.completeWipe();
        assertTrue(f.owner.onPanicWiped(f.backend));
        assertFalse(f.owner.onPanicWiped(f.backend));
        assertEquals(1, f.restarts.get()); assertEquals(0, f.failures.get());
    }

    @Test public void committedFailureCanBeDeliveredBeforeResourcesClose() {
        Fixture f = new Fixture(); f.stopped = true;
        IOException error = new IOException("Recovery marker could not be saved.");
        assertTrue(f.owner.onPanicFailed(f.backend, error));
        assertSame(error, f.lastError);
        assertEquals(1, f.failures.get()); assertEquals(0, f.restarts.get());
        assertFalse(f.closed);
    }

    @Test public void staleRuntimeCannotRestartOrFailItsReplacement() {
        Fixture f = new Fixture(); f.completeWipe(); f.current = new Object();
        assertFalse(f.owner.onPanicWiped(f.backend));
        f.completed = false;
        assertFalse(f.owner.onPanicFailed(f.backend, new IOException()));
        f.assertNoHandoff();
    }

    @Test public void anotherBackendCannotUseThisOwner() {
        Fixture f = new Fixture(); f.completeWipe();
        Object other = new Object();
        assertFalse(f.owner.onPanicWiped(other));
        f.completed = false;
        assertFalse(f.owner.onPanicFailed(other, new IOException()));
        f.assertNoHandoff();
    }

    @Test public void prematureCompletionDoesNotConsumeTheVerifiedCompletion() {
        Fixture f = new Fixture(); f.stopped = true; f.closed = true;
        assertFalse(f.owner.onPanicWiped(f.backend));
        f.assertNoHandoff();
        f.completed = true;
        assertTrue(f.owner.onPanicWiped(f.backend));
        assertEquals(1, f.restarts.get());
    }

    @Test public void runningRuntimeCannotBeReinitializedByACompletionCallback() {
        Fixture f = new Fixture(); f.completed = true; f.closed = true;
        assertFalse(f.owner.onPanicWiped(f.backend));
        f.assertNoHandoff();
    }

    @Test public void completionWaitsForVerifiedResourceClosure() {
        Fixture f = new Fixture(); f.stopped = true; f.completed = true;
        assertFalse(f.owner.onPanicWiped(f.backend));
        f.assertNoHandoff();
        f.closed = true;
        assertTrue(f.owner.onPanicWiped(f.backend));
        assertEquals(1, f.restarts.get());
    }

    @Test public void ordinaryErrorOnAnActiveRuntimeIsNotTerminal() {
        Fixture f = new Fixture();
        assertFalse(f.owner.onPanicFailed(f.backend, new IOException("Authentication failed.")));
        f.assertNoHandoff();
    }

    @Test public void completedWipeCannotBeReclassifiedAsCleanupFailure() {
        Fixture f = new Fixture(); f.completeWipe();
        assertFalse(f.owner.onPanicFailed(f.backend, new IOException()));
        f.assertNoHandoff();
        assertTrue(f.owner.onPanicWiped(f.backend));
        assertEquals(1, f.restarts.get());
    }

    @Test public void failedRuntimeNeverRestartsFromALateDuplicateSuccess() {
        Fixture f = new Fixture(); f.stopped = true;
        assertTrue(f.owner.onPanicFailed(f.backend, new IOException()));
        assertFalse(f.owner.onPanicFailed(f.backend, new IOException()));
        f.completeWipe();
        assertFalse(f.owner.onPanicWiped(f.backend));
        assertEquals(1, f.failures.get()); assertEquals(0, f.restarts.get());
    }

    @Test public void replacementRuntimeGetsAnIndependentOwner() {
        Fixture f = new Fixture(); f.stopped = true;
        assertTrue(f.owner.onPanicFailed(f.backend, new IOException()));
        Object replacement = new Object();
        f.current = replacement; f.completeWipe();
        PanicTerminalHandoff<Object> replacementOwner =
                new PanicTerminalHandoff<>(replacement, f.runtime);
        assertFalse(f.owner.onPanicWiped(replacement));
        assertFalse(f.owner.onPanicWiped(f.backend));
        assertTrue(replacementOwner.onPanicWiped(replacement));
        assertEquals(1, f.restarts.get()); assertEquals(1, f.failures.get());
    }

    @Test public void reentrantCompletionCannotStartInitializationTwice() {
        Fixture f = new Fixture(); f.completeWipe();
        f.afterWiped = () -> assertFalse(f.owner.onPanicWiped(f.backend));
        assertTrue(f.owner.onPanicWiped(f.backend));
        assertEquals(1, f.restarts.get());
    }

    @Test public void concurrentDuplicateCompletionsHaveOneApplicationHandoff() throws Exception {
        Fixture f = new Fixture(); f.completeWipe();
        ExecutorService workers = Executors.newFixedThreadPool(8);
        CountDownLatch ready = new CountDownLatch(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int i = 0; i < 8; i++) {
                results.add(workers.submit(() -> {
                    ready.countDown();
                    if (!start.await(10, TimeUnit.SECONDS)) {
                        throw new AssertionError("Start was not released.");
                    }
                    return f.owner.onPanicWiped(f.backend);
                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            start.countDown();
            int accepted = 0;
            for (Future<Boolean> result : results) {
                if (result.get(10, TimeUnit.SECONDS)) { accepted++; }
            }
            assertEquals(1, accepted); assertEquals(1, f.restarts.get());
            assertEquals(0, f.failures.get());
        } finally {
            start.countDown(); workers.shutdownNow();
            assertTrue(workers.awaitTermination(10, TimeUnit.SECONDS));
        }
    }
}

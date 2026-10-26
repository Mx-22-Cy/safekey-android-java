package com.safekey.app.security.panic;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class PanicRuntimeScopeTest {
    @Test public void wipeCannotUseAnUnrelatedRuntimeGate() {
        PanicWorkGate declared = new PanicWorkGate();
        PanicWipeCoordinator.Runtime runtime = new PanicWipeCoordinator.Runtime() {
            @Override public PanicWorkGate getWorkGate() { return declared; }
            @Override public void lockAndClearSession() { fail("constructor must reject first"); }
            @Override public void closeResources() { fail("constructor must reject first"); }
            @Override public boolean areResourcesClosed() { return false; }
        };
        try {
            new PanicWipeCoordinator(new PanicWorkGate(), new PanicWipeCoordinator.Journal() {
                @Override public boolean isPending() { return false; }
                @Override public void markPending() { fail("constructor must reject first"); }
                @Override public void clearPending() { fail("constructor must reject first"); }
            }, runtime, java.util.Collections.singletonList(new PanicWipeCoordinator.Target() {
                @Override public String name() { return "test"; }
                @Override public void erase() { fail("constructor must reject first"); }
                @Override public void verifyAbsent() { fail("constructor must reject first"); }
            }));
            fail("unrelated runtime gate was accepted");
        } catch (IllegalArgumentException expected) { }
    }

    @Test public void blockingAloneCannotClaimThatPendingSecretsAreClosed() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        AtomicBoolean cleared = new AtomicBoolean();
        scope.onStop(() -> cleared.set(true));
        scope.getWorkGate().blockNewWork();
        assertFalse(scope.areResourcesClosed());
        try { scope.closeAndAwait(1_000L); fail("pending owner was not cancelled"); }
        catch (IllegalStateException expected) { }
        scope.cancelPending();
        scope.closeAndAwait(1_000L);
        assertTrue(cleared.get());
        assertTrue(scope.areResourcesClosed());
    }

    @Test public void queuedWorkRemainsOwnedUntilItsFinallyCompletes() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        List<Runnable> queue = new ArrayList<>();
        AtomicInteger ran = new AtomicInteger();
        scope.execute(queue::add, ran::incrementAndGet);
        scope.cancelPending();
        expectBusy(scope);
        assertFalse(scope.areResourcesClosed());
        queue.remove(0).run();
        idle(scope);
        assertEquals(1, ran.get());
        assertTrue(scope.areResourcesClosed());
    }

    @Test public void rejectedSubmissionReleasesOwnership() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        try {
            scope.execute(work -> { throw new RejectedExecutionException("test"); }, () -> {});
            fail("submission should fail");
        } catch (RejectedExecutionException expected) { }
        scope.cancelPending();
        idle(scope);
    }

    @Test public void failingInlineWorkAlsoReleasesOwnership() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        try {
            scope.execute(Runnable::run, () -> { throw new IllegalStateException("test"); });
            fail("work should fail");
        } catch (IllegalStateException expected) { }
        scope.cancelPending();
        idle(scope);
    }

    @Test public void stoppedRuntimeRejectsNewSubmission() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        AtomicBoolean called = new AtomicBoolean();
        scope.cancelPending();
        try {
            scope.execute(Runnable::run, () -> called.set(true));
            fail("stopped runtime accepted work");
        } catch (CancellationException expected) { }
        assertFalse(called.get());
        idle(scope);
    }

    @Test public void cancellingPromptClearsItsKeyAndReleasesItsOperation() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        byte[] key = {1, 2, 3};
        AtomicInteger cancelled = new AtomicInteger();
        PanicRuntimeScope.PendingOperation pending = scope.pending(
                () -> Arrays.fill(key, (byte) 0), cancelled::incrementAndGet);
        assertTrue(pending.isCurrent());
        scope.cancelPending();
        scope.cancelPending();
        pending.close();
        assertFalse(pending.isCurrent());
        assertArrayEquals(new byte[3], key);
        assertEquals(1, cancelled.get());
        idle(scope);
    }

    @Test public void completedPromptIsNotCancelledLater() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        AtomicInteger cleared = new AtomicInteger();
        AtomicInteger cancelled = new AtomicInteger();
        PanicRuntimeScope.PendingOperation pending = scope.pending(
                cleared::incrementAndGet, cancelled::incrementAndGet);
        pending.close();
        scope.cancelPending();
        assertEquals(1, cleared.get());
        assertEquals(0, cancelled.get());
        idle(scope);
    }

    @Test public void oneCancellationFailureDoesNotSkipOtherSecrets() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        AtomicBoolean cleared = new AtomicBoolean();
        scope.pending(() -> { throw new IllegalStateException("test"); }, () -> {});
        scope.pending(() -> cleared.set(true), () -> {});
        try { scope.cancelPending(); fail("failure should propagate"); }
        catch (IllegalStateException expected) { assertEquals(1, expected.getSuppressed().length); }
        assertTrue(cleared.get());
        idle(scope);
        assertFalse(scope.areResourcesClosed());
        try { scope.closeAndAwait(1_000L); fail("failed cancellation cannot authorize closure"); }
        catch (IllegalStateException expected) { }
    }

    @Test public void lateCancellationRegistrationRunsImmediately() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        AtomicInteger cancelled = new AtomicInteger();
        scope.cancelPending();
        scope.onStop(cancelled::incrementAndGet).close();
        scope.cancelPending();
        assertEquals(1, cancelled.get());
    }

    @Test public void resourceFailureStillAttemptsRemainingClosures() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        AtomicBoolean otherClosed = new AtomicBoolean();
        scope.registerResource(new PanicRuntimeScope.Resource() {
            @Override public void closeAndAwait(long deadline) throws Exception {
                throw new IOException("test close failure");
            }
            @Override public boolean isClosed() { return false; }
        });
        scope.registerResource(new PanicRuntimeScope.Resource() {
            @Override public void closeAndAwait(long deadline) { otherClosed.set(true); }
            @Override public boolean isClosed() { return otherClosed.get(); }
        });
        scope.cancelPending();
        try { scope.closeAndAwait(1_000L); fail("closure failure should propagate"); }
        catch (IOException expected) { assertTrue(expected.getSuppressed().length > 0); }
        assertTrue(otherClosed.get());
        assertFalse(scope.areResourcesClosed());
    }

    @Test public void shutdownWaitsForAcceptedWorkBeforeClosingItsResource() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean finished = new AtomicBoolean();
        AtomicBoolean closedAfterWork = new AtomicBoolean();
        scope.registerExecutor(worker);
        scope.registerResource(new PanicRuntimeScope.Resource() {
            @Override public void closeAndAwait(long deadline) { closedAfterWork.set(finished.get()); }
            @Override public boolean isClosed() { return closedAfterWork.get(); }
        });
        scope.execute(worker, () -> {
            entered.countDown();
            try {
                if (!release.await(10L, TimeUnit.SECONDS)) { throw new AssertionError("release timeout"); }
                finished.set(true);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError(interrupted);
            }
        });
        try {
            assertTrue(entered.await(10L, TimeUnit.SECONDS));
            scope.cancelPending();
            FutureTask<Void> close = new FutureTask<>(() -> { scope.closeAndAwait(10_000L); return null; });
            Thread closer = new Thread(close, "Panic-scope-test-close");
            closer.start();
            assertFalse(scope.areResourcesClosed());
            release.countDown();
            close.get(10L, TimeUnit.SECONDS);
            assertTrue(closedAfterWork.get());
            assertTrue(worker.isTerminated());
            assertTrue(scope.areResourcesClosed());
        } finally {
            release.countDown();
            worker.shutdown();
            assertTrue(worker.awaitTermination(10L, TimeUnit.SECONDS));
        }
    }

    private static void expectBusy(PanicRuntimeScope scope) throws Exception {
        try {
            scope.getWorkGate().awaitIdle(1L, TimeUnit.MILLISECONDS);
            fail("accepted task was released before it ran");
        } catch (TimeoutException expected) { }
    }

    private static void idle(PanicRuntimeScope scope) throws Exception {
        scope.getWorkGate().awaitIdle(1L, TimeUnit.SECONDS);
    }
}

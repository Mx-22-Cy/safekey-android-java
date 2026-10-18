package com.safekey.app.breach;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class PasswordBreachCoordinatorTest {

    private static final String PASSWORD_SUFFIX =
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static final String OTHER_SUFFIX =
            "00000000000000000000000000000000000";

    @Test
    public void check_breachedPassword_usesOnlyPrefixAndClearsCallerPassword()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        PASSWORD_SUFFIX + ":42\n"
                );

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        char[] password =
                "password".toCharArray();

        AtomicReference<PasswordBreachResult> result =
                new AtomicReference<>();

        CountDownLatch completed =
                new CountDownLatch(1);

        try {

            coordinator.check(
                    password,
                    breachResult -> {

                        result.set(
                                breachResult
                        );

                        completed.countDown();
                    }
            );

            assertTrue(
                    completed.await(
                            5,
                            TimeUnit.SECONDS
                    )
            );

            assertNotNull(
                    result.get()
            );

            assertEquals(
                    PasswordBreachResult.Status.BREACHED,
                    result.get().getStatus()
            );

            assertEquals(
                    42L,
                    result.get().getOccurrenceCount()
            );

            assertEquals(
                    PasswordBreachResult.ErrorReason.NONE,
                    result.get().getErrorReason()
            );

            assertEquals(
                    "5BAA6",
                    source.getLastHashPrefix()
            );

            assertEquals(
                    5,
                    source.getLastHashPrefix().length()
            );

            assertEquals(
                    1,
                    source.getRequestCount()
            );

            assertCleared(
                    password
            );

        } finally {

            coordinator.shutdown();
        }
    }

    @Test
    public void check_noMatchingSuffix_returnsNotFound()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        OTHER_SUFFIX + ":7\n"
                );

        PasswordBreachResult result =
                runCheck(
                        source,
                        "password".toCharArray()
                );

        assertEquals(
                PasswordBreachResult.Status.NOT_FOUND,
                result.getStatus()
        );

        assertEquals(
                0L,
                result.getOccurrenceCount()
        );

        assertEquals(
                PasswordBreachResult.ErrorReason.NONE,
                result.getErrorReason()
        );

        assertTrue(
                result.isChecked()
        );
    }

    @Test
    public void check_invalidResponse_returnsInvalidResponse()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        "NOT_A_VALID_HIBP_RESPONSE"
                );

        PasswordBreachResult result =
                runCheck(
                        source,
                        "password".toCharArray()
                );

        assertError(
                result,
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE
        );
    }

    @Test
    public void check_timeout_returnsTimeout()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.failure(
                        new SocketTimeoutException(
                                "timeout"
                        )
                );

        PasswordBreachResult result =
                runCheck(
                        source,
                        "password".toCharArray()
                );

        assertError(
                result,
                PasswordBreachResult.ErrorReason.TIMEOUT
        );
    }

    @Test
    public void check_httpFailure_returnsNetworkError()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.failure(
                        new HibpHttpException(
                                500
                        )
                );

        PasswordBreachResult result =
                runCheck(
                        source,
                        "password".toCharArray()
                );

        assertError(
                result,
                PasswordBreachResult.ErrorReason.NETWORK_ERROR
        );
    }

    @Test
    public void check_ioFailure_returnsNetworkError()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.failure(
                        new IOException(
                                "network unavailable"
                        )
                );

        PasswordBreachResult result =
                runCheck(
                        source,
                        "password".toCharArray()
                );

        assertError(
                result,
                PasswordBreachResult.ErrorReason.NETWORK_ERROR
        );
    }

    @Test
    public void check_invalidPassword_returnsInvalidInputWithoutRequest()
            throws Exception {

        TrackingHibpRangeSource source =
                new TrackingHibpRangeSource();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        AtomicReference<PasswordBreachResult> result =
                new AtomicReference<>();

        CountDownLatch completed =
                new CountDownLatch(1);

        try {

            coordinator.check(
                    new char[0],
                    breachResult -> {

                        result.set(
                                breachResult
                        );

                        completed.countDown();
                    }
            );

            assertTrue(
                    completed.await(
                            5,
                            TimeUnit.SECONDS
                    )
            );

            assertNotNull(
                    result.get()
            );

            assertError(
                    result.get(),
                    PasswordBreachResult.ErrorReason.INVALID_INPUT
            );

            assertEquals(
                    0,
                    source.getRequestCount()
            );

        } finally {

            coordinator.shutdown();
        }
    }

    /**
     * Regression:
     * cancellation after the HIBP request starts must
     * suppress a late successful callback.
     */
    @Test
    public void check_cancellation_suppressesLateSuccessCallback()
            throws Exception {

        DeferredHibpRangeSource source =
                new DeferredHibpRangeSource();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        AtomicInteger callbackCount =
                new AtomicInteger();

        char[] password =
                "password".toCharArray();

        try {

            PasswordBreachCoordinator.Request request =
                    coordinator.check(
                            password,
                            result -> callbackCount.incrementAndGet()
                    );

            assertTrue(
                    source.awaitRequest()
            );

            assertEquals(
                    "5BAA6",
                    source.getHashPrefix()
            );

            assertCleared(
                    password
            );

            request.close();

            assertTrue(
                    request.isClosed()
            );

            source.succeed(
                    PASSWORD_SUFFIX + ":5\n"
            );

            waitForWorkerIdle(
                    worker
            );

            assertEquals(
                    0,
                    callbackCount.get()
            );

        } finally {

            coordinator.shutdown();
        }
    }

    @Test
    public void check_repeatedCallback_secondResultIsNotChecked()
            throws Exception {

        DeferredHibpRangeSource source =
                new DeferredHibpRangeSource();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        AtomicReference<PasswordBreachResult> firstResult =
                new AtomicReference<>();

        AtomicReference<PasswordBreachResult> secondResult =
                new AtomicReference<>();

        CountDownLatch completed =
                new CountDownLatch(2);

        try {

            coordinator.check(
                    "password".toCharArray(),
                    breachResult -> {

                        if (firstResult.get() == null) {

                            firstResult.set(
                                    breachResult
                            );

                        } else {

                            secondResult.set(
                                    breachResult
                            );
                        }

                        completed.countDown();
                    }
            );

            assertTrue(
                    source.awaitRequest()
            );

            source.succeed(
                    PASSWORD_SUFFIX + ":9\n"
            );

            source.succeed(
                    OTHER_SUFFIX + ":1\n"
            );

            assertTrue(
                    completed.await(
                            5,
                            TimeUnit.SECONDS
                    )
            );

            assertNotNull(
                    firstResult.get()
            );

            assertNotNull(
                    secondResult.get()
            );

            assertEquals(
                    PasswordBreachResult.Status.BREACHED,
                    firstResult.get().getStatus()
            );

            assertEquals(
                    9L,
                    firstResult.get().getOccurrenceCount()
            );

            assertEquals(
                    PasswordBreachResult.Status.NOT_CHECKED,
                    secondResult.get().getStatus()
            );

        } finally {

            coordinator.shutdown();
        }
    }

    @Test
    public void shutdown_closesPendingRequest()
            throws Exception {

        DeferredHibpRangeSource source =
                new DeferredHibpRangeSource();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        PasswordBreachCoordinator.Request request =
                coordinator.check(
                        "password".toCharArray(),
                        result -> {
                            // No result expected before shutdown.
                        }
                );

        assertTrue(
                source.awaitRequest()
        );

        coordinator.shutdown();

        assertTrue(
                request.isClosed()
        );
    }

    /**
     * Regression requested by review:
     * closing a request while preparation is still queued
     * must clear the caller's password immediately.
     */
    @Test
    public void close_beforeQueuedPreparationStarts_clearsPassword()
            throws Exception {

        TrackingHibpRangeSource source =
                new TrackingHibpRangeSource();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        CountDownLatch blockerStarted =
                new CountDownLatch(1);

        CountDownLatch releaseBlocker =
                new CountDownLatch(1);

        blockWorker(
                worker,
                blockerStarted,
                releaseBlocker
        );

        assertTrue(
                blockerStarted.await(
                        5,
                        TimeUnit.SECONDS
                )
        );

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        char[] password =
                "password".toCharArray();

        AtomicInteger callbackCount =
                new AtomicInteger();

        try {

            PasswordBreachCoordinator.Request request =
                    coordinator.check(
                            password,
                            result -> callbackCount.incrementAndGet()
                    );

            /*
             * The only worker thread is blocked, so the
             * password preparation task cannot have started.
             */
            request.close();

            assertTrue(
                    request.isClosed()
            );

            /*
             * Password must already be cleared even though
             * preparation has never executed.
             */
            assertCleared(
                    password
            );

            releaseBlocker.countDown();

            waitForWorkerIdle(
                    worker
            );

            /*
             * The cancelled queued task must not reach HIBP.
             */
            assertEquals(
                    0,
                    source.getRequestCount()
            );

            assertEquals(
                    0,
                    callbackCount.get()
            );

        } finally {

            releaseBlocker.countDown();

            coordinator.shutdown();
        }
    }

    /**
     * Regression requested by review:
     * shutdown while preparation is still queued must
     * clear the password even when shutdownNow discards
     * the queued preparation task.
     */
    @Test
    public void shutdown_beforeQueuedPreparationStarts_clearsPassword()
            throws Exception {

        TrackingHibpRangeSource source =
                new TrackingHibpRangeSource();

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        CountDownLatch blockerStarted =
                new CountDownLatch(1);

        CountDownLatch releaseBlocker =
                new CountDownLatch(1);

        blockWorker(
                worker,
                blockerStarted,
                releaseBlocker
        );

        assertTrue(
                blockerStarted.await(
                        5,
                        TimeUnit.SECONDS
                )
        );

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        char[] password =
                "password".toCharArray();

        AtomicInteger callbackCount =
                new AtomicInteger();

        PasswordBreachCoordinator.Request request =
                coordinator.check(
                        password,
                        result -> callbackCount.incrementAndGet()
                );

        /*
         * Preparation is still queued behind the blocker.
         */
        coordinator.shutdown();

        assertTrue(
                request.isClosed()
        );

        assertCleared(
                password
        );

        assertTrue(
                worker.awaitTermination(
                        5,
                        TimeUnit.SECONDS
                )
        );

        assertEquals(
                0,
                source.getRequestCount()
        );

        assertEquals(
                0,
                callbackCount.get()
        );

        releaseBlocker.countDown();
    }

    /**
     * Regression requested by review:
     * closing a request after BREACHED has been calculated
     * but before its queued callback executes must suppress
     * that callback.
     */
    @Test
    public void close_afterResultQueued_suppressesDelivery()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        PASSWORD_SUFFIX + ":42\n"
                );

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        QueuedCallbackExecutor callbackExecutor =
                new QueuedCallbackExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        callbackExecutor
                );

        AtomicInteger callbackCount =
                new AtomicInteger();

        AtomicReference<PasswordBreachResult> deliveredResult =
                new AtomicReference<>();

        char[] password =
                "password".toCharArray();

        try {

            PasswordBreachCoordinator.Request request =
                    coordinator.check(
                            password,
                            result -> {

                                deliveredResult.set(
                                        result
                                );

                                callbackCount.incrementAndGet();
                            }
                    );

            /*
             * Wait until the BREACHED result has been
             * calculated and its delivery runnable has
             * actually been queued.
             */
            assertTrue(
                    callbackExecutor.awaitTask()
            );

            assertCleared(
                    password
            );

            request.close();

            /*
             * Execute the callback runnable only after
             * cancellation.
             */
            callbackExecutor.runQueuedTask();

            assertEquals(
                    0,
                    callbackCount.get()
            );

            assertEquals(
                    null,
                    deliveredResult.get()
            );

        } finally {

            coordinator.shutdown();
        }
    }

    /**
     * Regression requested by review:
     * coordinator shutdown after BREACHED has been
     * calculated but before callback execution must
     * suppress that queued result.
     */
    @Test
    public void shutdown_afterResultQueued_suppressesDelivery()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        PASSWORD_SUFFIX + ":42\n"
                );

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        QueuedCallbackExecutor callbackExecutor =
                new QueuedCallbackExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        callbackExecutor
                );

        AtomicInteger callbackCount =
                new AtomicInteger();

        AtomicReference<PasswordBreachResult> deliveredResult =
                new AtomicReference<>();

        char[] password =
                "password".toCharArray();

        coordinator.check(
                password,
                result -> {

                    deliveredResult.set(
                            result
                    );

                    callbackCount.incrementAndGet();
                }
        );

        /*
         * A result exists, but delivery has not executed.
         */
        assertTrue(
                callbackExecutor.awaitTask()
        );

        assertCleared(
                password
        );

        /*
         * shutdown() must still know about this request
         * while its callback is waiting.
         */
        coordinator.shutdown();

        callbackExecutor.runQueuedTask();

        assertEquals(
                0,
                callbackCount.get()
        );

        assertEquals(
                null,
                deliveredResult.get()
        );
    }

    /**
     * Regression requested by review:
     * a check that overlaps with shutdown must not escape
     * the shutdown request snapshot.
     *
     * Once shutdown has started, the overlapping request
     * must be rejected, its password must be cleared
     * immediately, and it must never reach HIBP.
     */
    @Test
    public void check_overlappingShutdown_clearsPasswordAndRejectsRequest()
            throws Exception {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        PASSWORD_SUFFIX + ":42\n"
                );

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        CountDownLatch firstCallbackStarted =
                new CountDownLatch(1);

        CountDownLatch releaseFirstCallback =
                new CountDownLatch(1);

        AtomicInteger overlappingCallbackCount =
                new AtomicInteger();

        char[] firstPassword =
                "password".toCharArray();

        char[] overlappingPassword =
                "second-password".toCharArray();

        Thread shutdownThread =
                null;

        try {

            /*
             * The first request completes its breach result,
             * but the callback stays blocked while holding
             * the Request monitor.
             *
             * This gives shutdown() a deterministic place
             * to pause after shutdown has begun.
             */
            coordinator.check(
                    firstPassword,
                    result -> {

                        firstCallbackStarted.countDown();

                        try {

                            releaseFirstCallback.await();

                        } catch (InterruptedException exception) {

                            Thread.currentThread().interrupt();
                        }
                    }
            );

            assertTrue(
                    firstCallbackStarted.await(
                            5,
                            TimeUnit.SECONDS
                    )
            );

            assertCleared(
                    firstPassword
            );

            assertEquals(
                    1,
                    source.getRequestCount()
            );

            /*
             * Start shutdown on another thread.
             *
             * shutdown() sets the shutdown state before
             * trying to close the existing request.
             */
            shutdownThread =
                    new Thread(
                            coordinator::shutdown
                    );

            shutdownThread.start();

            /*
             * The first callback is still holding the
             * Request monitor, so shutdown should block
             * while closing that existing request.
             *
             * At this point shutdown has already started.
             */
            long deadline =
                    System.nanoTime()
                            + TimeUnit.SECONDS.toNanos(
                            5
                    );

            while (shutdownThread.getState()
                    != Thread.State.BLOCKED
                    && System.nanoTime()
                    < deadline) {

                Thread.yield();
            }

            assertEquals(
                    Thread.State.BLOCKED,
                    shutdownThread.getState()
            );

            /*
             * This check overlaps an already-started
             * shutdown.
             *
             * It must be rejected immediately and its
             * caller-owned password must be cleared.
             */
            PasswordBreachCoordinator.Request overlappingRequest =
                    coordinator.check(
                            overlappingPassword,
                            result ->
                                    overlappingCallbackCount
                                            .incrementAndGet()
                    );

            assertTrue(
                    overlappingRequest.isClosed()
            );

            assertCleared(
                    overlappingPassword
            );

            /*
             * Only the original request may have reached
             * the HIBP source.
             */
            assertEquals(
                    1,
                    source.getRequestCount()
            );

            assertEquals(
                    0,
                    overlappingCallbackCount.get()
            );

            /*
             * Allow the first callback to finish so
             * shutdown can complete.
             */
            releaseFirstCallback.countDown();

            shutdownThread.join(
                    5_000
            );

            assertFalse(
                    shutdownThread.isAlive()
            );

            assertTrue(
                    worker.awaitTermination(
                            5,
                            TimeUnit.SECONDS
                    )
            );

            assertEquals(
                    1,
                    source.getRequestCount()
            );

            assertEquals(
                    0,
                    overlappingCallbackCount.get()
            );

        } finally {

            /*
             * Prevent a failed assertion from leaving the
             * worker or shutdown thread blocked.
             */
            releaseFirstCallback.countDown();

            if (shutdownThread != null) {

                shutdownThread.join(
                        5_000
                );
            }

            coordinator.shutdown();
        }
    }

    private static PasswordBreachResult runCheck(
            HibpRangeSource source,
            char[] password
    ) throws Exception {

        ExecutorService worker =
                Executors.newSingleThreadExecutor();

        PasswordBreachCoordinator coordinator =
                new PasswordBreachCoordinator(
                        source,
                        worker,
                        Runnable::run
                );

        AtomicReference<PasswordBreachResult> result =
                new AtomicReference<>();

        CountDownLatch completed =
                new CountDownLatch(1);

        try {

            coordinator.check(
                    password,
                    breachResult -> {

                        result.set(
                                breachResult
                        );

                        completed.countDown();
                    }
            );

            assertTrue(
                    completed.await(
                            5,
                            TimeUnit.SECONDS
                    )
            );

            assertNotNull(
                    result.get()
            );

            assertCleared(
                    password
            );

            return result.get();

        } finally {

            coordinator.shutdown();
        }
    }

    private static void assertError(
            PasswordBreachResult result,
            PasswordBreachResult.ErrorReason expectedReason
    ) {

        assertEquals(
                PasswordBreachResult.Status.ERROR,
                result.getStatus()
        );

        assertEquals(
                expectedReason,
                result.getErrorReason()
        );

        assertEquals(
                0L,
                result.getOccurrenceCount()
        );

        assertFalse(
                result.isChecked()
        );
    }

    private static void assertCleared(
            char[] password
    ) {

        char[] expected =
                new char[password.length];

        Arrays.fill(
                expected,
                '\0'
        );

        assertTrue(
                Arrays.equals(
                        expected,
                        password
                )
        );
    }

    /**
     * Places a blocking task at the front of a
     * single-thread executor so later preparation work
     * remains queued.
     */
    private static void blockWorker(
            ExecutorService worker,
            CountDownLatch blockerStarted,
            CountDownLatch releaseBlocker
    ) {

        worker.execute(
                () -> {

                    blockerStarted.countDown();

                    try {

                        releaseBlocker.await();

                    } catch (InterruptedException exception) {

                        Thread.currentThread().interrupt();
                    }
                }
        );
    }

    /**
     * Waits until all worker tasks submitted before this
     * method have completed.
     */
    private static void waitForWorkerIdle(
            ExecutorService worker
    ) throws Exception {

        worker.submit(
                () -> {
                    // Queue barrier.
                }
        ).get(
                5,
                TimeUnit.SECONDS
        );
    }

    /**
     * Source used to verify that cancelled or invalid
     * local work never reaches the HIBP boundary.
     */
    private static final class TrackingHibpRangeSource
            implements HibpRangeSource {

        private int requestCount;

        @Override
        public synchronized void fetchRange(
                String hashPrefix,
                Callback callback
        ) {

            requestCount++;
        }

        private synchronized int getRequestCount() {

            return requestCount;
        }
    }

    /**
     * Source that stores its callback so tests can
     * simulate delayed or repeated network responses.
     */
    private static final class DeferredHibpRangeSource
            implements HibpRangeSource {

        private final CountDownLatch requested =
                new CountDownLatch(1);

        private Callback callback;
        private String hashPrefix;

        @Override
        public synchronized void fetchRange(
                String hashPrefix,
                Callback callback
        ) {

            this.hashPrefix =
                    hashPrefix;

            this.callback =
                    callback;

            requested.countDown();
        }

        private boolean awaitRequest()
                throws InterruptedException {

            return requested.await(
                    5,
                    TimeUnit.SECONDS
            );
        }

        private synchronized String getHashPrefix() {

            return hashPrefix;
        }

        private void succeed(
                String responseBody
        ) {

            Callback savedCallback;

            synchronized (this) {

                savedCallback =
                        callback;
            }

            if (savedCallback != null) {

                savedCallback.onSuccess(
                        responseBody
                );
            }
        }
    }

    /**
     * Callback executor controlled by the test.
     *
     * execute() stores the callback instead of running it.
     * The test can then cancel/shutdown before explicitly
     * executing the queued callback.
     */
    private static final class QueuedCallbackExecutor
            implements Executor {

        private final CountDownLatch taskQueued =
                new CountDownLatch(1);

        private final AtomicReference<Runnable> queuedTask =
                new AtomicReference<>();

        @Override
        public void execute(
                Runnable command
        ) {

            Objects.requireNonNull(
                    command,
                    "command"
            );

            if (!queuedTask.compareAndSet(
                    null,
                    command
            )) {

                throw new IllegalStateException(
                        "Only one queued callback is expected."
                );
            }

            taskQueued.countDown();
        }

        private boolean awaitTask()
                throws InterruptedException {

            return taskQueued.await(
                    5,
                    TimeUnit.SECONDS
            );
        }

        private void runQueuedTask() {

            Runnable command =
                    queuedTask.getAndSet(
                            null
                    );

            assertNotNull(
                    command
            );

            command.run();
        }
    }
}

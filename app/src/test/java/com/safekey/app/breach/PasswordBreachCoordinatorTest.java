package com.safekey.app.breach;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
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

            /*
             * Only the first five hexadecimal SHA-1
             * characters reached the HIBP source.
             */
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

    @Test
    public void check_cancellation_discardsLateSuccessAsNotChecked()
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

        AtomicReference<PasswordBreachResult> result =
                new AtomicReference<>();

        CountDownLatch completed =
                new CountDownLatch(1);

        char[] password =
                "password".toCharArray();

        try {

            PasswordBreachCoordinator.Request request =
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
                    PasswordBreachResult.Status.NOT_CHECKED,
                    result.get().getStatus()
            );

            assertFalse(
                    result.get().isChecked()
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
     * Source used to verify that invalid local input
     * never reaches the network boundary.
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
     * Source that stores the callback so tests can simulate
     * delayed or repeated network responses.
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
}

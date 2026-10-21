package com.safekey.app.security.totp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class TotpVerificationServiceTest {

    // Public RFC data, never a production enrollment secret.
    private static final byte[] TEST_SECRET =
            "12345678901234567890"
                    .getBytes(StandardCharsets.US_ASCII);

    private MemoryData data;
    private AtomicLong timeMillis;
    private TotpVerificationService service;

    @Before
    public void setUp() {
        data = new MemoryData();
        timeMillis = new AtomicLong(59_000L);

        try (TotpState initial =
                     new TotpState(TEST_SECRET, -1L, 0, 0L)) {
            data.encoded = initial.encode();
        }

        service = newService();
    }

    @After
    public void tearDown() {
        synchronized (data.lock) {
            if (data.encoded != null) {
                Arrays.fill(data.encoded, (byte) 0);
            }
        }
    }

    @Test
    public void validCode_persistsAcceptedStepBeforeSuccess()
            throws Exception {
        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify("287082").getStatus()
        );

        assertState(1L, 0, 0L);
        assertEquals(1, data.saveCalls);
    }

    @Test
    public void sameCode_cannotBeUsedTwice()
            throws Exception {
        verify("287082");

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify("287082").getStatus()
        );

        assertState(1L, 1, 0L);
    }

    @Test
    public void newServiceAndAdapter_stillRejectReplay()
            throws Exception {
        verify("287082");
        service = newService();

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify("287082").getStatus()
        );
    }

    @Test
    public void movingClockBack_doesNotUndoReplayState()
            throws Exception {
        verify("287082");
        timeMillis.set(0L);

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify("755224").getStatus()
        );

        assertState(1L, 1, 0L);
    }

    @Test
    public void failures_surviveServiceAndAdapterRecreation()
            throws Exception {
        verify("000000");
        verify("000000");

        service = newService();

        verify("000000");
        verify("000000");

        assertEquals(
                TotpVerificationService.Status.RETRY_LATER,
                verify("000000").getStatus()
        );

        assertState(-1L, 5, 89_000L);
    }

    @Test
    public void fifthFailure_startsThirtySecondCooldown()
            throws Exception {
        for (int attempt = 1; attempt < 5; attempt++) {
            assertEquals(
                    TotpVerificationService.Status.INVALID_CODE,
                    verify("000000").getStatus()
            );
        }

        TotpVerificationService.Result result =
                verify("000000");

        assertEquals(
                TotpVerificationService.Status.RETRY_LATER,
                result.getStatus()
        );

        assertEquals(30_000L, result.getRetryAfterMillis());
    }

    @Test
    public void validCodeDuringCooldown_isNotAccepted()
            throws Exception {
        reachCooldown();

        assertEquals(
                TotpVerificationService.Status.RETRY_LATER,
                verify("287082").getStatus()
        );

        assertState(-1L, 5, 89_000L);
    }

    @Test
    public void blockedRequests_doNotExtendDeadlineOrIncreaseFailures()
            throws Exception {
        reachCooldown();
        timeMillis.set(60_000L);

        TotpVerificationService.Result result =
                verify("000000");

        assertEquals(29_000L, result.getRetryAfterMillis());
        assertEquals(5, data.saveCalls);
        assertState(-1L, 5, 89_000L);
    }

    @Test
    public void cooldownExpiry_allowsValidCodeAndResetsFailures()
            throws Exception {
        reachCooldown();
        timeMillis.set(89_000L);

        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify("359152").getStatus()
        );

        assertState(2L, 0, 0L);
    }

    @Test
    public void failureAfterCooldown_startsNewAttemptBatch()
            throws Exception {
        reachCooldown();
        timeMillis.set(89_000L);

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify("000000").getStatus()
        );

        assertState(-1L, 1, 0L);
    }

    @Test
    public void successBeforeLimit_resetsPreviousFailures()
            throws Exception {
        verify("000000");
        verify("000000");
        verify("287082");

        assertState(1L, 0, 0L);
    }

    @Test
    public void malformedCode_countsAsFailure()
            throws Exception {
        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify("12A456").getStatus()
        );

        assertState(-1L, 1, 0L);
    }

    @Test
    public void nullCode_countsAsFailure()
            throws Exception {
        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                service.verify(null).getStatus()
        );

        assertState(-1L, 1, 0L);
    }

    @Test
    public void oversizedCode_isRejectedWithoutChangingCaller()
            throws Exception {
        char[] code = "1234567890".toCharArray();
        char[] original = code.clone();

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                service.verify(code).getStatus()
        );

        assertArrayEquals(original, code);
        assertState(-1L, 1, 0L);
    }

    @Test
    public void absentConfiguration_doesNotReportVerifiedOrCreateState()
            throws Exception {
        Arrays.fill(data.encoded, (byte) 0);
        data.encoded = null;

        assertEquals(
                TotpVerificationService.Status.NOT_CONFIGURED,
                verify("287082").getStatus()
        );

        assertEquals(0, data.saveCalls);
    }

    @Test
    public void acceptedCodeSaveFailure_isPropagated()
            throws Exception {
        data.failSaves = true;

        try {
            verify("287082");
            fail("Success must not be returned when persistence fails.");
        } catch (IOException expected) {
            assertState(-1L, 0, 0L);
        }

        data.failSaves = false;

        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify("287082").getStatus()
        );
    }

    @Test
    public void rejectedCodeSaveFailure_isPropagated()
            throws Exception {
        data.failSaves = true;

        try {
            verify("000000");
            fail("Attempt-state persistence failures must be surfaced.");
        } catch (IOException expected) {
            assertEquals(0, data.saveCalls);
        }
    }

    @Test
    public void concurrentRequests_canAcceptSameCodeOnlyOnce()
            throws Exception {
        ExecutorService workers =
                Executors.newFixedThreadPool(2);

        CountDownLatch start = new CountDownLatch(1);

        try {
            Future<TotpVerificationService.Status> first =
                    workers.submit(() -> {
                        start.await();

                        return newService()
                                .verify("287082".toCharArray())
                                .getStatus();
                    });

            Future<TotpVerificationService.Status> second =
                    workers.submit(() -> {
                        start.await();

                        return newService()
                                .verify("287082".toCharArray())
                                .getStatus();
                    });

            start.countDown();

            TotpVerificationService.Status a =
                    first.get(10, TimeUnit.SECONDS);

            TotpVerificationService.Status b =
                    second.get(10, TimeUnit.SECONDS);

            assertEquals(1, verifiedCount(a, b));
            assertState(1L, 1, 0L);
        } finally {
            workers.shutdownNow();
        }
    }

    @Test
    public void callerCode_isUnchangedAfterSuccessAndFailure()
            throws Exception {
        char[] valid = "287082".toCharArray();
        char[] invalid = "000000".toCharArray();

        char[] originalValid = valid.clone();
        char[] originalInvalid = invalid.clone();

        service.verify(valid);
        service.verify(invalid);

        assertArrayEquals(originalValid, valid);
        assertArrayEquals(originalInvalid, invalid);
    }

    @Test(expected = IllegalStateException.class)
    public void negativeClock_isRejected()
            throws Exception {
        timeMillis.set(-1L);
        verify("287082");
    }

    @Test(expected = IllegalStateException.class)
    public void overflowingClock_isRejected()
            throws Exception {
        timeMillis.set(Long.MAX_VALUE);
        verify("287082");
    }

    @Test
    public void readFailure_isPropagated()
            throws Exception {
        data.failLoads = true;

        try {
            verify("287082");
            fail("Unreadable state must not be treated as disabled TOTP.");
        } catch (IOException expected) {
            assertEquals(0, data.saveCalls);
        }
    }

    private TotpVerificationService newService() {
        return new TotpVerificationService(
                new MemoryStore(data),
                timeMillis::get
        );
    }

    private TotpVerificationService.Result verify(String code)
            throws Exception {
        return service.verify(code.toCharArray());
    }

    private void reachCooldown() throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            verify("000000");
        }
    }

    private void assertState(
            long step,
            int failures,
            long blockedUntil
    ) {
        synchronized (data.lock) {
            try (TotpState state =
                         TotpState.decode(data.encoded)) {
                assertEquals(step, state.getLastAcceptedStep());
                assertEquals(failures, state.getFailedAttempts());

                assertEquals(
                        blockedUntil,
                        state.getBlockedUntilEpochMillis()
                );
            }
        }
    }

    private static int verifiedCount(
            TotpVerificationService.Status first,
            TotpVerificationService.Status second
    ) {
        return (first == TotpVerificationService.Status.VERIFIED
                ? 1 : 0)
                + (second == TotpVerificationService.Status.VERIFIED
                ? 1 : 0);
    }

    private static final class MemoryData {

        final Object lock = new Object();

        byte[] encoded;
        int saveCalls;
        boolean failLoads;
        boolean failSaves;
    }

    private static final class MemoryStore
            implements TotpVerificationService.StateStore {

        private final MemoryData data;

        MemoryStore(MemoryData data) {
            this.data = data;
        }

        @Override
        public Object getTransactionLock() {
            return data.lock;
        }

        @Override
        public TotpState load() throws IOException {
            requireTransactionLock();

            if (data.failLoads) {
                throw new IOException("Simulated read failure.");
            }

            return data.encoded == null
                    ? null
                    : TotpState.decode(data.encoded);
        }

        @Override
        public void save(TotpState state) throws IOException {
            requireTransactionLock();

            if (data.failSaves) {
                throw new IOException("Simulated save failure.");
            }

            byte[] next = state.encode();

            if (data.encoded != null) {
                Arrays.fill(data.encoded, (byte) 0);
            }

            data.encoded = next;
            data.saveCalls++;
        }

        private void requireTransactionLock() {
            if (!Thread.holdsLock(data.lock)) {
                throw new AssertionError(
                        "The full transaction must hold the shared lock."
                );
            }
        }
    }
}

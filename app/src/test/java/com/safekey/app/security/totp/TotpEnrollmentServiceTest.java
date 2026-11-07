package com.safekey.app.security.totp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class TotpEnrollmentServiceTest {

    // Public RFC data; injected only into tests.
    private static final byte[] TEST_SECRET =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final String BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    private MemoryStore store;
    private AtomicLong wall;
    private AtomicLong elapsed;
    private TotpEnrollmentService service;

    @Before
    public void setUp() {
        store = new MemoryStore();
        wall = new AtomicLong(59_000L);
        elapsed = new AtomicLong(0L);
        service = newService(new FixedRandom(TEST_SECRET));
    }

    @After
    public void tearDown() {
        if (store.encoded != null) {
            Arrays.fill(store.encoded, (byte) 0);
        }
    }

    @Test
    public void manualKey_matchesKnownBase32Value() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            char[] key = pending.copyBase32Secret();
            try {
                assertArrayEquals(BASE32.toCharArray(), key);
            } finally {
                Arrays.fill(key, '\0');
            }
        }
    }

    @Test
    public void countdownAndDeadlineUseTheOriginalMonotonicClock() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            assertEquals(300_000L, pending.getRemainingMillis());
            assertEquals(300_000L, pending.getExpiresAtMonotonicMillis());
            wall.set(9_999_999_999L);
            elapsed.set(123_456L);
            assertEquals(176_544L, pending.getRemainingMillis());
            assertEquals(300_000L, pending.getExpiresAtMonotonicMillis());
        }
    }

    @Test
    public void remainingTimeAtExpiryClosesTheSecret() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            elapsed.set(300_000L);
            assertEquals(0L, pending.getRemainingMillis());
            assertFalse(pending.isActive());
            try {
                pending.copyBase32Secret();
                fail("Expired setup exposed a manual key.");
            } catch (IllegalStateException expected) {
                assertEquals(0L, pending.getRemainingMillis());
            }
        }
    }

    @Test
    public void cancelledSetupHasZeroRemainingTime() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            pending.close();
            assertEquals(0L, pending.getRemainingMillis());
        }
    }

    @Test
    public void backwardsClockProducesZeroRemainingTime() throws Exception {
        elapsed.set(100L);
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            elapsed.set(99L);
            assertEquals(0L, pending.getRemainingMillis());
            assertFalse(pending.isActive());
        }
    }

    @Test
    public void unrepresentableDeadlineClosesSetup() throws Exception {
        elapsed.set(Long.MAX_VALUE - 100_000L);
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            try {
                pending.getExpiresAtMonotonicMillis();
                fail("An overflowing deadline was accepted.");
            } catch (IllegalStateException expected) {
                assertFalse(pending.isActive());
                assertNull(store.encoded);
            }
        }
    }

    @Test
    public void uri_containsMatchingIssuerAndDefaultParameters() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            assertEquals(
                    "otpauth://totp/SafeKey:Vault?secret=" + BASE32
                            + "&issuer=SafeKey&algorithm=SHA1&digits=6&period=30",
                    pending.getAuthenticatorUri()
            );
        }
    }

    @Test
    public void begin_doesNotPersistUnconfirmedSecret() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            assertTrue(pending.isActive());
            assertEquals(5, pending.getRemainingAttempts());
            assertNull(store.encoded);
            assertEquals(0, store.saves);
        }
    }

    @Test
    public void productionRandom_createsDifferentSetupKeys() throws Exception {
        TotpEnrollmentService production = new TotpEnrollmentService(store);
        try (TotpEnrollmentService.PendingSetup first = production.begin();
             TotpEnrollmentService.PendingSetup second = production.begin()) {
            char[] a = first.copyBase32Secret();
            char[] b = second.copyBase32Secret();
            try {
                assertEquals(32, a.length);
                assertEquals(32, b.length);
                assertFalse(Arrays.equals(a, b));
            } finally {
                Arrays.fill(a, '\0');
                Arrays.fill(b, '\0');
            }
        }
    }

    @Test
    public void cancelledSetup_cannotEnableTotp() throws Exception {
        TotpEnrollmentService.PendingSetup pending = service.begin();
        pending.close();
        assertEquals(TotpEnrollmentService.Confirmation.CANCELLED,
                confirm(pending, "287082"));
        assertNull(store.encoded);
    }

    @Test(expected = IllegalStateException.class)
    public void closedSetup_doesNotExposeManualKey() throws Exception {
        TotpEnrollmentService.PendingSetup pending = service.begin();
        pending.close();
        pending.copyBase32Secret();
    }

    @Test
    public void setupExpiresAtExactFiveMinuteBoundary() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            elapsed.set(300_000L);
            assertEquals(TotpEnrollmentService.Confirmation.EXPIRED,
                    confirm(pending, "287082"));
            assertFalse(pending.isActive());
            assertNull(store.encoded);
        }
    }

    @Test
    public void backwardsMonotonicClock_expiresSetup() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            elapsed.set(-1L);
            assertEquals(TotpEnrollmentService.Confirmation.EXPIRED,
                    confirm(pending, "287082"));
            assertNull(store.encoded);
        }
    }

    @Test
    public void fiveInvalidConfirmations_closeSetupWithoutSaving() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            for (int i = 0; i < 4; i++) {
                assertEquals(TotpEnrollmentService.Confirmation.INVALID_CODE,
                        confirm(pending, "000000"));
            }
            assertEquals(TotpEnrollmentService.Confirmation.ATTEMPT_LIMIT_REACHED,
                    confirm(pending, "000000"));
            assertFalse(pending.isActive());
            assertEquals(0, pending.getRemainingAttempts());
            assertNull(store.encoded);
        }
    }

    @Test
    public void correctCodeBeforeLimit_canConfirmEnrollment() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            for (int i = 0; i < 4; i++) {
                confirm(pending, "000000");
            }
            assertEquals(TotpEnrollmentService.Confirmation.ENABLED,
                    confirm(pending, "287082"));
            assertSavedState(1L);
        }
    }

    @Test
    public void confirmedEnrollment_persistsSecretAndConsumesSetupStep() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            assertEquals(TotpEnrollmentService.Confirmation.ENABLED,
                    confirm(pending, "287082"));
            assertFalse(pending.isActive());
            assertSavedState(1L);
            assertEquals(1, store.saves);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void begin_cannotReplaceExistingConfiguration() throws Exception {
        try (TotpState existing = new TotpState(TEST_SECRET, 1L, 0, 0L)) {
            store.encoded = existing.encode();
        }
        service.begin();
    }

    @Test
    public void secondPendingSetup_cannotOverwriteFirstEnrollment() throws Exception {
        try (TotpEnrollmentService.PendingSetup first = service.begin();
             TotpEnrollmentService.PendingSetup second = service.begin()) {
            confirm(first, "287082");
            assertEquals(TotpEnrollmentService.Confirmation.ALREADY_CONFIGURED,
                    confirm(second, "287082"));
            assertEquals(1, store.saves);
            assertEquals(0, store.clears);
        }
    }

    @Test
    public void setup_cannotBeConfirmedByAnotherService() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            TotpEnrollmentService other = newService(new FixedRandom(TEST_SECRET));
            try {
                other.confirm(pending, "287082".toCharArray());
                fail("A setup must remain bound to its originating service.");
            } catch (IllegalArgumentException expected) {
                assertTrue(pending.isActive());
                assertNull(store.encoded);
            }
        }
    }

    @Test
    public void setupConfirmationCode_cannotThenBeUsedForSignIn() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            confirm(pending, "287082");
        }
        TotpVerificationService verifier =
                new TotpVerificationService(store, wall::get);
        assertEquals(TotpVerificationService.Status.INVALID_CODE,
                verifier.verify("287082".toCharArray()).getStatus());
    }

    @Test
    public void confirmation_leavesCallerCodeUnchanged() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            char[] code = "287082".toCharArray();
            char[] original = code.clone();
            service.confirm(pending, code);
            assertArrayEquals(original, code);
        }
    }

    @Test
    public void changingReturnedManualKey_doesNotChangeOwnedSecret() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            char[] key = pending.copyBase32Secret();
            Arrays.fill(key, 'A');
            char[] secondCopy = pending.copyBase32Secret();
            try {
                assertArrayEquals(BASE32.toCharArray(), secondCopy);
                assertEquals(TotpEnrollmentService.Confirmation.ENABLED,
                        confirm(pending, "287082"));
            } finally {
                Arrays.fill(key, '\0');
                Arrays.fill(secondCopy, '\0');
            }
        }
    }

    @Test
    public void failedInitialSave_isRolledBackAndCanBeRetried() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            store.failAfterSave = true;
            try {
                confirm(pending, "287082");
                fail("A failed first save must not report enrollment success.");
            } catch (IOException expected) {
                assertNull(store.encoded);
                assertEquals(1, store.clears);
                assertTrue(pending.isActive());
            }
            store.failAfterSave = false;
            assertEquals(TotpEnrollmentService.Confirmation.ENABLED,
                    confirm(pending, "287082"));
        }
    }

    @Test
    public void failedRollback_closesSetupAndPreservesError() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            store.failAfterSave = true;
            store.failClear = true;
            try {
                confirm(pending, "287082");
                fail("Save/rollback failure must not report success.");
            } catch (IOException expected) {
                assertEquals(1, expected.getSuppressed().length);
                assertFalse(pending.isActive());
            }
        }
    }

    @Test(expected = IOException.class)
    public void beginReadFailure_isNotTreatedAsUnconfigured() throws Exception {
        store.failLoad = true;
        service.begin();
    }

    @Test
    public void confirmationReadFailure_doesNotEnableTotp() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            store.failLoad = true;
            try {
                confirm(pending, "287082");
                fail("Unreadable state must not be treated as absent.");
            } catch (IOException expected) {
                assertEquals(0, store.saves);
            }
            store.failLoad = false;
            assertEquals(TotpEnrollmentService.Confirmation.ENABLED,
                    confirm(pending, "287082"));
        }
    }

    @Test(expected = IllegalStateException.class)
    public void expiredSetup_doesNotExposeManualKey() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            elapsed.set(300_000L);
            pending.copyBase32Secret();
        }
    }

    @Test
    public void simultaneousConfirmations_enableOnlyOneSetup() throws Exception {
        TotpEnrollmentService other = newService(new FixedRandom(TEST_SECRET));
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);

        try (TotpEnrollmentService.PendingSetup first = service.begin();
             TotpEnrollmentService.PendingSetup second = other.begin()) {
            try {
                Future<TotpEnrollmentService.Confirmation> a = workers.submit(() -> {
                    start.await();
                    return service.confirm(first, "287082".toCharArray());
                });
                Future<TotpEnrollmentService.Confirmation> b = workers.submit(() -> {
                    start.await();
                    return other.confirm(second, "287082".toCharArray());
                });
                start.countDown();

                TotpEnrollmentService.Confirmation x =
                        a.get(10, TimeUnit.SECONDS);
                TotpEnrollmentService.Confirmation y =
                        b.get(10, TimeUnit.SECONDS);

                int enabled =
                        (x == TotpEnrollmentService.Confirmation.ENABLED ? 1 : 0)
                                + (y == TotpEnrollmentService.Confirmation.ENABLED ? 1 : 0);

                assertEquals(1, enabled);
                assertEquals(1, store.saves);
            } finally {
                workers.shutdownNow();
            }
        }
    }

    @Test
    public void base32_handlesZeroAndHighBitBytes() throws Exception {
        byte[] zeros = new byte[20];
        byte[] high = new byte[20];
        Arrays.fill(high, (byte) 0xFF);

        byte[][] inputs = {zeros, high};
        String[] expected = {
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "77777777777777777777777777777777"
        };

        for (int i = 0; i < inputs.length; i++) {
            TotpEnrollmentService encoder = newService(new FixedRandom(inputs[i]));
            try (TotpEnrollmentService.PendingSetup pending = encoder.begin()) {
                char[] key = pending.copyBase32Secret();
                try {
                    assertArrayEquals(expected[i].toCharArray(), key);
                } finally {
                    Arrays.fill(key, '\0');
                }
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void invalidWallClock_cannotConfirmEnrollment() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            wall.set(-1L);
            confirm(pending, "287082");
        }
    }

    @Test
    public void malformedCodes_useConfirmationAttempts() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            assertEquals(TotpEnrollmentService.Confirmation.INVALID_CODE,
                    service.confirm(pending, null));
            assertEquals(TotpEnrollmentService.Confirmation.INVALID_CODE,
                    confirm(pending, "1234567"));
            assertEquals(3, pending.getRemainingAttempts());
            assertNull(store.encoded);
        }
    }

    private TotpEnrollmentService newService(SecureRandom random) {
        return new TotpEnrollmentService(store, random, wall::get, elapsed::get);
    }

    private TotpEnrollmentService.Confirmation confirm(
            TotpEnrollmentService.PendingSetup pending, String code
    ) throws Exception {
        return service.confirm(pending, code.toCharArray());
    }

    private void assertSavedState(long step) {
        try (TotpState saved = TotpState.decode(store.encoded)) {
            byte[] secret = saved.copySecret();
            try {
                assertArrayEquals(TEST_SECRET, secret);
                assertEquals(step, saved.getLastAcceptedStep());
                assertEquals(0, saved.getFailedAttempts());
                assertEquals(0L, saved.getBlockedUntilEpochMillis());
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
        }
    }

    private static final class FixedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] value;

        FixedRandom(byte[] value) {
            this.value = value.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(value, 0, bytes, 0, bytes.length);
        }
    }

    private static final class MemoryStore
            implements TotpEnrollmentService.EnrollmentStore {

        private final Object lock = new Object();
        byte[] encoded;
        int saves;
        int clears;
        boolean failLoad;
        boolean failAfterSave;
        boolean failClear;

        @Override
        public Object getTransactionLock() {
            return lock;
        }

        @Override
        public TotpState load() throws IOException {
            requireLock();
            if (failLoad) {
                throw new IOException("Simulated read failure.");
            }
            return encoded == null ? null : TotpState.decode(encoded);
        }

        @Override
        public void save(TotpState state) throws IOException {
            requireLock();
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            encoded = state.encode();
            saves++;
            if (failAfterSave) {
                throw new IOException("Simulated failure after partial save.");
            }
        }

        @Override
        public void clear() throws IOException {
            requireLock();
            if (failClear) {
                throw new IOException("Simulated cleanup failure.");
            }
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            encoded = null;
            clears++;
        }

        private void requireLock() {
            if (!Thread.holdsLock(lock)) {
                throw new AssertionError(
                        "Enrollment must hold the shared transaction lock."
                );
            }
        }
    }
}

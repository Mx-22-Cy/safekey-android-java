package com.safekey.app.security.totp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

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

public class VaultUnlockGateTest {

    // Public test data only; never use these values for a real vault.
    private static final byte[] SECRET =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEY = new byte[32];

    private MemoryStore store;
    private AtomicLong wall;
    private AtomicLong elapsed;
    private VaultUnlockGate gate;

    @Before
    public void setUp() {
        store = new MemoryStore();
        wall = new AtomicLong(59_000L);
        elapsed = new AtomicLong(0L);
        gate = new VaultUnlockGate(store, wall::get, elapsed::get);
    }

    @After
    public void tearDown() {
        gate.cancelAll();
        store.replace(null);
    }

    @Test
    public void keyCannotBeTakenBeforePrimaryAuthentication() {
        VaultUnlockGate.Attempt attempt = gate.begin();

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertEquals(
                VaultUnlockGate.Stage.WAITING_FOR_PRIMARY,
                gate.getStage(attempt)
        );
    }

    @Test
    public void unconfiguredTotp_allowsOneOwnedKeyHandoff() throws Exception {
        VaultUnlockGate.Attempt attempt = gate.begin();
        byte[] callerKey = KEY.clone();
        callerKey[0] = 42;

        assertEquals(
                VaultUnlockGate.Stage.READY_TO_OPEN,
                gate.acceptPrimary(attempt, callerKey)
        );

        Arrays.fill(callerKey, (byte) 0);

        byte[] taken = gate.takeKeyForOpening(attempt);

        try {
            assertEquals(42, taken[0]);
            assertEquals(
                    VaultUnlockGate.Stage.OPENING,
                    gate.getStage(attempt)
            );

            assertThrows(
                    IllegalStateException.class,
                    () -> gate.takeKeyForOpening(attempt)
            );
        } finally {
            Arrays.fill(taken, (byte) 0);
        }
    }

    @Test
    public void configuredTotp_blocksKeyUntilVerification() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();

        assertEquals(
                VaultUnlockGate.Stage.TOTP_REQUIRED,
                gate.getStage(attempt)
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertFalse(gate.complete(attempt));
    }

    @Test
    public void wrongCodeCannotReleaseKey_butCorrectCodeCan() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify(attempt, "000000")
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify(attempt, "287082")
        );

        takeAndClear(attempt);
    }

    @Test
    public void verificationLeavesCallerCodeUnchanged() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();

        char[] code = "287082".toCharArray();
        char[] original = code.clone();

        gate.verifyTotp(attempt, code);

        assertArrayEquals(original, code);
    }

    @Test
    public void acceptedCodeCannotBeReplayedThroughNewGate() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt first = primary();

        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify(first, "287082")
        );

        gate.cancelAll();

        gate = new VaultUnlockGate(store, wall::get, elapsed::get);
        VaultUnlockGate.Attempt second = primary();

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify(second, "287082")
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(second)
        );
    }

    @Test
    public void restartingAttemptsDoesNotResetFailedAttemptLimit()
            throws Exception {
        configure(SECRET);

        for (int i = 0; i < 5; i++) {
            VaultUnlockGate.Attempt attempt = primary();

            TotpVerificationService.Status expected = i < 4
                    ? TotpVerificationService.Status.INVALID_CODE
                    : TotpVerificationService.Status.RETRY_LATER;

            assertEquals(expected, verify(attempt, "000000"));
            attempt.close();
        }

        VaultUnlockGate.Attempt next = primary();

        assertEquals(
                TotpVerificationService.Status.RETRY_LATER,
                verify(next, "287082")
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(next)
        );
    }

    @Test
    public void correctCodeWorksOnlyAfterCooldownEnds() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();

        for (int i = 0; i < 5; i++) {
            verify(attempt, "000000");
        }

        assertEquals(
                TotpVerificationService.Status.RETRY_LATER,
                verify(attempt, "287082")
        );

        wall.set(89_000L);

        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify(attempt, "359152")
        );

        takeAndClear(attempt);
    }

    @Test
    public void cancelledAttemptRejectsLatePrimaryResult() {
        VaultUnlockGate.Attempt attempt = gate.begin();
        attempt.close();

        assertThrows(
                IllegalStateException.class,
                () -> gate.acceptPrimary(attempt, KEY)
        );

        assertFalse(gate.isActive(attempt));
    }

    @Test
    public void cancellationAfterPrimaryBlocksVerificationAndHandoff()
            throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();
        attempt.close();

        assertThrows(
                IllegalStateException.class,
                () -> gate.verifyTotp(attempt, "287082".toCharArray())
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertEquals(
                VaultUnlockGate.Stage.CANCELLED,
                gate.getStage(attempt)
        );
    }

    @Test
    public void replacementRejectsOldResult_andOldCloseCannotCancelReplacement()
            throws Exception {
        VaultUnlockGate.Attempt old = gate.begin();
        VaultUnlockGate.Attempt replacement = gate.begin();

        assertThrows(
                IllegalStateException.class,
                () -> gate.acceptPrimary(old, KEY)
        );

        old.close();

        assertTrue(gate.isActive(replacement));

        gate.acceptPrimary(replacement, KEY);
        takeAndClear(replacement);
    }

    @Test
    public void attemptExpiresBeforePrimaryResultAtExactBoundary() {
        VaultUnlockGate.Attempt attempt = gate.begin();
        elapsed.set(120_000L);

        assertThrows(
                IllegalStateException.class,
                () -> gate.acceptPrimary(attempt, KEY)
        );

        assertEquals(
                VaultUnlockGate.Stage.EXPIRED,
                gate.getStage(attempt)
        );
    }

    @Test
    public void attemptExpiresWhileWaitingForTotp() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();
        elapsed.set(120_000L);

        assertThrows(
                IllegalStateException.class,
                () -> gate.verifyTotp(attempt, "287082".toCharArray())
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertEquals(
                VaultUnlockGate.Stage.EXPIRED,
                gate.getStage(attempt)
        );
    }

    @Test
    public void backwardsMonotonicClockExpiresAttempt() {
        VaultUnlockGate.Attempt attempt = gate.begin();
        elapsed.set(-1L);

        assertFalse(gate.isActive(attempt));

        assertEquals(
                VaultUnlockGate.Stage.EXPIRED,
                gate.getStage(attempt)
        );
    }

    @Test
    public void primaryStateReadFailureCancelsAttempt() {
        VaultUnlockGate.Attempt attempt = gate.begin();
        store.failLoad = true;

        assertThrows(
                IOException.class,
                () -> gate.acceptPrimary(attempt, KEY)
        );

        assertEquals(
                VaultUnlockGate.Stage.CANCELLED,
                gate.getStage(attempt)
        );
    }

    @Test
    public void verificationReadFailureCancelsAttempt() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();
        store.failLoad = true;

        assertThrows(
                IOException.class,
                () -> gate.verifyTotp(attempt, "287082".toCharArray())
        );

        assertFalse(gate.isActive(attempt));

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );
    }

    @Test
    public void verificationSaveFailureCannotReleaseKey() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();
        store.failSave = true;

        assertThrows(
                IOException.class,
                () -> gate.verifyTotp(attempt, "287082".toCharArray())
        );

        assertFalse(gate.isActive(attempt));

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );
    }

    @Test
    public void missingConfigurationCannotBypassRequiredTotp() throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();
        store.replace(null);

        assertThrows(
                IllegalStateException.class,
                () -> gate.verifyTotp(attempt, "287082".toCharArray())
        );

        assertFalse(gate.isActive(attempt));
    }

    @Test
    public void replacedSecretRequiresFreshPrimaryAuthentication()
            throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();

        byte[] replacement = SECRET.clone();
        replacement[0] ^= 1;

        try {
            configure(replacement);
        } finally {
            Arrays.fill(replacement, (byte) 0);
        }

        assertThrows(
                IllegalStateException.class,
                () -> gate.verifyTotp(attempt, "287082".toCharArray())
        );

        assertFalse(gate.isActive(attempt));
    }

    @Test
    public void enablingTotpBeforeHandoffBlocksPasswordOnlyOpening()
            throws Exception {
        VaultUnlockGate.Attempt attempt = primary();
        configure(SECRET);

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertFalse(gate.isActive(attempt));
    }

    @Test
    public void removingConfigurationAfterVerificationBlocksHandoff()
            throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();

        verify(attempt, "287082");
        store.replace(null);

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertFalse(gate.isActive(attempt));
    }

    @Test
    public void stateReadFailureAtHandoffCancelsAttempt() throws Exception {
        VaultUnlockGate.Attempt attempt = primary();
        store.failLoad = true;

        assertThrows(
                IOException.class,
                () -> gate.takeKeyForOpening(attempt)
        );

        assertFalse(gate.isActive(attempt));
    }

    @Test
    public void staleDatabaseCallbackCannotCompleteNewAttempt()
            throws Exception {
        VaultUnlockGate.Attempt old = primary();
        takeAndClear(old);

        VaultUnlockGate.Attempt replacement = gate.begin();

        assertFalse(gate.complete(old));
        assertTrue(gate.isActive(replacement));
    }

    @Test
    public void successfulCompletionIsOneTime_andOldCloseDoesNotCancelNewAttempt()
            throws Exception {
        VaultUnlockGate.Attempt old = primary();
        takeAndClear(old);

        assertTrue(gate.complete(old));
        assertFalse(gate.complete(old));

        assertEquals(
                VaultUnlockGate.Stage.COMPLETED,
                gate.getStage(old)
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(old)
        );

        VaultUnlockGate.Attempt next = gate.begin();
        old.close();

        assertTrue(gate.isActive(next));
    }

    @Test
    public void attemptFromAnotherGateIsRejectedWithoutCancellingItsOwner() {
        VaultUnlockGate other =
                new VaultUnlockGate(store, wall::get, elapsed::get);

        VaultUnlockGate.Attempt foreign = other.begin();

        try {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> gate.acceptPrimary(foreign, KEY)
            );

            assertThrows(
                    IllegalArgumentException.class,
                    () -> gate.cancel(foreign)
            );

            assertTrue(other.isActive(foreign));
        } finally {
            other.cancelAll();
        }
    }

    @Test
    public void invalidDatabaseKeysCancelTheirAttempts() {
        byte[][] invalid = {null, new byte[31], new byte[33]};

        for (byte[] key : invalid) {
            VaultUnlockGate.Attempt attempt = gate.begin();

            assertThrows(
                    IllegalArgumentException.class,
                    () -> gate.acceptPrimary(attempt, key)
            );

            assertFalse(gate.isActive(attempt));
        }
    }

    @Test
    public void simultaneousHandoffsReleaseOnlyOneKey() throws Exception {
        VaultUnlockGate.Attempt attempt = primary();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);

        try {
            Future<Integer> first =
                    workers.submit(() -> handoffAfter(start, attempt));
            Future<Integer> second =
                    workers.submit(() -> handoffAfter(start, attempt));

            start.countDown();

            assertEquals(
                    1,
                    first.get(10, TimeUnit.SECONDS)
                            + second.get(10, TimeUnit.SECONDS)
            );
        } finally {
            workers.shutdownNow();
        }
    }

    @Test
    public void attemptExpiringDuringStorageReadCannotAcceptPrimaryKey() {
        VaultUnlockGate.Attempt attempt = gate.begin();
        store.afterLoad = () -> elapsed.set(120_000L);

        assertThrows(
                IllegalStateException.class,
                () -> gate.acceptPrimary(attempt, KEY)
        );

        assertEquals(
                VaultUnlockGate.Stage.EXPIRED,
                gate.getStage(attempt)
        );
    }

    @Test
    public void attemptExpiringDuringVerificationCannotReleaseKey()
            throws Exception {
        configure(SECRET);
        VaultUnlockGate.Attempt attempt = primary();
        store.afterSave = () -> elapsed.set(120_000L);

        assertThrows(
                IllegalStateException.class,
                () -> gate.verifyTotp(attempt, "287082".toCharArray())
        );

        assertEquals(
                VaultUnlockGate.Stage.EXPIRED,
                gate.getStage(attempt)
        );

        assertThrows(
                IllegalStateException.class,
                () -> gate.takeKeyForOpening(attempt)
        );
    }

    @Test
    public void expiredDatabaseOpenCannotComplete() throws Exception {
        VaultUnlockGate.Attempt attempt = primary();
        takeAndClear(attempt);
        elapsed.set(120_000L);

        assertFalse(gate.complete(attempt));

        assertEquals(
                VaultUnlockGate.Stage.EXPIRED,
                gate.getStage(attempt)
        );
    }

    @Test
    public void cancellationZerosPendingKeyAndTotpSecret() throws Exception {
        assertPendingSecretsZeroed(VaultUnlockGate.Attempt::close);
    }

    @Test
    public void expiryZerosPendingKeyAndTotpSecret() throws Exception {
        assertPendingSecretsZeroed(attempt -> {
            elapsed.set(VaultUnlockGate.ATTEMPT_LIFETIME_MILLIS);
            assertFalse(gate.isActive(attempt));
            assertEquals(VaultUnlockGate.Stage.EXPIRED, gate.getStage(attempt));
        });
    }

    private void assertPendingSecretsZeroed(
            java.util.function.Consumer<VaultUnlockGate.Attempt> finish
    ) throws Exception {
        configure(SECRET);
        byte[] suppliedKey = new byte[VaultUnlockGate.DATABASE_KEY_LENGTH_BYTES];
        Arrays.fill(suppliedKey, (byte) 0x5a);

        try (VaultUnlockGate.Attempt attempt = gate.begin()) {
            assertEquals(VaultUnlockGate.Stage.TOTP_REQUIRED,
                    gate.acceptPrimary(attempt, suppliedKey));

            byte[] ownedKey = readAttemptBuffer(attempt, "databaseKey");
            byte[] ownedTotpSecret = readAttemptBuffer(attempt, "totpSecret");
            assertArrayEquals(suppliedKey, ownedKey);
            assertTrue("The attempt must own a copy of the database key", ownedKey != suppliedKey);
            assertFalse("The TOTP fixture must start with nonzero bytes",
                    Arrays.equals(new byte[ownedTotpSecret.length], ownedTotpSecret));

            finish.accept(attempt);

            assertArrayEquals(new byte[ownedKey.length], ownedKey);
            assertArrayEquals(new byte[ownedTotpSecret.length], ownedTotpSecret);
        } finally {
            Arrays.fill(suppliedKey, (byte) 0);
        }
    }

    private static byte[] readAttemptBuffer(VaultUnlockGate.Attempt attempt, String name)
            throws ReflectiveOperationException {
        java.lang.reflect.Field field = VaultUnlockGate.Attempt.class.getDeclaredField(name);
        field.setAccessible(true);
        return (byte[]) field.get(attempt);
    }

    private VaultUnlockGate.Attempt primary() throws Exception {
        VaultUnlockGate.Attempt attempt = gate.begin();
        gate.acceptPrimary(attempt, KEY);
        return attempt;
    }

    private TotpVerificationService.Status verify(
            VaultUnlockGate.Attempt attempt,
            String code
    ) throws Exception {
        return gate.verifyTotp(attempt, code.toCharArray()).getStatus();
    }

    private void takeAndClear(VaultUnlockGate.Attempt attempt)
            throws Exception {
        byte[] key = gate.takeKeyForOpening(attempt);

        try {
            assertArrayEquals(KEY, key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private int handoffAfter(
            CountDownLatch start,
            VaultUnlockGate.Attempt attempt
    ) throws Exception {
        start.await();

        try {
            takeAndClear(attempt);
            return 1;
        } catch (IllegalStateException expected) {
            return 0;
        }
    }

    private void configure(byte[] secret) {
        try (TotpState state = new TotpState(secret, -1L, 0, 0L)) {
            store.replace(state.encode());
        }
    }

    private static final class MemoryStore
            implements TotpVerificationService.StateStore {

        private final Object lock = new Object();
        private byte[] encoded;
        boolean failLoad;
        boolean failSave;
        Runnable afterLoad = () -> { };
        Runnable afterSave = () -> { };

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

            afterLoad.run();
            return encoded == null ? null : TotpState.decode(encoded);
        }

        @Override
        public void save(TotpState state) throws IOException {
            requireLock();

            if (failSave) {
                throw new IOException("Simulated save failure.");
            }

            replace(state.encode());
            afterSave.run();
        }

        void replace(byte[] replacement) {
            synchronized (lock) {
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
                encoded = replacement;
            }
        }

        private void requireLock() {
            if (!Thread.holdsLock(lock)) {
                throw new AssertionError(
                        "The shared TOTP storage lock is required."
                );
            }
        }
    }
}

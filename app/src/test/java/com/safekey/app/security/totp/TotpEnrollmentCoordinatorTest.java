package com.safekey.app.security.totp;

import static org.junit.Assert.*;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.session.logic.VaultSessionManager;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class TotpEnrollmentCoordinatorTest {
    private static final String MASTER = "DisposableMasterForEnrollment123!";
    private static final byte[] SECRET =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final String BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    private final AtomicLong elapsed = new AtomicLong();
    private final AtomicLong selection = new AtomicLong();
    private final AtomicInteger verifications = new AtomicInteger();
    private final BlockingQueue<Runnable> callbacks = new LinkedBlockingQueue<>();
    private PanicRuntimeScope scope;
    private ScheduledExecutorService worker;
    private VaultSessionManager session;
    private MemoryStore store;
    private TotpEnrollmentCoordinator coordinator;
    private volatile boolean real;
    private volatile char[] verifiedPassword;
    private volatile CountDownLatch verifying;
    private volatile CountDownLatch finishVerification;
    private volatile boolean rejectCallbacks;

    @Before
    public void setUp() {
        elapsed.set(0L);
        real = true;
        scope = new PanicRuntimeScope();
        worker = Executors.newSingleThreadScheduledExecutor();
        scope.registerExecutor(worker);
        session = new VaultSessionManager(elapsed::get, () -> {
            if (coordinator != null) {
                coordinator.invalidateSession();
            }
        });
        session.unlockAfterAuthentication();
        store = new MemoryStore();
        TotpEnrollmentService service = new TotpEnrollmentService(store, new FixedRandom(),
                () -> 59_000L, elapsed::get);
        coordinator = new TotpEnrollmentCoordinator(service, password -> {
            verifications.incrementAndGet();
            verifiedPassword = password;
            if (verifying != null) {
                verifying.countDown();
                assertTrue(finishVerification.await(2, TimeUnit.SECONDS));
            }
            if (!Arrays.equals(MASTER.toCharArray(), password)) {
                throw new IOException("Master password verification failed.");
            }
        }, () -> {
            long authentication = session.getAuthenticationGeneration();
            long vaultSelection = selection.get();
            if (!real || authentication < 0L) {
                throw new IllegalStateException("REAL authentication is required.");
            }
            return action -> {
                boolean[] executed = {false};
                session.runIfCurrentAuthenticationForStorageCommit(authentication, () -> {
                    if (real && selection.get() == vaultSelection) {
                        executed[0] = true;
                        action.run();
                    }
                });
                return executed[0];
            };
        }, worker, action -> {
            if (rejectCallbacks) {
                throw new java.util.concurrent.RejectedExecutionException();
            }
            callbacks.add(action);
        }, scope);
    }

    @After
    public void tearDown() throws Exception {
        if (finishVerification != null) {
            finishVerification.countDown();
        }
        coordinator.cancelPending();
        scope.cancelPending();
        worker.shutdownNow();
        assertTrue(worker.awaitTermination(2, TimeUnit.SECONDS));
        if (store.encoded != null) {
            Arrays.fill(store.encoded, (byte) 0);
        }
    }

    @Test(expected = IllegalStateException.class)
    public void lockedSessionCannotStartEnrollment() {
        session.lock();
        coordinator.begin(MASTER.toCharArray(), new SetupCapture());
    }

    @Test(expected = IllegalStateException.class)
    public void decoySessionCannotStartEnrollment() {
        real = false;
        coordinator.begin(MASTER.toCharArray(), new SetupCapture());
    }

    @Test
    public void passwordIsVerifiedBeforeSecretIsExposed() throws Exception {
        SetupCapture capture = new SetupCapture();
        char[] password = MASTER.toCharArray();
        TotpEnrollmentCoordinator.Setup setup = coordinator.begin(password, capture);
        assertNull(capture.ready);
        flush();
        assertSame(setup, capture.ready);
        assertNull(capture.error);
        assertArrayEquals(MASTER.toCharArray(), password);
        assertCleared(verifiedPassword);
        assertArrayEquals(BASE32.toCharArray(), setup.copyBase32Secret());
        assertTrue(setup.getAuthenticatorUri().contains("secret=" + BASE32));
        assertEquals(0, store.saves);
    }

    @Test
    public void wrongPasswordCannotCreatePendingSetup() throws Exception {
        SetupCapture capture = new SetupCapture();
        coordinator.begin("WrongDisposablePassword".toCharArray(), capture);
        flush();
        assertNull(capture.ready);
        assertNotNull(capture.error);
        assertNull(coordinator.getPendingSetup());
        assertEquals(0, store.saves);
        assertCleared(verifiedPassword);
    }

    @Test
    public void navigationReusesPendingSetupAndItsAttemptCounter() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        ResultCapture result = new ResultCapture();
        setup.confirm("000000".toCharArray(), result);
        flush();
        assertEquals(TotpEnrollmentService.Confirmation.INVALID_CODE, result.result);
        assertEquals(4, result.remaining);
        assertSame(setup, coordinator.getPendingSetup());
        assertEquals(4, setup.getRemainingAttempts());
        assertArrayEquals(BASE32.toCharArray(), setup.copyBase32Secret());
    }

    @Test
    public void navigationKeepsTheOriginalCountdownAndDeadline() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        assertEquals(300_000L, setup.getRemainingMillis());
        assertEquals(300_000L, setup.getExpiresAtElapsedRealtimeMillis());
        elapsed.set(1_000L);
        TotpEnrollmentCoordinator.Setup restored = coordinator.getPendingSetup();
        assertSame(setup, restored);
        assertEquals(299_000L, restored.getRemainingMillis());
        assertEquals(300_000L, restored.getExpiresAtElapsedRealtimeMillis());
        assertEquals(1, verifications.get());
    }

    @Test
    public void expiredSetupReportsZeroWhileItsVaultSessionRemainsValid() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        elapsed.set(200_000L);
        assertTrue(session.recordActivity());
        elapsed.set(300_000L);
        assertEquals(0L, setup.getRemainingMillis());
        assertTrue(setup.isSessionValid());
        assertFalse(setup.isActive());
        assertNull(coordinator.getPendingSetup());
        assertEquals(0, store.saves);
    }

    @Test
    public void explicitCancellationIsDistinguishedFromInvalidAuthentication() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        setup.close();
        assertTrue(setup.isSessionValid());
        try {
            setup.confirm("287082".toCharArray(), new ResultCapture());
            fail("Closed setup accepted confirmation.");
        } catch (IllegalStateException expected) {
            assertFalse(expected instanceof TotpEnrollmentCoordinator.SessionInvalidException);
        }
    }

    @Test
    public void sessionLockProvidesAnIdentifiableSessionFailure() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        session.lock();
        assertFalse(setup.isSessionValid());
        try {
            setup.copyBase32Secret();
            fail("Invalid authentication exposed a secret.");
        } catch (TotpEnrollmentCoordinator.SessionInvalidException expected) {
            assertEquals(0, store.saves);
        }
    }

    @Test
    public void reauthenticationProvidesAnIdentifiableConfirmationFailure() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        session.unlockAfterAuthentication();
        try {
            setup.confirm("287082".toCharArray(), new ResultCapture());
            fail("Changed authentication accepted confirmation.");
        } catch (TotpEnrollmentCoordinator.SessionInvalidException expected) {
            assertFalse(setup.isSessionValid());
            assertEquals(0, store.saves);
        }
    }

    @Test
    public void secondBeginPreservesTheExistingPendingSetup() throws Exception {
        TotpEnrollmentCoordinator.Setup first = ready();
        try {
            coordinator.begin(MASTER.toCharArray(), new SetupCapture());
            fail("A second setup was accepted.");
        } catch (IllegalStateException expected) {
            assertSame(first, coordinator.getPendingSetup());
            assertTrue(first.isReady());
        }
    }

    @Test
    public void aNewAuthenticationCanReplaceItsStaleSetup() throws Exception {
        TotpEnrollmentCoordinator.Setup previous = ready();
        session.unlockAfterAuthentication();
        TotpEnrollmentCoordinator.Setup replacement = ready();
        assertFalse(previous.isActive());
        assertTrue(replacement.isActive());
        assertSame(replacement, coordinator.getPendingSetup());
    }

    @Test
    public void expiredSetupCanBeReplacedWhileTheVaultSessionIsActive() throws Exception {
        TotpEnrollmentCoordinator.Setup previous = ready();
        elapsed.set(200_000L);
        assertTrue(session.recordActivity());
        elapsed.set(300_000L);
        TotpEnrollmentCoordinator.Setup replacement = ready();
        assertFalse(previous.isActive());
        assertTrue(replacement.isActive());
        assertSame(replacement, coordinator.getPendingSetup());
    }

    @Test
    public void cancellationBeforeWorkerRunsPreventsPasswordVerification() throws Exception {
        CountDownLatch release = pauseWorker();
        try {
            SetupCapture capture = new SetupCapture();
            TotpEnrollmentCoordinator.Setup setup = coordinator.begin(MASTER.toCharArray(), capture);
            setup.close();
            release.countDown();
            flush();
            assertEquals(0, verifications.get());
            assertNull(capture.ready);
            assertNull(coordinator.getPendingSetup());
        } finally {
            release.countDown();
        }
    }

    @Test
    public void lockingDuringPasswordVerificationPreventsSecretHandoff() throws Exception {
        verifying = new CountDownLatch(1);
        finishVerification = new CountDownLatch(1);
        SetupCapture capture = new SetupCapture();
        coordinator.begin(MASTER.toCharArray(), capture);
        assertTrue(verifying.await(2, TimeUnit.SECONDS));
        session.lock();
        finishVerification.countDown();
        flush();
        assertNull(capture.ready);
        assertNull(capture.error);
        assertNull(coordinator.getPendingSetup());
        assertCleared(verifiedPassword);
    }

    @Test
    public void lockClosesPendingSetup() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        session.lock();
        assertFalse(setup.isActive());
        assertNull(coordinator.getPendingSetup());
        try {
            setup.copyBase32Secret();
            fail("A locked session exposed its secret.");
        } catch (IllegalStateException expected) {
            assertEquals(0, store.saves);
        }
    }

    @Test
    public void reauthenticationRejectsAQueuedConfirmation() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        CountDownLatch release = pauseWorker();
        try {
            ResultCapture result = new ResultCapture();
            setup.confirm("287082".toCharArray(), result);
            session.unlockAfterAuthentication();
            release.countDown();
            flush();
            assertEquals(0, store.saves);
            assertNull(result.result);
            assertFalse(setup.isActive());
        } finally {
            release.countDown();
        }
    }

    @Test
    public void vaultSelectionChangeRejectsAQueuedConfirmation() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        CountDownLatch release = pauseWorker();
        try {
            setup.confirm("287082".toCharArray(), new ResultCapture());
            selection.incrementAndGet();
            release.countDown();
            flush();
            assertEquals(0, store.saves);
            assertNull(coordinator.getPendingSetup());
        } finally {
            release.countDown();
        }
    }

    @Test
    public void correctCodeEnablesTotpAndConsumesTheEnrollmentStep() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        ResultCapture result = new ResultCapture();
        char[] code = "287082".toCharArray();
        setup.confirm(code, result);
        flush();
        assertNull(result.error);
        assertEquals(TotpEnrollmentService.Confirmation.ENABLED, result.result);
        assertArrayEquals("287082".toCharArray(), code);
        assertEquals(1, store.saves);
        assertNull(coordinator.getPendingSetup());
        try (TotpState saved = TotpState.decode(store.encoded)) {
            assertEquals(1L, saved.getLastAcceptedStep());
            assertArrayEquals(SECRET, saved.copySecret());
        }
    }

    @Test
    public void fiveInvalidCodesCloseSetupWithoutSaving() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        ResultCapture result = null;
        for (int attempt = 0; attempt < 5; attempt++) {
            result = new ResultCapture();
            setup.confirm("000000".toCharArray(), result);
            flush();
        }
        assertEquals(TotpEnrollmentService.Confirmation.ATTEMPT_LIMIT_REACHED, result.result);
        assertEquals(0, result.remaining);
        assertEquals(0, store.saves);
        assertNull(coordinator.getPendingSetup());
    }

    @Test
    public void setupExpiresEvenWhenActivityExtendsTheVaultSession() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        elapsed.set(200_000L);
        assertTrue(session.recordActivity());
        elapsed.set(300_000L);
        ResultCapture result = new ResultCapture();
        setup.confirm("287082".toCharArray(), result);
        flush();
        assertEquals(TotpEnrollmentService.Confirmation.EXPIRED, result.result);
        assertEquals(0, store.saves);
    }

    @Test
    public void expiredVaultSessionRejectsConfirmation() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        elapsed.set(300_000L);
        try {
            setup.confirm("287082".toCharArray(), new ResultCapture());
            fail("Expired authentication was accepted.");
        } catch (IllegalStateException expected) {
            assertEquals(0, store.saves);
        }
    }

    @Test
    public void panicCancelsQueuedConfirmationAndReleasesPendingWork() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        CountDownLatch release = pauseWorker();
        try {
            setup.confirm("287082".toCharArray(), new ResultCapture());
            scope.cancelPending();
            release.countDown();
            flush();
            scope.getWorkGate().awaitIdle(2, TimeUnit.SECONDS);
            assertEquals(0, store.saves);
            assertFalse(setup.isActive());
        } finally {
            release.countDown();
        }
    }

    @Test
    public void cancellationAfterCommitPreservesTheCommittedConfiguration() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        ResultCapture result = new ResultCapture();
        setup.confirm("287082".toCharArray(), result);
        drainWorker();
        assertEquals(1, store.saves);
        setup.close();
        drainCallbacks();
        assertNull(result.result);
        assertNotNull(store.encoded);
    }

    @Test
    public void failedSaveRollsBackAndAllowsRetryWithTheSameSetup() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        store.failAfterSave = true;
        ResultCapture first = new ResultCapture();
        setup.confirm("287082".toCharArray(), first);
        flush();
        assertNotNull(first.error);
        assertNull(store.encoded);
        assertSame(setup, coordinator.getPendingSetup());
        store.failAfterSave = false;
        ResultCapture retry = new ResultCapture();
        setup.confirm("287082".toCharArray(), retry);
        flush();
        assertEquals(TotpEnrollmentService.Confirmation.ENABLED, retry.result);
    }

    @Test
    public void duplicateMalformedConfirmationKeepsTheFirstAttempt() throws Exception {
        TotpEnrollmentCoordinator.Setup setup = ready();
        CountDownLatch release = pauseWorker();
        try {
            ResultCapture first = new ResultCapture();
            setup.confirm(null, first);
            try {
                setup.confirm(null, new ResultCapture());
                fail("A duplicate confirmation was accepted.");
            } catch (IllegalStateException expected) {
                release.countDown();
                flush();
                assertEquals(TotpEnrollmentService.Confirmation.INVALID_CODE, first.result);
                assertEquals(4, first.remaining);
            }
        } finally {
            release.countDown();
        }
    }

    @Test
    public void callbackRejectionClosesThePreparedSecret() throws Exception {
        rejectCallbacks = true;
        coordinator.begin(MASTER.toCharArray(), new SetupCapture());
        drainWorker();
        assertNull(coordinator.getPendingSetup());
        assertEquals(0, store.saves);
        assertCleared(verifiedPassword);
    }

    private TotpEnrollmentCoordinator.Setup ready() throws Exception {
        SetupCapture capture = new SetupCapture();
        coordinator.begin(MASTER.toCharArray(), capture);
        flush();
        assertNull(capture.error);
        assertNotNull(capture.ready);
        return capture.ready;
    }

    private CountDownLatch pauseWorker() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        worker.execute(() -> {
            entered.countDown();
            try {
                assertTrue(release.await(2, TimeUnit.SECONDS));
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            }
        });
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        return release;
    }

    private void flush() throws Exception {
        drainWorker();
        drainCallbacks();
    }

    private void drainWorker() throws Exception {
        worker.submit(() -> {}).get(2, TimeUnit.SECONDS);
    }

    private void drainCallbacks() {
        Runnable action;
        while ((action = callbacks.poll()) != null) {
            action.run();
        }
    }

    private static void assertCleared(char[] value) {
        assertNotNull(value);
        for (char character : value) {
            assertEquals('\0', character);
        }
    }

    private static final class SetupCapture implements TotpEnrollmentCoordinator.SetupCallback {
        private TotpEnrollmentCoordinator.Setup ready;
        private Exception error;
        @Override public void onReady(TotpEnrollmentCoordinator.Setup setup) { ready = setup; }
        @Override public void onError(Exception error) { this.error = error; }
    }

    private static final class ResultCapture implements TotpEnrollmentCoordinator.ConfirmationCallback {
        private TotpEnrollmentService.Confirmation result;
        private int remaining;
        private Exception error;
        @Override public void onResult(TotpEnrollmentService.Confirmation result, int remaining) {
            this.result = result;
            this.remaining = remaining;
        }
        @Override public void onError(Exception error) { this.error = error; }
    }

    private static final class FixedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        @Override public void nextBytes(byte[] bytes) {
            System.arraycopy(SECRET, 0, bytes, 0, bytes.length);
        }
    }

    private final class MemoryStore implements TotpEnrollmentService.EnrollmentStore {
        private final Object transactionLock = new Object();
        private byte[] encoded;
        private int saves;
        private boolean failAfterSave;
        @Override public Object getTransactionLock() { return transactionLock; }
        @Override public PanicRuntimeScope getPanicRuntimeScope() { return scope; }
        @Override public TotpState load() {
            assertTrue(Thread.holdsLock(transactionLock));
            return encoded == null ? null : TotpState.decode(encoded);
        }
        @Override public void save(TotpState state) throws IOException {
            assertTrue(Thread.holdsLock(transactionLock));
            assertTrue("A write escaped its authentication guard", Thread.holdsLock(session));
            encoded = state.encode();
            saves++;
            if (failAfterSave) {
                throw new IOException("Simulated incomplete write.");
            }
        }
        @Override public void clear() {
            assertTrue(Thread.holdsLock(transactionLock));
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            encoded = null;
        }
    }
}

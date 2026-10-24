package com.safekey.app.security.totp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.os.Handler;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class VaultUnlockSessionClaimInstrumentedTest {

    private ExecutorService worker;
    private FakeVault vault;
    private VaultUnlockFlow flow;
    private AtomicLong elapsed;

    @Before
    public void setUp() {
        worker = Executors.newSingleThreadExecutor();
        vault = new FakeVault();
        elapsed = new AtomicLong();

        flow = new VaultUnlockFlow(
                new VaultUnlockGate(new EmptyStore()),
                worker,
                new Handler(Looper.getMainLooper()),
                vault,
                elapsed::get
        );
    }

    @After
    public void tearDown() {
        flow.shutdown();
        worker.shutdown();
    }

    @Test
    public void closingCompletedButUnclaimedRequestClosesItsConnection()
            throws Exception {
        Outcome outcome = new Outcome();
        VaultUnlockFlow.Request request = begin(outcome);

        await(outcome.done);
        assertNull(outcome.error.get());

        request.close();

        assertEquals(2, vault.closes.get());
        assertFalse(request.claimSession());
    }

    @Test
    public void sessionCanBeClaimedOnce_andLaterCloseDoesNotCloseIt()
            throws Exception {
        Outcome outcome = new Outcome();
        VaultUnlockFlow.Request request = begin(outcome);

        await(outcome.done);
        assertNull(outcome.error.get());

        assertTrue(request.claimSession());
        assertFalse(request.claimSession());

        int closes = vault.closes.get();
        request.close();

        assertEquals(closes, vault.closes.get());
    }

    @Test
    public void cancelledOpeningCannotBeClaimedOrDeliverSuccess()
            throws Exception {
        vault.holdOpen = true;

        Outcome outcome = new Outcome();
        VaultUnlockFlow.Request request = begin(outcome);

        await(vault.openRequested);

        request.close();
        vault.pending.get().onSuccess();
        drainMain();

        assertFalse(request.claimSession());
        assertEquals(0, outcome.successes.get());
        assertEquals(2, vault.closes.get());
    }

    @Test
    public void oldCompletedRequestCannotCloseOrClaimReplacement()
            throws Exception {
        Outcome first = new Outcome();
        VaultUnlockFlow.Request old = begin(first);
        await(first.done);

        Outcome second = new Outcome();
        VaultUnlockFlow.Request replacement = begin(second);
        await(second.done);

        assertNull(first.error.get());
        assertNull(second.error.get());

        int closes = vault.closes.get();

        old.close();

        assertFalse(old.claimSession());
        assertEquals(closes, vault.closes.get());
        assertTrue(replacement.claimSession());
    }

    @Test
    public void expiredUnclaimedConnectionCannotBeClaimed()
            throws Exception {
        Outcome outcome = new Outcome();
        VaultUnlockFlow.Request request = begin(outcome);

        await(outcome.done);
        elapsed.set(VaultUnlockGate.ATTEMPT_LIFETIME_MILLIS);

        assertFalse(request.claimSession());
        assertEquals(2, vault.closes.get());
    }

    private VaultUnlockFlow.Request begin(Outcome outcome) {
        VaultUnlockFlow.Request request = flow.begin(outcome);
        flow.acceptPrimary(request, new byte[32]);
        return request;
    }

    private static void await(CountDownLatch latch)
            throws InterruptedException {
        CallbackTimeoutDiagnostics.await(latch, 10L);
    }

    private static void drainMain() throws InterruptedException {
        CountDownLatch done = new CountDownLatch(1);
        new Handler(Looper.getMainLooper()).post(done::countDown);
        await(done);
    }

    private static final class Outcome
            implements VaultUnlockFlow.Listener {

        final CountDownLatch done = new CountDownLatch(1);
        final AtomicInteger successes = new AtomicInteger();

        final AtomicReference<Exception> error =
                new AtomicReference<>();

        @Override
        public boolean requiresSessionClaim() {
            return true;
        }

        @Override
        public void onSuccess() {
            successes.incrementAndGet();
            done.countDown();
        }

        @Override
        public void onError(Exception failure) {
            error.set(failure);
            done.countDown();
        }

        @Override
        public void onTotpRequired(VaultUnlockFlow.Request request) {
            onError(
                    new IllegalStateException("Unexpected TOTP challenge.")
            );
        }
    }

    private static final class EmptyStore
            implements TotpVerificationService.StateStore {

        private final Object lock = new Object();

        @Override
        public Object getTransactionLock() {
            return lock;
        }

        @Override
        public TotpState load() {
            return null;
        }

        @Override
        public void save(TotpState state) {
            throw new AssertionError(
                    "No TOTP state should be written."
            );
        }
    }

    private static final class FakeVault
            implements VaultUnlockFlow.VaultAccess {

        final AtomicInteger closes = new AtomicInteger();
        final CountDownLatch openRequested = new CountDownLatch(1);

        final AtomicReference<VaultDataService.SimpleCallback> pending =
                new AtomicReference<>();

        volatile boolean holdOpen;

        @Override
        public void open(
                byte[] key,
                VaultDataService.SimpleCallback callback
        ) {
            pending.set(callback);
            openRequested.countDown();

            if (!holdOpen) {
                callback.onSuccess();
            }
        }

        @Override
        public void close(VaultDataService.SimpleCallback callback) {
            closes.incrementAndGet();
            callback.onSuccess();
        }
    }
}

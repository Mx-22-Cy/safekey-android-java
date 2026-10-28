package com.safekey.app.security.panic;

import android.os.Handler;
import android.os.Looper;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Real UI cancellation followed by background worker/database termination. */
public final class PanicAndroidRuntime implements PanicWipeCoordinator.Runtime {
    private final PanicRuntimeScope scope;
    private final Handler main;
    private final Runnable clearSession;

    public PanicAndroidRuntime(PanicRuntimeScope scope, Handler main, Runnable clearSession) {
        this.scope = Objects.requireNonNull(scope, "scope");
        this.main = Objects.requireNonNull(main, "main");
        this.clearSession = Objects.requireNonNull(clearSession, "clearSession");
    }

    @Override public PanicWorkGate getWorkGate() { return scope.getWorkGate(); }

    @Override public void lockAndClearSession() throws Exception {
        Runnable action = () -> {
            try { scope.cancelPending(); }
            finally { clearSession.run(); }
        };
        if (Looper.myLooper() == Looper.getMainLooper()) {
            action.run();
            return;
        }
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<RuntimeException> failure = new AtomicReference<>();
        if (!main.post(() -> {
            try { action.run(); }
            catch (RuntimeException error) { failure.set(error); }
            finally { done.countDown(); }
        })) { throw new IOException("Unable to cancel vault UI work."); }
        try {
            if (!done.await(30L, TimeUnit.SECONDS)) {
                throw new IOException("Timed out cancelling vault UI work.");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        }
        if (failure.get() != null) { throw failure.get(); }
    }

    @Override public void closeResources() throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Close vault resources on a worker thread.");
        }
        scope.closeAndAwait(30_000L);
    }

    @Override public boolean areResourcesClosed() { return scope.areResourcesClosed(); }
}

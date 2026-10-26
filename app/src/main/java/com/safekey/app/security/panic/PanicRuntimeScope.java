package com.safekey.app.security.panic;

import android.content.Context;
import android.os.Handler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** One captured scope for every producer and secret holder in a vault runtime. */
public final class PanicRuntimeScope {
    public interface Owner {
        PanicRuntimeScope getPanicRuntimeScope();
    }

    public interface Resource {
        void closeAndAwait(long deadlineNanos) throws Exception;
        boolean isClosed();
    }

    private final PanicWorkGate gate = new PanicWorkGate();
    private final List<Registration> cancellations = new ArrayList<>();
    private final List<Resource> resources = new ArrayList<>();
    private boolean cancellationFailed;

    public static PanicRuntimeScope capture(Context context) {
        Context app = Objects.requireNonNull(context, "context").getApplicationContext();
        return app instanceof Owner
                ? Objects.requireNonNull(((Owner) app).getPanicRuntimeScope(), "runtimeScope")
                : new PanicRuntimeScope();
    }

    public PanicWorkGate getWorkGate() { return gate; }
    public PanicWorkGate.Operation begin() { return gate.begin(); }
    public boolean isStopped() { return gate.isBlocked(); }

    /** Count work at submission, retaining ownership through its actual finally block. */
    public void execute(Executor executor, Runnable work) {
        Objects.requireNonNull(work, "work");
        PanicWorkGate.Operation operation = begin();
        try {
            executor.execute(() -> {
                try { work.run(); }
                finally { operation.close(); }
            });
        } catch (RuntimeException error) {
            operation.close();
            throw error;
        }
    }

    /** Clear queued payload references when the main-thread cancellation runs. */
    public boolean deliver(Handler handler, Runnable action) {
        AtomicReference<Runnable> payload = new AtomicReference<>(action);
        Runnable[] queued = new Runnable[1];
        final PendingOperation pending;
        try {
            pending = pending(() -> payload.set(null), () -> {
                if (queued[0] != null) { handler.removeCallbacks(queued[0]); }
            });
        } catch (java.util.concurrent.CancellationException stopped) {
            payload.set(null);
            return false;
        }
        queued[0] = () -> {
            try {
                Runnable current = payload.getAndSet(null);
                if (pending.isCurrent() && current != null) { current.run(); }
            } finally { pending.close(); }
        };
        if (!pending.isCurrent()) { pending.close(); return false; }
        try {
            boolean posted = handler.post(queued[0]);
            if (!posted) { pending.close(); }
            return posted;
        } catch (RuntimeException error) {
            pending.close();
            throw error;
        }
    }

    public Registration onStop(Runnable action) {
        Registration registration = new Registration(Objects.requireNonNull(action, "action"));
        boolean stopped;
        synchronized (this) {
            stopped = isStopped();
            if (!stopped) { cancellations.add(registration); }
        }
        if (stopped) { registration.cancel(); }
        return registration;
    }

    /** Pending prompts and key handoffs retain an operation until cleared or cancelled. */
    public PendingOperation pending(Runnable clear, Runnable cancel) {
        return new PendingOperation(clear, cancel);
    }

    public synchronized void registerResource(Resource resource) {
        if (isStopped()) {
            throw new IllegalStateException("Cannot add resources to a stopped runtime.");
        }
        resources.add(Objects.requireNonNull(resource, "resource"));
    }

    public void registerExecutor(ExecutorService executor) {
        registerResource(new Resource() {
            @Override public void closeAndAwait(long deadline) throws Exception {
                executor.shutdown();
                if (!executor.awaitTermination(remainingMillis(deadline), TimeUnit.MILLISECONDS)) {
                    throw new TimeoutException("Security worker did not terminate.");
                }
            }
            @Override public boolean isClosed() { return executor.isTerminated(); }
        });
    }

    /** Run cancellation on the UI thread when its owners include biometric prompts. */
    public void cancelPending() {
        gate.blockNewWork();
        List<Registration> pending;
        synchronized (this) { pending = new ArrayList<>(cancellations); }
        RuntimeException failure = null;
        for (Registration registration : pending) {
            try { registration.cancel(); }
            catch (RuntimeException error) {
                if (failure == null) { failure = new IllegalStateException("Runtime cancellation failed."); }
                failure.addSuppressed(error);
            }
        }
        if (failure != null) { throw failure; }
    }

    /** Worker-only terminal barrier. Every resource is attempted before reporting failure. */
    public void closeAndAwait(long timeoutMillis) throws Exception {
        if (!isStopped() || timeoutMillis <= 0) {
            throw new IllegalStateException("Stop the runtime before closing resources.");
        }
        synchronized (this) {
            if (cancellationFailed || !cancellations.isEmpty()) {
                throw new IllegalStateException("Cancel pending owners before closing resources.");
            }
        }
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        try {
            gate.awaitIdle(timeoutMillis, TimeUnit.MILLISECONDS);
            List<Resource> snapshot;
            synchronized (this) { snapshot = new ArrayList<>(resources); }
            IOException failure = new IOException("Runtime resources did not close.");
            boolean interrupted = false;
            try {
                for (Resource resource : snapshot) {
                    try { resource.closeAndAwait(deadline); }
                    catch (InterruptedException error) {
                        interrupted = true;
                        failure.addSuppressed(error);
                    }
                    catch (Exception error) { failure.addSuppressed(error); }
                }
            } finally {
                if (interrupted) { Thread.currentThread().interrupt(); }
            }
            if (!areResourcesClosed()) {
                failure.addSuppressed(new IOException("A vault connection or worker remains open."));
            }
            if (failure.getSuppressed().length != 0) { throw failure; }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        }
    }

    public boolean areResourcesClosed() {
        if (!isStopped() || !gate.isIdle()) { return false; }
        List<Resource> snapshot;
        synchronized (this) {
            if (cancellationFailed || !cancellations.isEmpty()) { return false; }
            snapshot = new ArrayList<>(resources);
        }
        for (Resource resource : snapshot) {
            if (!resource.isClosed()) { return false; }
        }
        return true;
    }

    public static long remainingMillis(long deadlineNanos) throws TimeoutException {
        long remaining = deadlineNanos - System.nanoTime();
        if (remaining <= 0) { throw new TimeoutException("Runtime shutdown timed out."); }
        return Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remaining));
    }

    public final class Registration implements AutoCloseable {
        private final Runnable action;
        private final AtomicBoolean closed = new AtomicBoolean();
        private Registration(Runnable action) { this.action = action; }
        private void cancel() {
            if (closed.compareAndSet(false, true)) {
                try { action.run(); }
                catch (RuntimeException error) {
                    synchronized (PanicRuntimeScope.this) { cancellationFailed = true; }
                    throw error;
                }
                finally { synchronized (PanicRuntimeScope.this) { cancellations.remove(this); } }
            }
        }
        @Override public void close() {
            if (closed.compareAndSet(false, true)) {
                synchronized (PanicRuntimeScope.this) { cancellations.remove(this); }
            }
        }
    }

    public final class PendingOperation implements AutoCloseable {
        private final PanicWorkGate.Operation operation;
        private final Runnable clear;
        private final Runnable cancel;
        private final AtomicBoolean closed = new AtomicBoolean();
        private Registration registration;

        private PendingOperation(Runnable clear, Runnable cancel) {
            this.clear = Objects.requireNonNull(clear, "clear");
            this.cancel = Objects.requireNonNull(cancel, "cancel");
            operation = begin();
            try {
                registration = onStop(() -> finish(true));
                if (closed.get()) { registration.close(); }
            } catch (RuntimeException error) {
                finish(false);
                throw error;
            }
        }

        public boolean isCurrent() { return !closed.get() && !isStopped(); }
        @Override public void close() { finish(false); }

        private void finish(boolean cancelled) {
            if (!closed.compareAndSet(false, true)) { return; }
            try {
                try { clear.run(); }
                finally { if (cancelled) { cancel.run(); } }
            } finally {
                if (registration != null) { registration.close(); }
                operation.close();
            }
        }
    }
}

package com.safekey.app.security.panic;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;

/** One startup attempt. Initialization is forbidden until recovery succeeds. */
public final class PanicStartupGate {
    public enum State { NEW, RECOVERING, READY, FAILED }

    public interface Recovery {
        boolean isPending() throws Exception;
        void recover() throws Exception;
    }

    public interface Runtime {
        void block();
        void initialize(boolean recovered) throws Exception;
    }

    private final Recovery recovery;
    private final Runtime runtime;
    private final Executor worker;
    private final Executor main;
    private final List<Runnable> listeners = new ArrayList<>();
    private volatile State state = State.NEW;
    private volatile Exception failure;
    private volatile boolean recovered;
    private boolean started;

    public PanicStartupGate(Recovery recovery, Runtime runtime, Executor worker, Executor main) {
        this.recovery = Objects.requireNonNull(recovery, "recovery");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.worker = Objects.requireNonNull(worker, "worker");
        this.main = Objects.requireNonNull(main, "main");
    }

    /** Call on the UI thread; the normal path only probes marker existence. */
    public void start() {
        synchronized (this) {
            if (started) { throw new IllegalStateException("Startup already attempted."); }
            started = true;
        }
        try {
            if (!recovery.isPending()) {
                initialize(false);
                return;
            }
            runtime.block();
            state = State.RECOVERING;
            notifyListeners();
            worker.execute(() -> {
                try {
                    recovery.recover();
                    if (recovery.isPending()) {
                        throw new IllegalStateException("Recovery marker remains.");
                    }
                    dispatch(() -> initialize(true));
                } catch (Exception error) {
                    dispatch(() -> fail(error));
                }
            });
        } catch (Exception error) {
            fail(error);
        }
    }

    private void dispatch(Runnable action) {
        try { main.execute(action); }
        catch (RuntimeException error) {
            // A dead UI dispatcher must never leave the gate ready.
            fail(error);
        }
    }

    private void initialize(boolean afterRecovery) {
        try {
            runtime.initialize(afterRecovery);
            recovered = afterRecovery;
            state = State.READY;
            notifyListeners();
        } catch (Exception error) {
            fail(error);
        }
    }

    private void fail(Exception error) {
        try { runtime.block(); }
        catch (RuntimeException blockingError) { error.addSuppressed(blockingError); }
        failure = error;
        state = State.FAILED;
        notifyListeners();
    }

    public State getState() { return state; }
    public Exception getFailure() { return failure; }
    public boolean wasRecovered() { return recovered; }

    /** Observers only update UI; an observer failure cannot change startup outcome. */
    public AutoCloseable observe(Runnable listener) {
        Objects.requireNonNull(listener, "listener");
        synchronized (listeners) { listeners.add(listener); }
        return () -> { synchronized (listeners) { listeners.remove(listener); } };
    }

    private void notifyListeners() {
        List<Runnable> snapshot;
        synchronized (listeners) { snapshot = new ArrayList<>(listeners); }
        for (Runnable listener : snapshot) {
            try { listener.run(); }
            catch (RuntimeException ignored) { /* Isolate UI observers. */ }
        }
    }
}

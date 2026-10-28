package com.safekey.app.security.panic;

import android.os.Handler;
import android.os.Looper;

import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Cancel a queued commit on timeout; retain ownership until an executing commit finishes. */
final class PanicMainThread {
    private final Handler main = new Handler(Looper.getMainLooper());

    <T> T call(Callable<T> action) throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) { return action.call(); }
        Posted<T> posted = new Posted<>(action);
        if (!main.post(posted)) { throw new IllegalStateException("UI dispatcher is unavailable."); }
        try { return posted.await(); }
        finally { main.removeCallbacks(posted); }
    }

    private static final class Posted<T> implements Runnable {
        private final Callable<T> action;
        private boolean running;
        private boolean cancelled;
        private boolean done;
        private T result;
        private Throwable failure;

        Posted(Callable<T> action) { this.action = action; }

        @Override public void run() {
            synchronized (this) {
                if (cancelled) { return; }
                running = true;
                notifyAll();
            }
            try { result = action.call(); }
            catch (Throwable error) { failure = error; }
            finally { synchronized (this) { done = true; notifyAll(); } }
        }

        synchronized T await() throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            boolean interrupted = false;
            try {
                while (!done) {
                    long remaining = deadline - System.nanoTime();
                    if (!running && remaining <= 0) {
                        cancelled = true;
                        throw new TimeoutException("Timed out awaiting enrollment authorization.");
                    }
                    try {
                        if (running) { wait(); }
                        else { TimeUnit.NANOSECONDS.timedWait(this, remaining); }
                    } catch (InterruptedException error) {
                        interrupted = true;
                        if (!running) { cancelled = true; throw error; }
                        // A write already executing must finish before its counted worker exits.
                    }
                }
                if (failure instanceof Exception) { throw (Exception) failure; }
                if (failure instanceof Error) { throw (Error) failure; }
                return result;
            } finally {
                if (interrupted) { Thread.currentThread().interrupt(); }
            }
        }
    }
}

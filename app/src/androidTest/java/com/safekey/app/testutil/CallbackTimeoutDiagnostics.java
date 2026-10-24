package com.safekey.app.testutil;

import android.os.Handler;
import android.os.Looper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Adds thread diagnostics after a test's original wait has already failed. */
public final class CallbackTimeoutDiagnostics {

    private CallbackTimeoutDiagnostics() {
    }

    public static void await(CountDownLatch latch, long waitSeconds)
            throws InterruptedException {
        Looper mainLooper = Looper.getMainLooper();

        if (Looper.myLooper() == mainLooper) {
            throw new AssertionError(
                    "A callback wait must not block Android's main thread."
            );
        }

        if (latch.await(waitSeconds, TimeUnit.SECONDS)) {
            return;
        }

        throw timeout(
                "Timed out waiting for callback. Limit: "
                        + waitSeconds + " seconds.",
                latch
        );
    }

    /** For an existing condition poll that has already reached its deadline. */
    public static AssertionError timeout(String description) {
        return timeout(description, null);
    }

    private static AssertionError timeout(
            String description,
            CountDownLatch originalLatch
    ) {
        Looper mainLooper = Looper.getMainLooper();
        StringBuilder details = new StringBuilder(description).append('\n');

        Thread waiting = Thread.currentThread();
        details.append("Waiting thread: ").append(waiting.getName())
                .append(" [").append(waiting.getState()).append("]\n");
        if (originalLatch != null) {
            details.append("Latch count at timeout: ")
                    .append(originalLatch.getCount()).append('\n');
        }

        // Capture the threads before probing the main queue.
        try {
            List<Map.Entry<Thread, StackTraceElement[]>> threads =
                    new ArrayList<>(Thread.getAllStackTraces().entrySet());

            threads.sort((left, right) -> {
                int names = left.getKey().getName()
                        .compareTo(right.getKey().getName());
                return names != 0 ? names : Long.compare(
                        left.getKey().getId(), right.getKey().getId()
                );
            });

            details.append("\nThread stacks captured at timeout:\n");

            for (Map.Entry<Thread, StackTraceElement[]> entry : threads) {
                Thread thread = entry.getKey();
                details.append('\n').append(thread.getName())
                        .append(" [").append(thread.getState()).append("]\n");

                for (StackTraceElement frame : entry.getValue()) {
                    details.append("    at ").append(frame).append('\n');
                }
            }
        } catch (RuntimeException diagnosticError) {
            details.append("Thread snapshot unavailable: ")
                    .append(diagnosticError).append('\n');
        }

        if (Looper.myLooper() == mainLooper) {
            details.append("\nMain-thread probe skipped: already on main thread.\n");
            return new AssertionError(details.toString());
        }

        // A short probe after the failure checks whether the main queue responds.
        // Its result is diagnostic only: the original timeout still fails.
        Handler handler = new Handler(mainLooper);
        CountDownLatch pulse = new CountDownLatch(1);
        Runnable ping = pulse::countDown;

        try {
            boolean posted = handler.post(ping);
            boolean answered = posted && pulse.await(500, TimeUnit.MILLISECONDS);
            details.append("\nMain-thread probe after timeout: posted=")
                    .append(posted).append(", answeredWithin500ms=")
                    .append(answered).append('\n');
            if (originalLatch != null) {
                details.append("Original latch count after probe: ")
                        .append(originalLatch.getCount()).append('\n');
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            details.append("\nMain-thread probe interrupted.\n");
        } catch (RuntimeException diagnosticError) {
            details.append("\nMain-thread probe unavailable: ")
                    .append(diagnosticError).append('\n');
        } finally {
            handler.removeCallbacks(ping);
        }

        return new AssertionError(details.toString());
    }
}

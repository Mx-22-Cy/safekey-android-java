package com.safekey.app.securityui;

import com.safekey.app.security.totp.TotpEnrollmentCoordinator;
import com.safekey.app.security.totp.TotpEnrollmentService;

/**
 * In-process, Activity-independent confirmation receipt. It stores NO TOTP code
 * or secret. The owning enrollment is session-bound by the coordinator.
 * Must be called only on the main thread (coordinator delivers callbacks on main).
 */
final class TotpConfirmationState {
    interface Listener {
        void onConfirmation(TotpEnrollmentService.Confirmation result,
                            int remainingAttempts, boolean failed);
    }

    private static TotpEnrollmentCoordinator.Setup owner;
    private static Listener listener;
    private static boolean confirming;
    private static boolean completed;
    private static boolean failed;
    private static TotpEnrollmentService.Confirmation result;
    private static int remaining;

    private TotpConfirmationState() { }

    static void submit(TotpEnrollmentCoordinator.Setup setup, char[] code) {
        if (confirming) { throw new IllegalStateException("Confirmation already running"); }
        discard();
        owner = setup;
        confirming = true;
        try {
            setup.confirm(code, new TotpEnrollmentCoordinator.ConfirmationCallback() {
                @Override public void onResult(TotpEnrollmentService.Confirmation value, int attempts) {
                    finish(value, attempts, false);
                }
                @Override public void onError(Exception error) { finish(null, 0, true); }
            });
        } catch (RuntimeException error) {
            discard();
            throw error;
        }
    }

    private static void finish(TotpEnrollmentService.Confirmation value,
                               int attempts, boolean isError) {
        confirming = false;
        completed = true;
        result = value;
        remaining = attempts;
        failed = isError;
        dispatch();
    }

    static void observe(Listener next) {
        listener = next;
        if (completed) { dispatch(); }
    }

    static void stopObserving(Listener stopped) {
        if (listener == stopped) { listener = null; }
    }

    static boolean isConfirming() { return confirming; }
    static boolean hasResult() { return completed; }

    static boolean isSessionCurrent() {
        try { return owner != null && owner.isSessionValid(); }
        catch (RuntimeException error) { return false; }
    }

    static void consume() { discard(); }

    static void discard() {
        // Never close owner here: that may cancel an in-flight backend operation.
        owner = null;
        confirming = false;
        completed = false;
        failed = false;
        result = null;
        remaining = 0;
    }

    private static void dispatch() {
        Listener current = listener;
        if (current != null && completed) {
            current.onConfirmation(result, remaining, failed);
        }
    }
}

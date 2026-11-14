package com.safekey.app.auth;

import android.os.Handler;
import android.os.Looper;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.panic.PanicBackend;
import com.safekey.app.security.panic.PanicSignInService;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Application-owned password role router. This class never grants a vault session:
 * the caller must complete the selected vault's ordinary authentication and
 * session-claim flow before activation.
 *
 * The supplied executor MUST be an independent control worker, not an executor
 * registered with the Panic runtime. The terminal callback MUST be owned by the
 * application, not an Activity.
 */
public final class SignInController implements AutoCloseable {

    public interface PanicTerminalHandler {
        /** Runs on main even when the initiating Activity has been destroyed. */
        void onPanicWiped(PanicBackend completedBackend);

        /** A committed destructive cleanup failed; keep authentication blocked. */
        void onPanicFailed(PanicBackend backend, Exception error);
    }

    public interface SignInCallback {
        /**
         * Runs on main. Password is owned by the controller and is erased after
         * this method returns. Any asynchronous vault-unlock API must copy the
         * password before returning from this callback.
         */
        void onRoleIdentified(PanicSignInService.Result role, char[] password);

        /** Runs on main for readiness, execution, or routing failures. */
        void onError(Exception error);
    }

    private final SafeKeyApplication application;
    private final Executor controlWorker;
    private final Handler mainHandler;
    private final PanicTerminalHandler terminalHandler;
    private final Object lock = new Object();

    private Attempt current;
    private boolean closed;

    public SignInController(
            SafeKeyApplication application,
            Executor controlWorker,
            Handler mainHandler,
            PanicTerminalHandler terminalHandler
    ) {
        this.application = Objects.requireNonNull(application, "application");
        this.controlWorker = Objects.requireNonNull(controlWorker, "controlWorker");
        this.mainHandler = Objects.requireNonNull(mainHandler, "mainHandler");
        this.terminalHandler = Objects.requireNonNull(terminalHandler, "terminalHandler");
        if (mainHandler.getLooper() != Looper.getMainLooper()) {
            throw new IllegalArgumentException("A main-thread handler is required.");
        }
    }

    /**
     * Starts a new attempt. Call after the UI has locked the previous session.
     * The caller retains ownership of password and should erase its own array.
     */
    public void startPasswordSignIn(char[] password, SignInCallback callback) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(callback, "callback");
        if (password.length == 0) {
            throw new IllegalArgumentException("Password is empty.");
        }

        Attempt attempt = new Attempt(password.clone(), callback);
        Attempt previous;
        synchronized (lock) {
            if (closed) {
                attempt.cancel();
                throw new IllegalStateException("Sign In controller is closed.");
            }
            previous = current;
            current = attempt;
        }
        if (previous != null) {
            previous.cancel();
        }

        try {
            application.prepareForVaultAuthentication(new VaultDataService.SimpleCallback() {
                @Override public void onSuccess() { dispatchWork(attempt); }
                @Override public void onError(Exception error) { deliverError(attempt, error); }
            });
        } catch (RuntimeException error) {
            deliverError(attempt, error);
        }
    }

    private void dispatchWork(Attempt attempt) {
        if (!isCurrent(attempt)) {
            return;
        }
        try {
            controlWorker.execute(() -> runRoleCheck(attempt));
        } catch (RuntimeException error) {
            deliverError(attempt, error);
        }
    }

    private void runRoleCheck(Attempt attempt) {
        PanicBackend backend = null;
        PanicBackend.SignInRequest request = null;
        try {
            if (!isCurrent(attempt)) {
                return;
            }
            // Capture before submission, so the terminal handler does not depend
            // on getPanicBackend() after runtime shutdown.
            backend = application.getPanicBackend();
            char[] candidate = attempt.copyForBackend();
            if (candidate == null) {
                return;
            }
            try {
                request = backend.prepareSignIn(candidate);
            } finally {
                Arrays.fill(candidate, '\0');
            }
            if (!attempt.attach(request)) {
                return;
            }
            PanicSignInService.Result result = request.run();
            if (result == PanicSignInService.Result.PANIC_WIPED) {
                // This is intentionally independent of the current attempt,
                // Activity lifetime, and controller closure. Maryam's app-level
                // handler is responsible for terminal deduplication and handoff.
                PanicBackend completedBackend = backend;
                if (!mainHandler.post(() -> terminalHandler.onPanicWiped(completedBackend))) {
                    throw new IllegalStateException("Cannot dispatch Panic terminal result.");
                }
            } else if (result == PanicSignInService.Result.NO_MATCH) {
                deliverRole(attempt, result);
            } else if (result == PanicSignInService.Result.MASTER
                    || result == PanicSignInService.Result.DECOY) {
                deliverRole(attempt, result);
            } else {
                deliverError(attempt, new IllegalStateException("Unknown Sign In result."));
            }
        } catch (Exception error) {
            // A failed destructive Panic remains terminal only when THIS request
            // committed Panic. Other shutdowns and ordinary Sign In errors must
            // never be misclassified as a committed wipe.
            if (backend != null && request != null && request.isPanicCommitted()) {
                PanicBackend failedBackend = backend;
                mainHandler.post(() -> terminalHandler.onPanicFailed(failedBackend, error));
            } else {
                deliverError(attempt, error);
            }
        } finally {
            if (request != null) {
                request.close();
            }
        }
    }

    private void deliverRole(Attempt attempt, PanicSignInService.Result role) {
        mainHandler.post(() -> {
            if (!isCurrent(attempt)) {
                return;
            }
            SignInCallback callback = attempt.callback();
            char[] password = attempt.takePassword();
            if (callback == null || password == null) {
                if (password != null) Arrays.fill(password, '\0');
                return;
            }
            try {
                callback.onRoleIdentified(role, password);
            } finally {
                Arrays.fill(password, '\0');
            }
        });
    }

    private void deliverError(Attempt attempt, Exception error) {
        mainHandler.post(() -> {
            if (!isCurrent(attempt)) {
                return;
            }
            SignInCallback callback = attempt.callback();
            attempt.erasePassword();
            if (callback != null) {
                callback.onError(error);
            }
        });
    }

    private boolean isCurrent(Attempt attempt) {
        synchronized (lock) {
            return !closed && current == attempt && !attempt.isCancelled();
        }
    }

    public void cancelCurrentAttempt() {
        Attempt old;
        synchronized (lock) {
            old = current;
            current = null;
        }
        if (old != null) old.cancel();
    }

    /**
     * Cancels only the attempt owned by the specified Activity callback.
     * An obsolete Activity cannot cancel a newer Activity's attempt.
     */
    public void cancelCurrentAttempt(SignInCallback owner) {
        Objects.requireNonNull(owner, "owner");
        Attempt old = null;
        synchronized (lock) {
            if (current != null && current.matches(owner)) {
                old = current;
                current = null;
            }
        }
        if (old != null) old.cancel();
    }

    /** Detaches only the callback that still owns the current attempt. */
    public void detachCallback(SignInCallback callback) {
        cancelCurrentAttempt(callback);
    }

    @Override public void close() {
        Attempt old;
        synchronized (lock) {
            if (closed) return;
            closed = true;
            old = current;
            current = null;
        }
        if (old != null) old.cancel();
        // Do not shut down the injected executor: SafeKeyApplication owns it.
    }

    private static final class Attempt {
        private char[] password;
        private SignInCallback callback;
        private PanicBackend.SignInRequest request;
        private boolean cancelled;

        Attempt(char[] password, SignInCallback callback) {
            this.password = password;
            this.callback = callback;
        }

        synchronized char[] copyForBackend() {
            return cancelled || password == null ? null : password.clone();
        }

        synchronized boolean attach(PanicBackend.SignInRequest next) {
            if (cancelled) {
                next.close();
                return false;
            }
            request = next;
            return true;
        }

        synchronized SignInCallback callback() { return cancelled ? null : callback; }
        synchronized boolean matches(SignInCallback other) { return callback == other; }
        synchronized boolean isCancelled() { return cancelled; }

        synchronized char[] takePassword() {
            if (cancelled) return null;
            char[] result = password;
            password = null;
            return result;
        }

        synchronized void erasePassword() {
            if (password != null) {
                Arrays.fill(password, '\0');
                password = null;
            }
        }

        void cancel() {
            PanicBackend.SignInRequest toClose;
            synchronized (this) {
                if (cancelled) return;
                cancelled = true;
                callback = null;
                erasePassword();
                toClose = request;
                request = null;
            }
            // Do not block the attempt monitor during a committed wipe.
            if (toClose != null) toClose.close();
        }
    }
}

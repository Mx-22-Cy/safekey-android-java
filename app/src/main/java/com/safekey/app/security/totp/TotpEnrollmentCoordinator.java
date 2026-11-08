package com.safekey.app.security.totp;

import com.safekey.app.security.panic.PanicRuntimeScope;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Supplier;

/** Authenticated enrollment adapter exposed by SafeKeyApplication. */
public final class TotpEnrollmentCoordinator {
    /** Captures one REAL authentication and atomically guards its operations. */
    public interface Authorization {
        boolean runIfCurrent(Runnable action);
    }

    public interface PasswordVerifier {
        void verify(char[] password) throws Exception;
    }

    public interface SetupCallback {
        void onReady(Setup setup);
        void onError(Exception error);
    }

    public interface ConfirmationCallback {
        void onResult(TotpEnrollmentService.Confirmation result, int remainingAttempts);
        void onError(Exception error);
    }

    /** The REAL authentication captured by setup has expired or changed. */
    public static final class SessionInvalidException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        public SessionInvalidException() {
            super("The REAL vault authentication has expired or changed.");
        }
    }

    private final Object lock = new Object();
    private final TotpEnrollmentService enrollment;
    private final PasswordVerifier passwordVerifier;
    private final Supplier<Authorization> authorizations;
    private final ScheduledExecutorService worker;
    private final Executor callbacks;
    private final PanicRuntimeScope runtimeScope;
    private volatile Setup current;

    /** Application wiring supplies the security worker and main-thread dispatcher. */
    public TotpEnrollmentCoordinator(
            TotpEnrollmentService enrollment,
            PasswordVerifier passwordVerifier,
            Supplier<Authorization> authorizations,
            ScheduledExecutorService worker,
            Executor callbacks,
            PanicRuntimeScope runtimeScope
    ) {
        this.enrollment = Objects.requireNonNull(enrollment, "enrollment");
        this.passwordVerifier = Objects.requireNonNull(passwordVerifier, "passwordVerifier");
        this.authorizations = Objects.requireNonNull(authorizations, "authorizations");
        this.worker = Objects.requireNonNull(worker, "worker");
        this.callbacks = Objects.requireNonNull(callbacks, "callbacks");
        this.runtimeScope = Objects.requireNonNull(runtimeScope, "runtimeScope");
    }

    /** Starts on the UI thread. The caller owns and clears the original password. */
    public Setup begin(char[] masterPassword, SetupCallback callback) {
        Objects.requireNonNull(callback, "callback");
        if (masterPassword == null || masterPassword.length == 0) {
            throw new IllegalArgumentException("The master password is required.");
        }
        if (getPendingSetup() != null) {
            throw new IllegalStateException("TOTP setup is already in progress.");
        }
        Authorization authorization = Objects.requireNonNull(authorizations.get(), "authorization");
        Setup setup = new Setup(authorization, masterPassword.clone(), callback);
        try {
            if (!authorization.runIfCurrent(() -> {
                synchronized (lock) {
                    if (runtimeScope.isStopped()) {
                        throw new SessionInvalidException();
                    }
                    if (current != null) {
                        throw new IllegalStateException("TOTP setup is already in progress.");
                    }
                    current = setup;
                }
            })) {
                throw new SessionInvalidException();
            }
            setup.cancellation = runtimeScope.onStop(setup::invalidateSession);
            if (setup.cancelled) {
                setup.cancellation.close();
                throw new IllegalStateException("TOTP setup was cancelled.");
            }
            runtimeScope.execute(worker, () -> prepare(setup));
            return setup;
        } catch (RuntimeException error) {
            setup.close();
            throw error;
        }
    }

    /** Reuses the same setup while navigating between the Setup and Verify screens. */
    public Setup getPendingSetup() {
        Setup setup = current;
        return setup != null && setup.isActive() ? setup : null;
    }

    /** Application session cleanup calls this before closing vault connections. */
    public void cancelPending() {
        Setup setup = current;
        if (setup != null) {
            setup.close();
        }
    }

    /** Revokes setup when the application locks or invalidates its REAL session. */
    public void invalidateSession() {
        Setup setup = current;
        if (setup != null) {
            setup.invalidateSession();
        }
    }

    public final class Setup implements AutoCloseable {
        private final Authorization authorization;
        private SetupCallback callback;
        private char[] password;
        private TotpEnrollmentService.PendingSetup pending;
        private ConfirmationAttempt confirmation;
        private ScheduledFuture<?> expiry;
        private volatile PanicRuntimeScope.Registration cancellation;
        private volatile boolean cancelled;
        private volatile boolean sessionInvalid;
        private boolean terminal;

        private Setup(Authorization authorization, char[] password, SetupCallback callback) {
            this.authorization = authorization;
            this.password = password;
            this.callback = callback;
        }

        public boolean isActive() {
            boolean[] active = {false};
            boolean[] finished = {false};
            authorize(this, () -> {
                finished[0] = terminal;
                active[0] = !terminal && (pending == null || pending.isActive());
            });
            if (!active[0] && !finished[0]) {
                close();
            }
            return active[0];
        }

        public boolean isReady() {
            if (!isActive()) {
                return false;
            }
            synchronized (lock) {
                return !cancelled && !terminal && pending != null;
            }
        }

        /** Allows lifecycle code to identify lost authentication after an asynchronous cancellation. */
        public boolean isSessionValid() {
            if (sessionInvalid || runtimeScope.isStopped()
                    || !authorization.runIfCurrent(() -> {})) {
                invalidateSession();
                return false;
            }
            return true;
        }

        /** Caller owns and clears this copy after rendering the manual key. */
        public char[] copyBase32Secret() {
            return read(TotpEnrollmentService.PendingSetup::copyBase32Secret);
        }

        /** Sensitive QR payload. Render locally and discard it when the screen stops. */
        public String getAuthenticatorUri() {
            return read(TotpEnrollmentService.PendingSetup::getAuthenticatorUri);
        }

        public int getRemainingAttempts() {
            return read(TotpEnrollmentService.PendingSetup::getRemainingAttempts);
        }

        public long getRemainingMillis() {
            return read(TotpEnrollmentService.PendingSetup::getRemainingMillis);
        }

        /** Android application wiring uses SystemClock.elapsedRealtime() for this deadline. */
        public long getExpiresAtElapsedRealtimeMillis() {
            return read(TotpEnrollmentService.PendingSetup::getExpiresAtMonotonicMillis);
        }

        /** The caller owns and clears the original code. Results arrive on main. */
        public void confirm(char[] code, ConfirmationCallback callback) {
            ConfirmationAttempt attempt = new ConfirmationAttempt(code, callback);
            try {
                if (!authorize(this, () -> {
                    requireReady();
                    if (confirmation != null) {
                        throw new IllegalStateException("A confirmation is already in progress.");
                    }
                    confirmation = attempt;
                })) {
                    throw unavailable();
                }
                runtimeScope.execute(worker, () -> confirmInBackground(this, attempt));
            } catch (RuntimeException error) {
                synchronized (lock) {
                    if (confirmation == attempt) {
                        confirmation = null;
                    }
                    attempt.clearCode();
                }
                throw error;
            }
        }

        private <T> T read(Function<TotpEnrollmentService.PendingSetup, T> reader) {
            AtomicReference<T> result = new AtomicReference<>();
            if (!authorize(this, () -> {
                requireReady();
                result.set(reader.apply(pending));
            })) {
                throw unavailable();
            }
            return result.get();
        }

        private void requireReady() {
            if (terminal || pending == null) {
                throw new IllegalStateException("TOTP setup is not ready.");
            }
        }

        private IllegalStateException unavailable() {
            return sessionInvalid ? new SessionInvalidException()
                    : new IllegalStateException("TOTP setup has been closed.");
        }

        private void invalidateSession() {
            sessionInvalid = true;
            close();
        }

        @Override
        public void close() {
            cancelled = true;
            synchronized (lock) {
                clear(password);
                password = null;
                callback = null;
                if (confirmation != null) {
                    confirmation.clearCode();
                    confirmation = null;
                }
                if (pending != null) {
                    pending.close();
                    pending = null;
                }
                if (expiry != null) {
                    expiry.cancel(false);
                    expiry = null;
                }
                if (current == this) {
                    current = null;
                }
            }
            PanicRuntimeScope.Registration registration = cancellation;
            if (registration != null) {
                registration.close();
            }
        }
    }

    private static final class ConfirmationAttempt {
        private char[] code;
        private final ConfirmationCallback callback;

        private ConfirmationAttempt(char[] code, ConfirmationCallback callback) {
            this.callback = Objects.requireNonNull(callback, "callback");
            this.code = code != null && code.length == TotpGenerator.DEFAULT_DIGITS
                    ? code.clone() : null;
        }

        private void clearCode() {
            clear(code);
            code = null;
        }
    }

    private boolean authorize(Setup setup, Runnable action) {
        boolean[] executed = {false};
        if (!runtimeScope.isStopped() && setup.authorization.runIfCurrent(() -> {
            synchronized (lock) {
                if (current == setup && !setup.cancelled && !runtimeScope.isStopped()) {
                    executed[0] = true;
                    action.run();
                }
            }
        })) {
            return executed[0];
        }
        setup.invalidateSession();
        return false;
    }

    private void prepare(Setup setup) {
        char[] password;
        synchronized (lock) {
            if (current != setup || setup.cancelled) {
                return;
            }
            password = setup.password;
            setup.password = null;
        }
        try {
            passwordVerifier.verify(password);
            AtomicReference<Exception> failure = new AtomicReference<>();
            if (!authorize(setup, () -> {
                try {
                    setup.pending = enrollment.begin();
                    setup.expiry = worker.schedule(setup::close,
                            TotpEnrollmentService.SETUP_LIFETIME_MILLIS, TimeUnit.MILLISECONDS);
                } catch (Exception error) {
                    failure.set(error);
                }
            })) {
                return;
            }
            if (failure.get() != null) {
                throw failure.get();
            }
            post(setup, () -> authorize(setup, () -> {
                if (setup.pending.isActive()) {
                    SetupCallback callback = setup.callback;
                    setup.callback = null;
                    callback.onReady(setup);
                } else {
                    SetupCallback callback = setup.callback;
                    try {
                        callback.onError(new IllegalStateException("TOTP setup expired."));
                    } finally {
                        setup.close();
                    }
                }
            }));
        } catch (Exception error) {
            failPreparation(setup, error);
        } finally {
            clear(password);
        }
    }

    private void failPreparation(Setup setup, Exception error) {
        synchronized (lock) {
            if (current != setup || setup.cancelled) {
                return;
            }
            setup.terminal = true;
            if (setup.pending != null) {
                setup.pending.close();
            }
        }
        post(setup, () -> authorize(setup, () -> {
            try {
                setup.callback.onError(error);
            } finally {
                setup.close();
            }
        }));
    }

    private void confirmInBackground(Setup setup, ConfirmationAttempt attempt) {
        AtomicReference<TotpEnrollmentService.Confirmation> result = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        authorize(setup, () -> {
            if (setup.confirmation != attempt) {
                return;
            }
            char[] code = attempt.code;
            attempt.code = null;
            try {
                result.set(enrollment.confirm(setup.pending, code));
                setup.terminal = result.get() != TotpEnrollmentService.Confirmation.INVALID_CODE;
            } catch (Exception error) {
                failure.set(error);
                setup.terminal = !setup.pending.isActive();
            } finally {
                clear(code);
            }
        });
        if (result.get() == null && failure.get() == null) {
            return;
        }
        post(setup, () -> authorize(setup, () -> {
            if (setup.confirmation != attempt) {
                return;
            }
            setup.confirmation = null;
            try {
                if (failure.get() != null) {
                    attempt.callback.onError(failure.get());
                } else {
                    attempt.callback.onResult(result.get(), setup.pending.getRemainingAttempts());
                }
            } finally {
                if (setup.terminal) {
                    setup.close();
                }
            }
        }));
    }

    private void post(Setup setup, Runnable action) {
        try {
            callbacks.execute(action);
        } catch (RuntimeException rejected) {
            setup.close();
        }
    }

    private static void clear(char[] value) {
        if (value != null) {
            Arrays.fill(value, '\0');
        }
    }
}

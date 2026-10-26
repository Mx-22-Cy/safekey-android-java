package com.safekey.app.security.totp;

import com.safekey.app.security.panic.PanicRuntimeScope;

import android.os.Handler;
import android.os.SystemClock;

import com.safekey.app.data.service.VaultDataService;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.function.LongSupplier;

/** Android adapter for a cancellable, two-stage vault unlock. */
public final class VaultUnlockFlow {

    public interface VaultAccess {
        void open(byte[] key, VaultDataService.SimpleCallback callback);
        void close(VaultDataService.SimpleCallback callback);
    }

    public interface Listener {
        void onSuccess();
        void onError(Exception error);
        void onTotpRequired(Request request);

        default void onPrimaryFailed() {
        }

        // UI callers retain a cancellable connection until navigation is ready.
        default boolean requiresSessionClaim() {
            return false;
        }
    }

    public interface CodeCallback {
        // VERIFIED only completes TOTP. Wait for onSuccess, then claim the session.
        void onResult(TotpVerificationService.Result result);
    }

    public static final class Request implements AutoCloseable {
        private final VaultUnlockFlow owner;
        private final VaultUnlockGate.Attempt attempt;
        private final Listener listener;
        private final Runnable timeout;
        private final boolean requiresClaim;

        private long completedAtMillis;
        private boolean primarySubmitted;
        private boolean initialCloseDone;
        private boolean verifying;
        private boolean opening;
        private boolean cleanupQueued;
        private boolean terminal;
        private boolean completed;
        private boolean cancelled;

        private Request(
                VaultUnlockFlow owner,
                VaultUnlockGate.Attempt attempt,
                Listener listener
        ) {
            this.owner = owner;
            this.attempt = attempt;
            this.listener = listener;
            this.requiresClaim = listener.requiresSessionClaim();
            this.timeout = () -> owner.expire(this);
        }

        public boolean isActive() {
            synchronized (owner.lock) {
                return owner.active(this);
            }
        }

        public void submitCode(char[] code, CodeCallback callback) {
            owner.submitCode(this, code, callback);
        }

        /** Claim once, immediately before the UI unlocks its session and navigates. */
        public boolean claimSession() {
            return owner.claimSession(this);
        }

        @Override
        public void close() {
            owner.cancel(this);
        }
    }

    private final PanicRuntimeScope runtimeScope;
    private final Object lock = new Object();
    private final VaultUnlockGate gate;
    private final Executor worker;
    private final Handler main;
    private final VaultAccess vault;
    private final LongSupplier elapsedMillis;

    private Request current;
    private boolean closed;

    public VaultUnlockFlow(
            VaultUnlockGate gate,
            Executor worker,
            Handler main,
            VaultAccess vault
    ) {
        this(gate, worker, main, vault, SystemClock::elapsedRealtime, new PanicRuntimeScope());
    }

    public VaultUnlockFlow(VaultUnlockGate gate, Executor worker, Handler main,
                           VaultAccess vault, PanicRuntimeScope runtimeScope) {
        this(gate, worker, main, vault, SystemClock::elapsedRealtime, runtimeScope);
    }

    // Tests can check claim expiry without waiting for real time.
    VaultUnlockFlow(
            VaultUnlockGate gate,
            Executor worker,
            Handler main,
            VaultAccess vault,
            LongSupplier elapsedMillis
    ) {
        this(gate, worker, main, vault, elapsedMillis, new PanicRuntimeScope());
    }

    private VaultUnlockFlow(VaultUnlockGate gate, Executor worker, Handler main,
                            VaultAccess vault, LongSupplier elapsedMillis,
                            PanicRuntimeScope runtimeScope) {
        this.runtimeScope = Objects.requireNonNull(runtimeScope, "runtimeScope");
        this.gate = Objects.requireNonNull(gate, "gate");
        Objects.requireNonNull(worker, "worker");
        this.worker = work -> runtimeScope.execute(worker, work);
        this.main = Objects.requireNonNull(main, "main");
        this.vault = Objects.requireNonNull(vault, "vault");
        this.elapsedMillis = Objects.requireNonNull(
                elapsedMillis, "elapsedMillis"
        );

        runtimeScope.onStop(this::shutdown);
    }

    /** Begin before starting password derivation or the biometric prompt. */
    public Request begin(Listener listener) {
        Objects.requireNonNull(listener, "listener");

        synchronized (lock) {
            if (closed || runtimeScope.isStopped()) {
                throw new IllegalStateException("Unlock flow is shut down.");
            }

            if (current != null) {
                cancel(current);
            }

            Request request = new Request(this, gate.begin(), listener);
            current = request;

            if (!main.postDelayed(
                    request.timeout,
                    VaultUnlockGate.ATTEMPT_LIFETIME_MILLIS
            )) {
                cancel(request);
                throw new IllegalStateException(
                        "Unable to schedule sign-in expiry."
                );
            }

            try {
                // Wait for this close to succeed before handing any key to open.
                vault.close(new VaultDataService.SimpleCallback() {
                    @Override
                    public void onSuccess() {
                        execute(request, () -> {
                            synchronized (lock) {
                                if (active(request)) {
                                    request.initialCloseDone = true;
                                    openIfReady(request);
                                }
                            }
                        });
                    }

                    @Override
                    public void onError(Exception error) {
                        fail(request, error);
                    }
                });
            } catch (RuntimeException error) {
                fail(request, error);
            }

            return request;
        }
    }

    /** Only the authentication coordinator may supply an authenticated key. */
    public void acceptPrimary(Request request, byte[] key) {
        synchronized (lock) {
            requireOwner(request);

            if (!active(request) || request.primarySubmitted) {
                return;
            }

            if (key == null
                    || key.length != VaultUnlockGate.DATABASE_KEY_LENGTH_BYTES) {
                fail(
                        request,
                        new IllegalArgumentException(
                                "Invalid authenticated vault key."
                        )
                );
                return;
            }

            request.primarySubmitted = true;
            byte[] copy = key.clone();

            try {
                worker.execute(() -> {
                    try {
                        synchronized (lock) {
                            if (!active(request)) {
                                return;
                            }

                            VaultUnlockGate.Stage stage =
                                    gate.acceptPrimary(request.attempt, copy);

                            if (stage == VaultUnlockGate.Stage.TOTP_REQUIRED) {
                                post(
                                        request,
                                        () -> request.listener.onTotpRequired(request)
                                );
                            } else {
                                openIfReady(request);
                            }
                        }
                    } catch (Exception error) {
                        fail(request, error);
                    } finally {
                        Arrays.fill(copy, (byte) 0);
                    }
                });
            } catch (RuntimeException error) {
                Arrays.fill(copy, (byte) 0);
                fail(request, error);
            }
        }
    }

    public void primaryFailed(Request request) {
        synchronized (lock) {
            requireOwner(request);
            post(request, request.listener::onPrimaryFailed);
        }
    }

    public void fail(Request request, Exception error) {
        Objects.requireNonNull(error, "error");

        synchronized (lock) {
            requireOwner(request);

            if (current != request || request.terminal || request.cancelled) {
                return;
            }

            request.terminal = true;
            gate.cancel(request.attempt);
            main.removeCallbacks(request.timeout);
            cleanup(request, error);

            if (!main.post(() -> {
                synchronized (lock) {
                    if (current == request && !request.cancelled) {
                        current = null;
                        request.listener.onError(error);
                    }
                }
            })) {
                request.cancelled = true;
                current = null;
            }
        }
    }

    public void cancelPending() {
        synchronized (lock) {
            if (current != null) {
                cancel(current);
            }
        }
    }

    /** Serialize session cleanup with all key handoffs and new sign-in attempts. */
    public void closeVault(VaultDataService.SimpleCallback callback) {
        Objects.requireNonNull(callback, "callback");

        synchronized (lock) {
            cancelPending();
            vault.close(callback);
        }
    }

    public void shutdown() {
        synchronized (lock) {
            closed = true;
            cancelPending();
        }
    }

    private void cancel(Request request) {
        synchronized (lock) {
            requireOwner(request);

            if (current != request || request.cancelled) {
                return;
            }

            request.cancelled = true;
            request.terminal = true;
            gate.cancel(request.attempt);
            main.removeCallbacks(request.timeout);
            cleanup(request, null);
            current = null;
        }
    }

    private boolean claimSession(Request request) {
        synchronized (lock) {
            requireOwner(request);

            if (current != request
                    || closed
                    || runtimeScope.isStopped()
                    || request.cancelled
                    || !request.completed
                    || !request.requiresClaim) {
                return false;
            }

            long age = elapsedMillis.getAsLong() - request.completedAtMillis;

            if (age < 0L
                    || age >= VaultUnlockGate.ATTEMPT_LIFETIME_MILLIS) {
                cancel(request);
                return false;
            }

            main.removeCallbacks(request.timeout);
            current = null;
            return true;
        }
    }

    private void expire(Request request) {
        synchronized (lock) {
            if (current != request || request.cancelled) {
                return;
            }

            if (request.completed) {
                cancel(request);
            } else {
                fail(
                        request,
                        new IllegalStateException(
                                "Sign-in expired. Authenticate again."
                        )
                );
            }
        }
    }

    private void submitCode(
            Request request,
            char[] code,
            CodeCallback callback
    ) {
        Objects.requireNonNull(callback, "callback");

        synchronized (lock) {
            requireOwner(request);

            if (!active(request)
                    || request.verifying
                    || gate.getStage(request.attempt)
                    != VaultUnlockGate.Stage.TOTP_REQUIRED) {
                throw new IllegalStateException(
                        "No TOTP challenge is available."
                );
            }

            request.verifying = true;

            char[] copy = code != null
                    && code.length == TotpGenerator.DEFAULT_DIGITS
                    ? code.clone()
                    : null;

            try {
                worker.execute(() -> {
                    try {
                        synchronized (lock) {
                            if (!active(request)) {
                                return;
                            }

                            TotpVerificationService.Result result =
                                    gate.verifyTotp(request.attempt, copy);

                            request.verifying = false;
                            post(request, () -> callback.onResult(result));

                            if (result.getStatus()
                                    == TotpVerificationService.Status.VERIFIED) {
                                openIfReady(request);
                            }
                        }
                    } catch (Exception error) {
                        fail(request, error);
                    } finally {
                        if (copy != null) {
                            Arrays.fill(copy, '\0');
                        }
                    }
                });
            } catch (RuntimeException error) {
                if (copy != null) {
                    Arrays.fill(copy, '\0');
                }

                fail(request, error);
            }
        }
    }

    // Called on the worker while holding lock. open() must copy the key.
    private void openIfReady(Request request) {
        if (!active(request)
                || !request.initialCloseDone
                || request.opening
                || gate.getStage(request.attempt)
                != VaultUnlockGate.Stage.READY_TO_OPEN) {
            return;
        }

        byte[] key = null;

        try {
            key = gate.takeKeyForOpening(request.attempt);
            request.opening = true;

            vault.open(key, new VaultDataService.SimpleCallback() {
                @Override
                public void onSuccess() {
                    post(request, () -> {
                        if (!gate.complete(request.attempt)) {
                            fail(
                                    request,
                                    new IllegalStateException("Sign-in expired.")
                            );
                            return;
                        }

                        request.completed = true;
                        request.terminal = true;
                        main.removeCallbacks(request.timeout);

                        if (request.requiresClaim) {
                            request.completedAtMillis =
                                    elapsedMillis.getAsLong();

                            if (!main.postDelayed(
                                    request.timeout,
                                    VaultUnlockGate.ATTEMPT_LIFETIME_MILLIS
                            )) {
                                cancel(request);
                                return;
                            }
                        } else {
                            current = null;
                        }

                        request.listener.onSuccess();
                    });
                }

                @Override
                public void onError(Exception error) {
                    fail(request, error);
                }
            });
        } catch (Exception error) {
            fail(request, error);
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private void execute(Request request, Runnable action) {
        synchronized (lock) {
            if (!active(request)) {
                return;
            }

            try {
                worker.execute(action);
            } catch (RuntimeException error) {
                fail(request, error);
            }
        }
    }

    private void post(Request request, Runnable action) {
        if (!main.post(() -> {
            synchronized (lock) {
                if (current == request
                        && !runtimeScope.isStopped()
                        && !request.cancelled
                        && !request.terminal) {
                    action.run();
                }
            }
        })) {
            cancel(request);
        }
    }

    private boolean active(Request request) {
        return current == request
                && !closed
                && !runtimeScope.isStopped()
                && !request.cancelled
                && !request.terminal
                && gate.isActive(request.attempt);
    }

    private void cleanup(Request request, Exception original) {
        if (!request.opening || request.cleanupQueued) {
            return;
        }

        request.cleanupQueued = true;

        try {
            vault.close(new VaultDataService.SimpleCallback() {
                @Override
                public void onSuccess() {
                }

                @Override
                public void onError(Exception error) {
                    if (original != null && original != error) {
                        original.addSuppressed(error);
                    }
                }
            });
        } catch (RuntimeException error) {
            if (original != null && original != error) {
                original.addSuppressed(error);
            }
        }
    }

    private void requireOwner(Request request) {
        Objects.requireNonNull(request, "request");

        if (request.owner != this) {
            throw new IllegalArgumentException(
                    "Sign-in request belongs to another flow."
            );
        }
    }
}

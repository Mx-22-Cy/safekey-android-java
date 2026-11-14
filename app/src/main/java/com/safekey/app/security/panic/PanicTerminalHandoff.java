package com.safekey.app.security.panic;

import java.util.Objects;

/**
 * Delivers at most one terminal result for one application-owned vault runtime.
 * It holds no Activity or authentication callback and never authorizes a wipe.
 *
 * Failure delivery is trusted only from the controller after that controller's
 * own SignInRequest reports isPanicCommitted(). A pending journal marker is not
 * required: saving that marker can itself be the committed cleanup failure.
 */
public final class PanicTerminalHandoff<B> {
    public interface Runtime<B> {
        boolean isCurrent(B backend);
        boolean isStopped();
        boolean wasWipeCompleted(B backend);
        boolean areResourcesClosed();
        void onWiped(B backend);
        void onFailed(B backend, Exception error);
    }

    private final B ownedBackend;
    private final Runtime<B> runtime;
    private boolean delivered;

    public PanicTerminalHandoff(B ownedBackend, Runtime<B> runtime) {
        this.ownedBackend = Objects.requireNonNull(ownedBackend, "ownedBackend");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
    }

    /** A fresh setup is allowed only after complete, verified resource cleanup. */
    public boolean onPanicWiped(B backend) {
        synchronized (this) {
            if (delivered || backend != ownedBackend || !runtime.isCurrent(backend)
                    || !runtime.isStopped() || !runtime.wasWipeCompleted(backend)
                    || !runtime.areResourcesClosed()) {
                return false;
            }
            // Claim before calling application code, which may replace this runtime
            // synchronously or cause reentrant lifecycle notifications.
            delivered = true;
        }
        runtime.onWiped(backend);
        return true;
    }

    /** A committed failure stays blocked and does not start fresh initialization. */
    public boolean onPanicFailed(B backend, Exception error) {
        Objects.requireNonNull(error, "error");
        synchronized (this) {
            if (delivered || backend != ownedBackend || !runtime.isCurrent(backend)
                    || !runtime.isStopped() || runtime.wasWipeCompleted(backend)) {
                return false;
            }
            delivered = true;
        }
        runtime.onFailed(backend, error);
        return true;
    }
}

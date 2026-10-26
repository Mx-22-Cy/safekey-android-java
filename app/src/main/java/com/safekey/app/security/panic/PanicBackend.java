package com.safekey.app.security.panic;

import android.content.Context;
import android.os.Looper;

import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.SecureVaultCoordinator;

import java.util.Arrays;
import java.util.concurrent.CancellationException;

/** Application-owned entry point for Hind's later screen integration. */
public final class PanicBackend {
    private final PanicRuntimeScope scope;
    private final PanicPasswordService passwords;
    private final AndroidPanicEnrollmentAuthority enrollment;

    public PanicBackend(Context context, SecureVaultCoordinator real, DecoyVaultCoordinator decoy,
                         PanicWipeCoordinator.Runtime runtime) {
        scope = PanicRuntimeScope.capture(context);
        PanicWipeCoordinator wipe = new PanicWipeCoordinator(scope.getWorkGate(),
                new PanicWipeJournal(context), runtime, PanicWipeTargets.forSafeKey(context));
        passwords = new PanicPasswordService(scope.getWorkGate(), new PanicPasswordStore(context),
                new PanicPasswordCrypto(), wipe);
        enrollment = new AndroidPanicEnrollmentAuthority(context, real, decoy);
    }

    // The device tests retain real authorization/crypto/storage and supply a non-destructive wipe plan.
    PanicBackend(PanicRuntimeScope scope, PanicPasswordService passwords,
                 AndroidPanicEnrollmentAuthority enrollment) {
        this.scope = scope; this.passwords = passwords; this.enrollment = enrollment;
    }

    /** Copies input at submission. Close on screen abandonment; run once on a worker. */
    public EnrollmentRequest prepareEnrollment(char[] master, char[] decoy, char[] panic,
                                                char[] confirmation, boolean warningConfirmed) {
        if (!warningConfirmed) { throw new IllegalArgumentException("Panic warning confirmation is required."); }
        return new EnrollmentRequest(master, decoy, panic, confirmation);
    }

    /** Call on a worker after the UI warning and explicit confirmation. Clear caller arrays afterwards. */
    public void enrollPanicPassword(char[] master, char[] decoy, char[] panic, char[] confirmation,
                                    boolean warningConfirmed) throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Enroll Panic mode on a background worker.");
        }
        try (EnrollmentRequest request = prepareEnrollment(master, decoy, panic, confirmation, warningConfirmed)) {
            request.run();
        }
    }

    public final class EnrollmentRequest implements AutoCloseable {
        private char[][] pending;
        private PanicRuntimeScope.PendingOperation ownership;
        private boolean started;
        private boolean closed;

        private EnrollmentRequest(char[]... input) {
            pending = new char[input.length][];
            try {
                for (int i = 0; i < input.length; i++) { pending[i] = input[i] == null ? null : input[i].clone(); }
                ownership = scope.pending(this::clearPending, this::markClosed);
                synchronized (this) { if (closed) { ownership.close(); } }
            } catch (RuntimeException | Error error) {
                clearPending();
                throw error;
            }
        }

        /** No UI callbacks. Returning successfully means that the proof was saved. */
        public void run() throws Exception {
            if (Looper.myLooper() == Looper.getMainLooper()) {
                throw new IllegalStateException("Run Panic enrollment on a background worker.");
            }
            char[][] copies = null;
            try {
                // This lease outlives cancellation until the actual worker clears its taken copies.
                try (PanicWorkGate.Operation ignored = scope.begin()) {
                    try {
                        synchronized (this) {
                            if (closed || started) { throw new CancellationException("Enrollment is no longer active."); }
                            started = true;
                            copies = pending;
                            pending = null;
                        }
                        passwords.enroll(copies[0], copies[1], copies[2], copies[3], (master, decoy) -> {
                            PanicPasswordService.Grant grant = enrollment.authenticate(master, decoy);
                            return new PanicPasswordService.Grant() {
                                @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
                                    grant.commitIfCurrent(() -> commitIfActive(action));
                                }
                                @Override public void close() { grant.close(); }
                            };
                        });
                    } finally { clear(copies); }
                }
            } finally { close(); }
        }

        private synchronized void commitIfActive(PanicPasswordService.Commit action) throws Exception {
            if (closed || scope.isStopped()) { throw new CancellationException("Enrollment was cancelled."); }
            action.run();
        }

        private synchronized void clearPending() { clear(pending); pending = null; }
        private synchronized void markClosed() { closed = true; }

        @Override public synchronized void close() {
            closed = true;
            clearPending();
            if (ownership != null) { ownership.close(); }
        }

        private void clear(char[][] copies) {
            if (copies != null) {
                for (char[] copy : copies) { if (copy != null) { Arrays.fill(copy, '\0'); } }
            }
        }
    }
}

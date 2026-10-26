package com.safekey.app.security.totp;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWorkGate;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * Verifies TOTP and persists replay/attempt state before reporting success.
 * Use off the main thread, after the primary authentication factor succeeds.
 * This service does not open the vault or unlock the application session.
 */
public final class TotpVerificationService {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final long LOCKOUT_MILLIS = 30_000L;

    public enum Status {
        VERIFIED,
        INVALID_CODE,
        RETRY_LATER,
        NOT_CONFIGURED
    }

    public static final class Result {

        private final Status status;
        private final long retryAfterMillis;

        private Result(Status status, long retryAfterMillis) {
            this.status = status;
            this.retryAfterMillis = retryAfterMillis;
        }

        public Status getStatus() {
            return status;
        }

        public long getRetryAfterMillis() {
            return retryAfterMillis;
        }
    }

    public interface StateStore {

        /** Production adapters must return their captured application runtime. */
        default PanicRuntimeScope getPanicRuntimeScope() { return new PanicRuntimeScope(); }

        // All adapters for the same persisted state must share this lock.
        Object getTransactionLock();

        // Returns an owned state; the service closes it after use.
        TotpState load()
                throws GeneralSecurityException, IOException;

        void save(TotpState state)
                throws GeneralSecurityException, IOException;
    }

    private final PanicRuntimeScope runtimeScope;
    private final StateStore store;
    private final Object transactionLock;
    private final LongSupplier clockMillis;

    public TotpVerificationService(StateStore store) {
        this(store, System::currentTimeMillis);
    }

    // Tests can supply a deterministic clock.
    TotpVerificationService(
            StateStore store,
            LongSupplier clockMillis
    ) {
        this.store = Objects.requireNonNull(store, "store");
        runtimeScope = Objects.requireNonNull(store.getPanicRuntimeScope(), "runtimeScope");

        this.transactionLock = Objects.requireNonNull(
                store.getTransactionLock(),
                "transactionLock"
        );

        this.clockMillis = Objects.requireNonNull(
                clockMillis,
                "clockMillis"
        );
    }

    /**
     * Leaves the caller's code unchanged and clears the temporary code copy.
     * The caller remains responsible for clearing the original code.
     * Storage errors propagate; callers must keep authentication locked.
     * NOT_CONFIGURED is not a successful authentication result.
     */
    private Result verifyWhileRunning(char[] submittedCode)
            throws GeneralSecurityException, IOException {

        char[] codeCopy = submittedCode != null
                && submittedCode.length == TotpGenerator.DEFAULT_DIGITS
                ? submittedCode.clone()
                : null;

        try {
            synchronized (transactionLock) {
                try (TotpState state = store.load()) {
                    if (state == null) {
                        return new Result(
                                Status.NOT_CONFIGURED,
                                0L
                        );
                    }

                    long now = clockMillis.getAsLong();

                    if (now < 0L
                            || now > Long.MAX_VALUE - LOCKOUT_MILLIS) {
                        throw new IllegalStateException(
                                "The TOTP clock is invalid."
                        );
                    }

                    long blockedUntil =
                            state.getBlockedUntilEpochMillis();

                    if (blockedUntil > now) {
                        return new Result(
                                Status.RETRY_LATER,
                                blockedUntil - now
                        );
                    }

                    byte[] secret = state.copySecret();
                    long matchedStep;

                    try {
                        matchedStep =
                                TotpVerifier.findMatchingStep(
                                        secret,
                                        codeCopy,
                                        now / 1_000L,
                                        state.getLastAcceptedStep()
                                );
                    } finally {
                        Arrays.fill(secret, (byte) 0);
                    }

                    if (matchedStep != TotpVerifier.NO_MATCH) {
                        try (TotpState updated =
                                     state.withVerificationState(
                                             matchedStep,
                                             0,
                                             0L
                                     )) {
                            store.save(updated);
                        }

                        return new Result(
                                Status.VERIFIED,
                                0L
                        );
                    }

                    int failures = state.getFailedAttempts();

                    if (failures >= MAX_FAILED_ATTEMPTS) {
                        // A previous cooldown has expired.
                        failures = 0;
                    }

                    failures++;

                    boolean mustWait =
                            failures >= MAX_FAILED_ATTEMPTS;

                    long nextBlockedUntil = mustWait
                            ? now + LOCKOUT_MILLIS
                            : 0L;

                    try (TotpState updated =
                                 state.withVerificationState(
                                         state.getLastAcceptedStep(),
                                         failures,
                                         nextBlockedUntil
                                 )) {
                        store.save(updated);
                    }

                    return new Result(
                            mustWait
                                    ? Status.RETRY_LATER
                                    : Status.INVALID_CODE,
                            mustWait
                                    ? LOCKOUT_MILLIS
                                    : 0L
                    );
                }
            }
        } finally {
            if (codeCopy != null) {
                Arrays.fill(codeCopy, '\0');
            }
        }
    }

    public Result verify(char[] submittedCode)
            throws GeneralSecurityException, IOException {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return verifyWhileRunning(submittedCode);
        }
    }

}

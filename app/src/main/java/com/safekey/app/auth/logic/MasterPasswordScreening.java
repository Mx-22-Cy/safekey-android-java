package com.safekey.app.auth.logic;

import com.safekey.app.breach.PasswordBreachResult;

import java.util.Arrays;
import java.util.Objects;

/**
 * Screens complete proposed passwords for enrollment and password changes.
 * An unavailable online check is an explicit offline choice, never a pass.
 * This class neither persists a password nor performs authentication.
 */
public final class MasterPasswordScreening {

    public enum Outcome {
        LOCAL_REJECTION,
        BREACHED,
        CHECKED_ACCEPTABLE,
        OFFLINE_CHOICE_REQUIRED,
        RETRY_REQUIRED
    }

    public static final class Result {
        private final Outcome outcome;
        private final MasterPasswordValidationResult validation;

        private Result(Outcome outcome, MasterPasswordValidationResult validation) {
            this.outcome = outcome;
            this.validation = validation;
        }

        public Outcome getOutcome() {
            return outcome;
        }

        public MasterPasswordValidationResult getValidation() {
            return validation;
        }
    }

    public interface Callback {
        void onResult(Result result);
    }

    public interface Cancellation {
        void close();
    }

    public interface BreachChecker {
        /**
         * Takes ownership of password and clears it after hashing or cancellation.
         * If this method throws, it must stop using the array before returning.
         */
        Cancellation check(char[] password, BreachCallback callback);
    }

    public interface BreachCallback {
        void onResult(PasswordBreachResult result);
    }

    private final BreachChecker checker;

    public MasterPasswordScreening(BreachChecker checker) {
        this.checker = Objects.requireNonNull(checker, "checker");
    }

    /**
     * Borrows both input arrays only during this call. The caller clears them.
     * The checker receives an independent copy, so the caller can clear or edit
     * its input immediately. Local failures can be delivered synchronously.
     */
    public Request checkNewPassword(
            char[] password,
            char[] confirmation,
            Callback callback
    ) {
        Objects.requireNonNull(callback, "callback");

        MasterPasswordValidationResult validation =
                MasterPasswordPolicy.validateForEnrollment(password, confirmation);
        Request request = new Request(callback);

        if (validation != MasterPasswordValidationResult.VALID) {
            request.finish(new Result(Outcome.LOCAL_REJECTION, validation));
            return request;
        }

        return start(password, request);
    }

    /**
     * Rechecks an existing password without applying new enrollment rules.
     * Callers must authenticate the candidate before associating its result with
     * the current vault; a breach result is not proof of password correctness.
     */
    public Request recheckExistingPassword(char[] password, Callback callback) {
        Request request = new Request(Objects.requireNonNull(callback, "callback"));
        if (password == null || password.length == 0) {
            request.finish(new Result(
                    Outcome.LOCAL_REJECTION,
                    MasterPasswordValidationResult.REQUIRED
            ));
            return request;
        }
        return start(password, request);
    }

    private Request start(char[] password, Request request) {
        char[] checkCopy = Arrays.copyOf(password, password.length);
        Cancellation cancellation;
        try {
            cancellation = Objects.requireNonNull(
                    checker.check(checkCopy, result -> request.finish(classify(result))),
                    "cancellation"
            );
        } catch (RuntimeException error) {
            Arrays.fill(checkCopy, '\0');
            request.finish(new Result(Outcome.RETRY_REQUIRED, null));
            return request;
        }
        request.attach(cancellation);
        return request;
    }

    private static Result classify(PasswordBreachResult result) {
        if (result == null) {
            return new Result(Outcome.RETRY_REQUIRED, null);
        }
        switch (result.getStatus()) {
            case BREACHED:
                return new Result(Outcome.BREACHED, null);
            case NOT_FOUND:
                return new Result(Outcome.CHECKED_ACCEPTABLE, null);
            case ERROR:
                switch (result.getErrorReason()) {
                    case OFFLINE:
                    case TIMEOUT:
                    case NETWORK_ERROR:
                        return new Result(Outcome.OFFLINE_CHOICE_REQUIRED, null);
                    default:
                        return new Result(Outcome.RETRY_REQUIRED, null);
                }
            default:
                return new Result(Outcome.RETRY_REQUIRED, null);
        }
    }

    public static final class Request implements AutoCloseable {
        private Callback callback;
        private Cancellation cancellation;
        private boolean terminal;

        private Request(Callback callback) {
            this.callback = callback;
        }

        private void attach(Cancellation supplied) {
            boolean close;
            synchronized (this) {
                close = terminal;
                if (!close) {
                    cancellation = supplied;
                }
            }
            if (close) {
                supplied.close();
            }
        }

        private void finish(Result result) {
            Callback delivery;
            Cancellation toClose;
            synchronized (this) {
                if (terminal) {
                    return;
                }
                terminal = true;
                delivery = callback;
                callback = null;
                toClose = cancellation;
                cancellation = null;
            }
            // The checker may call back while holding its own request lock.
            // Never call it while holding this request's lock.
            if (toClose != null) {
                toClose.close();
            }
            delivery.onResult(result);
        }

        /**
         * Suppresses results that have not started delivery and cancels the
         * underlying check. A callback that already began cannot be recalled;
         * screen owners must also check their lifecycle/request generation.
         */
        @Override
        public void close() {
            Cancellation toClose;
            synchronized (this) {
                if (terminal) {
                    return;
                }
                terminal = true;
                callback = null;
                toClose = cancellation;
                cancellation = null;
            }
            if (toClose != null) {
                toClose.close();
            }
        }
    }
}

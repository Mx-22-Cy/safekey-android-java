package com.safekey.app.breach;

/**
 * Immutable password-breach result.
 * Does not retain the password or its hash.
 */
public final class PasswordBreachResult {

    public enum Status {
        BREACHED,
        NOT_FOUND,
        NOT_CHECKED,
        ERROR
    }

    public enum ErrorReason {
        NONE,
        INVALID_INPUT,
        INVALID_RESPONSE,
        OFFLINE,
        TIMEOUT,
        NETWORK_ERROR
    }

    private final Status status;
    private final long occurrenceCount;
    private final ErrorReason errorReason;

    private PasswordBreachResult(
            Status status,
            long occurrenceCount,
            ErrorReason errorReason
    ) {
        this.status = status;
        this.occurrenceCount = occurrenceCount;
        this.errorReason = errorReason;
    }

    public static PasswordBreachResult breached(long occurrenceCount) {
        if (occurrenceCount <= 0) {
            throw new IllegalArgumentException(
                    "Breach occurrence count must be positive."
            );
        }

        return new PasswordBreachResult(
                Status.BREACHED,
                occurrenceCount,
                ErrorReason.NONE
        );
    }

    public static PasswordBreachResult notFound() {
        return new PasswordBreachResult(
                Status.NOT_FOUND,
                0,
                ErrorReason.NONE
        );
    }

    public static PasswordBreachResult notChecked() {
        return new PasswordBreachResult(
                Status.NOT_CHECKED,
                0,
                ErrorReason.NONE
        );
    }

    public static PasswordBreachResult error(ErrorReason reason) {
        if (reason == null || reason == ErrorReason.NONE) {
            throw new IllegalArgumentException(
                    "An error reason is required."
            );
        }

        return new PasswordBreachResult(
                Status.ERROR,
                0,
                reason
        );
    }

    public Status getStatus() {
        return status;
    }

    /**
     * Meaningful only when status is BREACHED.
     */
    public long getOccurrenceCount() {
        return occurrenceCount;
    }

    public ErrorReason getErrorReason() {
        return errorReason;
    }

    public boolean isChecked() {
        return status == Status.BREACHED
                || status == Status.NOT_FOUND;
    }
}

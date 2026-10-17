package com.safekey.app.breach;

/**
 * A connection failure with a fixed, non-sensitive message.
 */
public final class BreachRangeException extends Exception {

    private static final long serialVersionUID = 1L;

    private final PasswordBreachResult.ErrorReason errorReason;

    public BreachRangeException(
            PasswordBreachResult.ErrorReason errorReason
    ) {
        super("Breach range request failed.");

        if (errorReason != PasswordBreachResult.ErrorReason.OFFLINE
                && errorReason != PasswordBreachResult.ErrorReason.TIMEOUT
                && errorReason != PasswordBreachResult.ErrorReason.NETWORK_ERROR) {
            throw new IllegalArgumentException(
                    "Range failure must be offline, timeout, or network error."
            );
        }

        this.errorReason = errorReason;
    }

    public PasswordBreachResult.ErrorReason getErrorReason() {
        return errorReason;
    }
}

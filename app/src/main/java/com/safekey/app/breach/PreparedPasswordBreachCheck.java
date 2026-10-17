package com.safekey.app.breach;

import java.util.Arrays;

/**
 * Owns the local hash for one pending callback-based breach check.
 * Complete, fail, or close it to clear that hash.
 * Close it when the session locks or the request is cancelled.
 */
public final class PreparedPasswordBreachCheck implements AutoCloseable {

    private final String hashPrefix;
    private char[] fullHash;

    PreparedPasswordBreachCheck(char[] fullHash) {
        if (fullHash == null || fullHash.length != 40) {
            throw new IllegalArgumentException(
                    "A SHA-1 lookup hash is required."
            );
        }

        this.hashPrefix = new String(fullHash, 0, 5);
        this.fullHash = fullHash;
    }

    public String getHashPrefix() {
        return hashPrefix;
    }

    public synchronized boolean isClosed() {
        return fullHash == null;
    }

    /**
     * Consumes the raw range response and clears the retained hash.
     * Late or repeated callbacks return NOT_CHECKED and should be ignored.
     */
    public synchronized PasswordBreachResult complete(String responseBody) {
        if (fullHash == null) {
            return PasswordBreachResult.notChecked();
        }

        try {
            return PasswordBreachChecker.matchResponse(
                    fullHash,
                    responseBody
            );
        } finally {
            close();
        }
    }

    public synchronized PasswordBreachResult fail(
            PasswordBreachResult.ErrorReason reason
    ) {
        if (fullHash == null) {
            return PasswordBreachResult.notChecked();
        }

        try {
            return PasswordBreachResult.error(reason);
        } finally {
            close();
        }
    }

    @Override
    public synchronized void close() {
        if (fullHash != null) {
            Arrays.fill(fullHash, '\0');
            fullHash = null;
        }
    }
}

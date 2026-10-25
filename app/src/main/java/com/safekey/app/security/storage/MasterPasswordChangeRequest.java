package com.safekey.app.security.storage;

import java.util.Arrays;

/** Cancellation can prevent a pending envelope replacement, never undo a commit. */
public final class MasterPasswordChangeRequest implements AutoCloseable {
    private char[][] pending;
    private boolean cancelled;

    MasterPasswordChangeRequest(char[] currentPassword, char[] newPassword) {
        pending = new char[][]{currentPassword.clone(), newPassword.clone()};
    }

    synchronized char[][] takePasswords() {
        char[][] result = pending;
        pending = null;
        return result;
    }

    synchronized boolean commit(Runnable action) {
        if (cancelled) {
            return false;
        }
        action.run();
        return true;
    }

    public synchronized boolean isCancelled() {
        return cancelled;
    }

    @Override
    public synchronized void close() {
        cancelled = true;
        if (pending != null) {
            Arrays.fill(pending[0], '\0');
            Arrays.fill(pending[1], '\0');
            pending = null;
        }
        // Arrays already taken by the worker are cleared by its finally block.
    }
}

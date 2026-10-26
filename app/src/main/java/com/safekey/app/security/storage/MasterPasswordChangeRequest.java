package com.safekey.app.security.storage;

import com.safekey.app.security.panic.PanicRuntimeScope;

import java.util.Arrays;

/** Cancellation can prevent a pending envelope replacement, never undo a commit. */
public final class MasterPasswordChangeRequest implements AutoCloseable {
    private final PanicRuntimeScope runtimeScope;
    private PanicRuntimeScope.Registration cancellation;
    private char[][] pending;
    private boolean cancelled;

    MasterPasswordChangeRequest(char[] currentPassword, char[] newPassword) {
        this(currentPassword, newPassword, new PanicRuntimeScope());
    }

    MasterPasswordChangeRequest(char[] currentPassword, char[] newPassword,
                                PanicRuntimeScope runtimeScope) {
        this.runtimeScope = runtimeScope;
        pending = new char[][]{currentPassword.clone(), newPassword.clone()};
        cancellation = runtimeScope.onStop(this::close);
        if (cancelled) { cancellation.close(); }
    }

    synchronized char[][] takePasswords() {
        char[][] result = pending;
        pending = null;
        return result;
    }

    synchronized boolean commit(Runnable action) {
        if (cancelled || runtimeScope.isStopped()) {
            return false;
        }
        action.run();
        if (pending != null) {
            Arrays.fill(pending[0], '\0');
            Arrays.fill(pending[1], '\0');
            pending = null;
        }
        cancellation.close();
        return true;
    }

    public synchronized boolean isCancelled() {
        return cancelled;
    }

    @Override
    public synchronized void close() {
        cancelled = true;
        if (cancellation != null) { cancellation.close(); }
        if (pending != null) {
            Arrays.fill(pending[0], '\0');
            Arrays.fill(pending[1], '\0');
            pending = null;
        }
        // Arrays already taken by the worker are cleared by its finally block.
    }
}

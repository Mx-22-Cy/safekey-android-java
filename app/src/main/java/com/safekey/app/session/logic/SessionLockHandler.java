package com.safekey.app.session.logic;

@FunctionalInterface
public interface SessionLockHandler {

    /**
     * Clears session-scoped sensitive material after the session locks.
     */
    void onSessionLocked();
}

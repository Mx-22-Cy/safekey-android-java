package com.safekey.app.session;

import android.os.SystemClock;

import com.safekey.app.session.logic.SessionState;
import com.safekey.app.session.logic.VaultSessionManager;

public final class SafeKeySession {

    private static final VaultSessionManager SESSION_MANAGER =
            new VaultSessionManager(
                    SystemClock::elapsedRealtime,
                    () -> {
                        /*
                         * Session-scoped sensitive material will be
                         * cleared here when the security/key layer
                         * is integrated.
                         *
                         * Never log passwords or vault keys.
                         */
                    }
            );

    private SafeKeySession() {
        // Utility holder.
    }

    public static VaultSessionManager getManager() {
        return SESSION_MANAGER;
    }

    public static SessionState getState() {
        return SESSION_MANAGER.getState();
    }

    public static boolean recordActivity() {
        return SESSION_MANAGER.recordActivity();
    }

    public static void lock() {
        SESSION_MANAGER.lock();
    }
}
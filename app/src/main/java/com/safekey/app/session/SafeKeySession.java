package com.safekey.app.session;

import android.os.SystemClock;

import com.safekey.app.session.logic.SessionState;
import com.safekey.app.session.logic.VaultSessionManager;

/**
 * Android-side holder for the shared vault session state.
 *
 * <p>The shared session intentionally starts in the LOCKED state.
 * Real production code must call unlockAfterAuthentication() only
 * after the authentication/security layer has successfully verified
 * the user and established the required vault key material.</p>
 *
 * <p>The current Sign In screen still contains placeholder security
 * integration, so it must not unlock the session yet.</p>
 */
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
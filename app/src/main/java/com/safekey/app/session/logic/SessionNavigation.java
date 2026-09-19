package com.safekey.app.session.logic;

import java.util.Objects;

public final class SessionNavigation {

    private SessionNavigation() {
        // Utility class.
    }

    public static SessionDestination destinationFor(
            SessionState state
    ) {
        Objects.requireNonNull(
                state,
                "state"
        );

        if (state == SessionState.UNLOCKED) {
            return SessionDestination.HOME;
        }

        return SessionDestination.LOCK_SCREEN;
    }
}

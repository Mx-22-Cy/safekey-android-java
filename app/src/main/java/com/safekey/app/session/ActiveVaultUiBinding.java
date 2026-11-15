package com.safekey.app.session;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.security.storage.VaultOperations;
import com.safekey.app.session.logic.SessionState;

/**
 * Binds an activity to the authenticated vault selected when it opened.
 * A later Real/Decoy login cannot reuse callbacks from this activity.
 * The underlying VaultOperations implementations enforce storage authorization.
 */
public final class ActiveVaultUiBinding {
    private final SafeKeyApplication application;
    private final VaultOperations operations;
    private final long authenticationGeneration;

    public ActiveVaultUiBinding(SafeKeyApplication application) {
        this.application = application;
        this.operations = application.getActiveVaultOperations();
        this.authenticationGeneration =
                SafeKeySession.getManager().getAuthenticationGeneration();
    }

    public VaultOperations operations() {
        return operations;
    }

    public boolean isCurrent() {
        if (SafeKeySession.getState() != SessionState.UNLOCKED
                || SafeKeySession.getManager().getAuthenticationGeneration()
                   != authenticationGeneration) {
            return false;
        }
        try {
            return application.getActiveVaultOperations() == operations;
        } catch (IllegalStateException exception) {
            return false;
        }
    }
}

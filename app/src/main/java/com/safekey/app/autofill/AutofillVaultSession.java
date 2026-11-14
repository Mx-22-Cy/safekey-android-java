package com.safekey.app.autofill;

import android.content.Context;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.security.storage.VaultOperations;

import java.util.List;
import java.util.Objects;

/**
 * Restricts Autofill credential access to one authenticated vault session.
 *
 * Does not unlock a vault and does not switch between Real and Decoy.
 *
 * This guard does not replace final authentication at dataset selection.
 */
public final class AutofillVaultSession {

    private final SafeKeyApplication application;
    private final VaultOperations operations;
    private final SafeKeyApplication.ActiveVault vaultIdentity;
    private final long authenticationGeneration;

    private AutofillVaultSession(
            SafeKeyApplication application,
            VaultOperations operations,
            SafeKeyApplication.ActiveVault vaultIdentity,
            long authenticationGeneration
    ) {
        this.application = application;
        this.operations = operations;
        this.vaultIdentity = vaultIdentity;
        this.authenticationGeneration = authenticationGeneration;
    }

    public static AutofillVaultSession capture(Context context) {
        if (context == null) {
            return null;
        }

        if (!(context.getApplicationContext()
                instanceof SafeKeyApplication)) {
            return null;
        }

        SafeKeyApplication app =
                (SafeKeyApplication) context.getApplicationContext();

        try {
            if (SafeKeySession.getState() != SessionState.UNLOCKED) {
                return null;
            }
            long generation = SafeKeySession.getManager()
                    .getAuthenticationGeneration();
            SafeKeyApplication.ActiveVault selected = app.getActiveVault();
            if (generation < 0L || selected == SafeKeyApplication.ActiveVault.NONE) {
                return null;
            }
            VaultOperations current = app.getActiveVaultOperations();
            if (SafeKeySession.getManager().getAuthenticationGeneration() != generation
                    || app.getActiveVault() != selected) {
                return null;
            }
            return new AutofillVaultSession(app, current, selected, generation);
        } catch (IllegalStateException exception) {
            return null;
        }
    }

    /** Separate, explicit vault and authentication binding prevents vault switching. */
    public boolean isCurrent() {
        try {
            if (SafeKeySession.getState() != SessionState.UNLOCKED) {
                return false;
            }
            long currentGeneration = SafeKeySession.getManager()
                    .getAuthenticationGeneration();
            SafeKeyApplication.ActiveVault currentVault = application.getActiveVault();
            if (currentVault != vaultIdentity || currentGeneration != authenticationGeneration) {
                return false;
            }
            VaultOperations currentOperations = application.getActiveVaultOperations();
            return matchesBinding(vaultIdentity, authenticationGeneration, operations,
                    currentVault, currentGeneration, currentOperations, true);
        } catch (IllegalStateException exception) {
            return false;
        }
    }

    /** Testable policy used by the production authorization check above. */
    static boolean matchesBinding(
            SafeKeyApplication.ActiveVault expectedVault,
            long expectedGeneration,
            Object expectedOperations,
            SafeKeyApplication.ActiveVault actualVault,
            long actualGeneration,
            Object actualOperations,
            boolean unlocked
    ) {
        return unlocked
                && expectedVault != null
                && expectedVault != SafeKeyApplication.ActiveVault.NONE
                && expectedVault == actualVault
                && expectedGeneration >= 0L
                && expectedGeneration == actualGeneration
                && expectedOperations != null
                && expectedOperations == actualOperations;
    }

    public void getCredentials(
            VaultDataService.ResultCallback<List<Credential>> callback
    ) {
        Objects.requireNonNull(callback, "callback");

        if (!isCurrent()) {
            callback.onError(sessionExpired());
            return;
        }

        operations.getCredentials(
                new VaultDataService.ResultCallback<List<Credential>>() {

                    @Override
                    public void onSuccess(List<Credential> credentials) {
                        if (!isCurrent()) {
                            callback.onError(sessionExpired());
                            return;
                        }

                        callback.onSuccess(credentials);
                    }

                    @Override
                    public void onError(Exception exception) {
                        if (!isCurrent()) {
                            callback.onError(sessionExpired());
                            return;
                        }

                        callback.onError(exception);
                    }
                }
        );
    }

    /** Re-fetch a selected credential from the same vault before dataset delivery. */
    public void getCredential(
            long id,
            VaultDataService.ResultCallback<Credential> callback
    ) {
        Objects.requireNonNull(callback, "callback");
        if (id <= 0L || !isCurrent()) {
            callback.onError(sessionExpired());
            return;
        }
        operations.getCredential(id, new VaultDataService.ResultCallback<Credential>() {
            @Override
            public void onSuccess(Credential credential) {
                if (!isCurrent()) {
                    callback.onError(sessionExpired());
                } else {
                    callback.onSuccess(credential);
                }
            }

            @Override
            public void onError(Exception exception) {
                callback.onError(isCurrent() ? exception : sessionExpired());
            }
        });
    }

    private static IllegalStateException sessionExpired() {
        return new IllegalStateException(
                "The Autofill vault session is no longer active."
        );
    }
}
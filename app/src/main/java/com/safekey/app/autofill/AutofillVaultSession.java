package com.safekey.app.autofill;

import android.content.Context;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
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

    private AutofillVaultSession(
            SafeKeyApplication application,
            VaultOperations operations
    ) {
        this.application = application;
        this.operations = operations;
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
            VaultOperations current = app.getActiveVaultOperations();

            return new AutofillVaultSession(app, current);

        } catch (IllegalStateException exception) {
            return null;
        }
    }

    public boolean isCurrent() {
        try {
            return application.getActiveVaultOperations() == operations;

        } catch (IllegalStateException exception) {
            return false;
        }
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

    private static IllegalStateException sessionExpired() {
        return new IllegalStateException(
                "The Autofill vault session is no longer active."
        );
    }
}
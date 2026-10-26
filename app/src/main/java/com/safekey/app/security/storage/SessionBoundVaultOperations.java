
package com.safekey.app.security.storage;

import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.VaultDataService;

import java.util.List;
import java.util.Objects;

/**
 * Session-bound wrapper for vault data operations.
 *
 * A wrapper belongs to one authenticated vault session.
 * It must not automatically switch to another vault.
 *
 * SafeKeyApplication provides the session guard.
 */
public final class SessionBoundVaultOperations
        implements VaultOperations {

    public interface SessionGuard {

        boolean runIfCurrent(Runnable action);

        boolean isCurrent();
    }

    private interface VaultRequest<T> {

        void execute(
                VaultOperations operations,
                VaultDataService.ResultCallback<T> callback
        );
    }

    private final VaultOperations delegate;
    private final SessionGuard sessionGuard;

    public SessionBoundVaultOperations(
            VaultOperations delegate,
            SessionGuard sessionGuard
    ) {
        this.delegate =
                Objects.requireNonNull(
                        delegate,
                        "delegate"
                );

        this.sessionGuard =
                Objects.requireNonNull(
                        sessionGuard,
                        "sessionGuard"
                );
    }

    private <T> void execute(
            VaultRequest<T> request,
            VaultDataService.ResultCallback<T> callback
    ) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(callback, "callback");

        VaultDataService.ResultCallback<T> guardedCallback =
                new VaultDataService.ResultCallback<T>() {

                    @Override
                    public void onSuccess(T value) {
                        if (!sessionGuard.isCurrent()) {
                            callback.onError(
                                    sessionExpired()
                            );
                            return;
                        }

                        callback.onSuccess(value);
                    }

                    @Override
                    public void onError(Exception exception) {
                        if (!sessionGuard.isCurrent()) {
                            callback.onError(
                                    sessionExpired()
                            );
                            return;
                        }

                        callback.onError(exception);
                    }
                };

        boolean accepted =
                sessionGuard.runIfCurrent(
                        () -> request.execute(
                                delegate,
                                guardedCallback
                        )
                );

        if (!accepted) {
            callback.onError(
                    sessionExpired()
            );
        }
    }

    private static IllegalStateException sessionExpired() {
        return new IllegalStateException(
                "The authenticated vault session is no longer active."
        );
    }

    @Override
    public void getCredential(
            long id,
            VaultDataService.ResultCallback<Credential> callback
    ) {
        execute(
                (operations, result) ->
                        operations.getCredential(id, result),
                callback
        );
    }

    @Override
    public void addCredential(
            Credential credential,
            VaultDataService.ResultCallback<Long> callback
    ) {
        execute(
                (operations, result) ->
                        operations.addCredential(credential, result),
                callback
        );
    }

    @Override
    public void updateCredential(
            Credential credential,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        execute(
                (operations, result) ->
                        operations.updateCredential(credential, result),
                callback
        );
    }

    @Override
    public void deleteCredential(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        execute(
                (operations, result) ->
                        operations.deleteCredential(id, result),
                callback
        );
    }

    @Override
    public void setCredentialFavorite(
            long id,
            boolean favorite,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        execute(
                (operations, result) ->
                        operations.setCredentialFavorite(
                                id,
                                favorite,
                                result
                        ),
                callback
        );
    }

    @Override
    public void getVaultCounts(
            VaultDataService.ResultCallback<VaultCounts> callback
    ) {
        execute(
                (operations, result) ->
                        operations.getVaultCounts(result),
                callback
        );
    }

    @Override
    public void getCredentials(
            VaultDataService.ResultCallback<List<Credential>> callback
    ) {
        execute(
                (operations, result) ->
                        operations.getCredentials(result),
                callback
        );
    }

    @Override
    public void getSecureNote(
            long id,
            VaultDataService.ResultCallback<SecureNote> callback
    ) {
        execute(
                (operations, result) ->
                        operations.getSecureNote(id, result),
                callback
        );
    }

    @Override
    public void addSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Long> callback
    ) {
        execute(
                (operations, result) ->
                        operations.addSecureNote(note, result),
                callback
        );
    }

    @Override
    public void updateSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        execute(
                (operations, result) ->
                        operations.updateSecureNote(note, result),
                callback
        );
    }

    @Override
    public void deleteSecureNote(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        execute(
                (operations, result) ->
                        operations.deleteSecureNote(id, result),
                callback
        );
    }

    @Override
    public void getSecureNotes(
            VaultDataService.ResultCallback<List<SecureNote>> callback
    ) {
        execute(
                (operations, result) ->
                        operations.getSecureNotes(result),
                callback
        );
    }
}

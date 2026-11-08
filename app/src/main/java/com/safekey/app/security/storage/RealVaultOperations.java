package com.safekey.app.security.storage;

import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.VaultDataService;

import java.util.List;
import java.util.Objects;

/**
 * Adapter exposing the existing real SecureVaultCoordinator
 * through the common VaultOperations contract.
 *
 * The existing coordinator remains unchanged.
 */
public final class RealVaultOperations
        implements VaultOperations {

    private final SecureVaultCoordinator coordinator;

    public RealVaultOperations(
            SecureVaultCoordinator coordinator
    ) {
        this.coordinator =
                Objects.requireNonNull(
                        coordinator,
                        "coordinator"
                );
    }

    @Override
    public void getVaultDisplayName(
            VaultDataService.ResultCallback<String> callback
    ) {
        coordinator.getVaultDisplayName(callback);
    }

    @Override
    public void updateVaultDisplayName(
            String displayName,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        coordinator.updateVaultDisplayName(displayName, callback);
    }

    @Override
    public void getCredential(
            long id,
            VaultDataService.ResultCallback<Credential> callback
    ) {
        coordinator.getCredential(
                id,
                callback
        );
    }

    @Override
    public void addCredential(
            Credential credential,
            VaultDataService.ResultCallback<Long> callback
    ) {
        coordinator.addCredential(
                credential,
                callback
        );
    }

    @Override
    public void updateCredential(
            Credential credential,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        coordinator.updateCredential(
                credential,
                callback
        );
    }

    @Override
    public void deleteCredential(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        coordinator.deleteCredential(
                id,
                callback
        );
    }

    @Override
    public void setCredentialFavorite(
            long id,
            boolean favorite,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        coordinator.setCredentialFavorite(
                id,
                favorite,
                callback
        );
    }

    @Override
    public void getVaultCounts(
            VaultDataService.ResultCallback<VaultCounts> callback
    ) {
        coordinator.getVaultCounts(
                callback
        );
    }

    @Override
    public void getCredentials(
            VaultDataService.ResultCallback<List<Credential>> callback
    ) {
        coordinator.getCredentials(
                callback
        );
    }

    @Override
    public void getSecureNote(
            long id,
            VaultDataService.ResultCallback<SecureNote> callback
    ) {
        coordinator.getSecureNote(
                id,
                callback
        );
    }

    @Override
    public void addSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Long> callback
    ) {
        coordinator.addSecureNote(
                note,
                callback
        );
    }

    @Override
    public void updateSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        coordinator.updateSecureNote(
                note,
                callback
        );
    }

    @Override
    public void deleteSecureNote(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    ) {
        coordinator.deleteSecureNote(
                id,
                callback
        );
    }

    @Override
    public void getSecureNotes(
            VaultDataService.ResultCallback<List<SecureNote>> callback
    ) {
        coordinator.getSecureNotes(
                callback
        );
    }
}

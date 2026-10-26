package com.safekey.app.security.storage;

import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.VaultDataService;

import java.util.List;

/**
 * Common vault-data operations used by the SafeKey UI.
 *
 * The presentation layer uses this contract instead of knowing
 * whether the currently active vault is the real vault or the
 * Decoy Vault.
 *
 * Authentication, enrollment, biometrics and key management
 * intentionally remain outside this interface.
 */
public interface VaultOperations {

    void getCredential(
            long id,
            VaultDataService.ResultCallback<Credential> callback
    );

    void addCredential(
            Credential credential,
            VaultDataService.ResultCallback<Long> callback
    );

    void updateCredential(
            Credential credential,
            VaultDataService.ResultCallback<Integer> callback
    );

    void deleteCredential(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    );

    void setCredentialFavorite(
            long id,
            boolean favorite,
            VaultDataService.ResultCallback<Integer> callback
    );

    void getVaultCounts(
            VaultDataService.ResultCallback<VaultCounts> callback
    );

    void getCredentials(
            VaultDataService.ResultCallback<List<Credential>> callback
    );

    void getSecureNote(
            long id,
            VaultDataService.ResultCallback<SecureNote> callback
    );

    void addSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Long> callback
    );

    void updateSecureNote(
            SecureNote note,
            VaultDataService.ResultCallback<Integer> callback
    );

    void deleteSecureNote(
            long id,
            VaultDataService.ResultCallback<Integer> callback
    );

    void getSecureNotes(
            VaultDataService.ResultCallback<List<SecureNote>> callback
    );
}

package com.safekey.app.data.service;

import android.content.Context;

import com.safekey.app.data.database.SafeKeyDatabase;

import java.util.Objects;

/**
 * VaultDataService bound to a specific secondary SQLCipher
 * database instead of the normal primary safekey.db.
 *
 * This gives the Decoy Vault its own repository and database
 * connection path.
 */
public final class DecoyVaultDataService
        extends VaultDataService {

    public DecoyVaultDataService(
            Context context,
            String databaseName
    ) {
        super(
                new SafeKeyDatabase(
                        requireContext(
                                context
                        ).getApplicationContext(),
                        databaseName
                )
        );
    }

    private static Context requireContext(
            Context context
    ) {
        return Objects.requireNonNull(
                context,
                "context"
        );
    }
}

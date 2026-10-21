package com.safekey.app.security.storage;

import android.content.Context;

import com.safekey.app.data.database.SafeKeyDatabase;

import java.io.File;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Week 10 Decoy Vault storage layout.
 *
 * The secondary SQLCipher database exists even before
 * a Decoy Vault is configured. This prevents database-file
 * presence alone from revealing whether Decoy setup occurred.
 *
 * Before Decoy setup, the secondary database is initialized
 * with a random throwaway key. The key is intentionally not
 * retained. Decoy enrollment will later replace this cover
 * database with the real Decoy Vault using its independent key.
 */
public final class DecoyVaultStorage {

    /*
     * Use a neutral secondary-storage name.
     * The file exists regardless of Decoy configuration.
     */
    public static final String DATABASE_NAME =
            "safekey_secondary.db";

    private DecoyVaultStorage() {
        // Utility class.
    }

    /**
     * Ensures that the secondary SQLCipher database file exists.
     *
     * If it already exists, it is left completely unchanged.
     * If it does not exist, a valid encrypted SQLCipher database
     * is created with a random temporary key.
     */
    public static synchronized void ensureDatabaseFile(
            Context context
    ) {
        Objects.requireNonNull(
                context,
                "context"
        );

        Context applicationContext =
                context.getApplicationContext();

        File databaseFile =
                applicationContext.getDatabasePath(
                        DATABASE_NAME
                );

        if (databaseFile.exists()) {
            return;
        }

        byte[] coverDatabaseKey =
                new byte[
                        SafeKeyDatabase
                                .DATABASE_KEY_LENGTH_BYTES
                        ];

        SafeKeyDatabase databaseManager =
                new SafeKeyDatabase(
                        applicationContext,
                        DATABASE_NAME
                );

        boolean createdSuccessfully =
                false;

        try {
            new SecureRandom().nextBytes(
                    coverDatabaseKey
            );

            databaseManager.open(
                    coverDatabaseKey
            );

            createdSuccessfully =
                    true;

        } finally {
            databaseManager.close();

            Arrays.fill(
                    coverDatabaseKey,
                    (byte) 0
            );

            /*
             * Do not leave a partial or unusable file if
             * initialization failed.
             */
            if (!createdSuccessfully) {
                applicationContext.deleteDatabase(
                        DATABASE_NAME
                );
            }
        }
    }

    /**
     * Reports whether the secondary database artifact exists.
     *
     * This reports storage-file presence only. It does not mean
     * that a Decoy Vault has been enrolled.
     */
    public static boolean databaseFileExists(
            Context context
    ) {
        Objects.requireNonNull(
                context,
                "context"
        );

        return context
                .getApplicationContext()
                .getDatabasePath(
                        DATABASE_NAME
                )
                .exists();
    }
}

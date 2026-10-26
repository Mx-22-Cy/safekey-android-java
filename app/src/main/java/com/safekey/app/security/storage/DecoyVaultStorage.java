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
 * with a random throwaway key. That key is intentionally
 * not retained.
 */
public final class DecoyVaultStorage {

    public static final String DATABASE_NAME =
            "safekey_secondary.db";

    private DecoyVaultStorage() {
        // Utility class.
    }

    /**
     * Ensures that a valid encrypted secondary SQLCipher
     * database exists.
     *
     * If the file already exists, it is left untouched.
     */
    public static synchronized void ensureDatabaseFile(
            Context context
    ) {
        Context applicationContext =
                requireApplicationContext(
                        context
                );

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
            try {
                databaseManager.close();
            } finally {
                Arrays.fill(
                        coverDatabaseKey,
                        (byte) 0
                );

                if (!createdSuccessfully) {
                    deleteDatabaseIfPresent(
                            applicationContext
                    );
                }
            }
        }
    }

    /**
     * Removes the unconfigured cover database immediately
     * before a real Decoy Vault is created.
     *
     * The Decoy coordinator then recreates this same filename
     * as a SQLCipher vault with the new independent Decoy key.
     */
    static synchronized void prepareDatabaseForEnrollment(
            Context context
    ) {
        Context applicationContext =
                requireApplicationContext(
                        context
                );

        deleteDatabaseIfPresent(
                applicationContext
        );
    }

    /**
     * Restores the always-present encrypted cover database if
     * Decoy enrollment fails before it is completed.
     */
    static synchronized void restoreCoverDatabase(
            Context context
    ) {
        Context applicationContext =
                requireApplicationContext(
                        context
                );

        deleteDatabaseIfPresent(
                applicationContext
        );

        ensureDatabaseFile(
                applicationContext
        );
    }

    public static boolean databaseFileExists(
            Context context
    ) {
        Context applicationContext =
                requireApplicationContext(
                        context
                );

        return applicationContext
                .getDatabasePath(
                        DATABASE_NAME
                )
                .exists();
    }

    private static Context requireApplicationContext(
            Context context
    ) {
        Objects.requireNonNull(
                context,
                "context"
        );

        return context.getApplicationContext();
    }

    private static void deleteDatabaseIfPresent(
            Context applicationContext
    ) {
        File databaseFile =
                applicationContext.getDatabasePath(
                        DATABASE_NAME
                );

        if (!databaseFile.exists()) {
            return;
        }

        boolean deleted =
                applicationContext.deleteDatabase(
                        DATABASE_NAME
                );

        if (!deleted
                && databaseFile.exists()) {

            throw new IllegalStateException(
                    "Unable to reset secondary vault database."
            );
        }
    }
}

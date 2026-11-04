package com.safekey.app.data.database;

import android.content.Context;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.io.File;
import java.util.Arrays;

public class SafeKeyDatabase {

    private static final String DEFAULT_DATABASE_NAME = "safekey.db";
    private static final int DATABASE_VERSION = 3;

    public static final int DATABASE_KEY_LENGTH_BYTES = 32;

    private final Context context;
    private final String databaseName;

    private SQLiteDatabase database;

    static {
        System.loadLibrary("sqlcipher");
    }

    public SafeKeyDatabase(Context context) {
        this(
                context,
                DEFAULT_DATABASE_NAME
        );
    }

    public SafeKeyDatabase(
            Context context,
            String databaseName
    ) {
        if (databaseName == null
                || databaseName.trim().isEmpty()) {

            throw new IllegalArgumentException(
                    "Database name cannot be empty."
            );
        }

        this.context =
                context.getApplicationContext();

        this.databaseName =
                databaseName;
    }

    public SQLiteDatabase open(
            byte[] databaseKey
    ) {
        byte[] encodedDatabaseKey =
                SqlCipherKeyEncoder.encode(
                        databaseKey
                );

        return openWithEncodedDatabaseKey(
                encodedDatabaseKey
        );
    }

    private SQLiteDatabase openWithEncodedDatabaseKey(
            byte[] encodedDatabaseKey
    ) {
        if (database != null
                && database.isOpen()) {

            Arrays.fill(
                    encodedDatabaseKey,
                    (byte) 0
            );

            return database;
        }

        /*
         * The previous connection may have been
         * closed directly by another caller.
         */
        database = null;

        SQLiteDatabase db = null;

        try {
            File databaseFile =
                    context.getDatabasePath(
                            databaseName
                    );

            File parent =
                    databaseFile.getParentFile();

            if (parent != null) {
                parent.mkdirs();
            }

            db =
                    SQLiteDatabase.openOrCreateDatabase(
                            databaseFile,
                            encodedDatabaseKey,
                            null,
                            null,
                            null
                    );

            db.execSQL(
                    "PRAGMA foreign_keys = ON"
            );

            int currentVersion =
                    db.getVersion();

            if (currentVersion > DATABASE_VERSION) {
                throw new IllegalStateException(
                        "Database version "
                                + currentVersion
                                + " is newer than supported version "
                                + DATABASE_VERSION
                                + "."
                );
            }

            if (currentVersion < DATABASE_VERSION) {
                migrateDatabase(
                        db,
                        currentVersion,
                        DATABASE_VERSION
                );
            }

            database = db;

            return database;

        } catch (
                RuntimeException
                | Error initializationError
        ) {
            try {
                if (db != null
                        && db.isOpen()) {

                    db.close();
                }

            } catch (
                    RuntimeException
                    | Error closeError
            ) {
                initializationError.addSuppressed(
                        closeError
                );
            }

            throw initializationError;

        } finally {

            /*
             * SQLCipher has already consumed the encoded
             * key before openOrCreateDatabase() returns.
             * Do not retain another Java-memory copy.
             */
            Arrays.fill(
                    encodedDatabaseKey,
                    (byte) 0
            );
        }
    }

    private void createCredentialsTable(
            SQLiteDatabase db
    ) {
        db.execSQL(
                "CREATE TABLE IF NOT EXISTS credentials (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                        "title TEXT NOT NULL, " +
                        "username TEXT NOT NULL, " +
                        "password_ciphertext TEXT NOT NULL, " +
                        "website TEXT NOT NULL DEFAULT '', " +
                        "category TEXT NOT NULL DEFAULT 'Work', " +
                        "notes_ciphertext TEXT NOT NULL DEFAULT '', " +
                        "favorite INTEGER NOT NULL DEFAULT 0, " +
                        "created_at INTEGER NOT NULL, " +
                        "updated_at INTEGER NOT NULL" +
                        ")"
        );
    }

    private void createSecureNotesTable(
            SQLiteDatabase db
    ) {
        db.execSQL(
                "CREATE TABLE IF NOT EXISTS secure_notes (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                        "title TEXT NOT NULL, " +
                        "content_ciphertext TEXT NOT NULL, " +
                        "created_at INTEGER NOT NULL, " +
                        "updated_at INTEGER NOT NULL" +
                        ")"
        );
    }

    /*
     * Each encrypted vault database stores its own
     * display name.
     *
     * The fixed ID ensures that the table contains
     * only one vault-profile record.
     *
     * REAL and DECOY databases remain independent.
     */
    private void createVaultProfileTable(
            SQLiteDatabase db
    ) {
        db.execSQL(
                "CREATE TABLE IF NOT EXISTS vault_profile (" +
                        "id INTEGER PRIMARY KEY CHECK (id = 1), " +
                        "display_name TEXT NOT NULL DEFAULT 'Local Vault'" +
                        ")"
        );

        /*
         * Insert the default only when the profile
         * has not already been created.
         *
         * Existing customized names are preserved.
         */
        db.execSQL(
                "INSERT OR IGNORE INTO vault_profile " +
                        "(id, display_name) VALUES (1, 'Local Vault')"
        );
    }

    private void migrateDatabase(
            SQLiteDatabase db,
            int oldVersion,
            int newVersion
    ) {
        int version =
                oldVersion;

        db.beginTransaction();

        try {
            /*
             * Fresh databases use the same upgrade path
             * as existing vaults.
             *
             * Table creation, migration and user_version
             * are committed together.
             */
            if (version == 0) {
                createCredentialsTable(db);
                createSecureNotesTable(db);
                version = 1;
            }

            while (version < newVersion) {

                switch (version) {

                    case 1:
                        db.execSQL(
                                "ALTER TABLE credentials ADD COLUMN "
                                        + "breach_status TEXT NOT NULL DEFAULT 'NOT_CHECKED' "
                                        + "CHECK (breach_status IN ("
                                        + "'NOT_CHECKED', 'NOT_FOUND', 'BREACHED', 'ERROR'))"
                        );

                        version = 2;
                        break;

                    case 2:
                        /*
                         * Upgrade existing REAL or DECOY
                         * vaults without modifying their
                         * credentials or secure notes.
                         */
                        createVaultProfileTable(db);

                        version = 3;
                        break;

                    default:
                        throw new IllegalStateException(
                                "No migration available from database version "
                                        + version
                        );
                }
            }

            db.setVersion(
                    newVersion
            );

            db.setTransactionSuccessful();

        } finally {
            db.endTransaction();
        }
    }

    public void close() {
        try {
            if (database != null) {
                database.close();
            }

        } finally {
            database = null;
        }
    }

    public boolean isOpen() {
        return database != null
                && database.isOpen();
    }
}

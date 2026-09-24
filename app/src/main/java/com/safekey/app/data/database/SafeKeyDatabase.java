package com.safekey.app.data.database;

import android.content.Context;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.io.File;

public class SafeKeyDatabase {

    private static final String DEFAULT_DATABASE_NAME = "safekey.db";
    private static final int DATABASE_VERSION = 1;

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
            String databasePassphrase
    ) {

        /*
         * Reject a missing database passphrase
         * before SQLCipher attempts to open or
         * create the database.
         *
         * The production database passphrase will
         * later come from the security/key-management
         * layer. It must never be hard-coded here.
         */
        if (databasePassphrase == null
                || databasePassphrase.isEmpty()) {

            throw new IllegalArgumentException(
                    "Database passphrase cannot be null or empty."
            );
        }

        if (database != null
                && database.isOpen()) {

            return database;
        }

        File databaseFile =
                context.getDatabasePath(
                        databaseName
                );

        File parent =
                databaseFile.getParentFile();

        if (parent != null) {
            parent.mkdirs();
        }

        /*
         * Keep this connection local until all
         * database initialization is complete.
         *
         * If opening succeeds but schema setup,
         * version checking, or migration fails,
         * this local connection must be closed.
         */
        SQLiteDatabase db =
                SQLiteDatabase.openOrCreateDatabase(
                        databaseFile,
                        databasePassphrase,
                        null,
                        null,
                        null
                );

        try {

            db.execSQL(
                    "PRAGMA foreign_keys = ON"
            );

            int currentVersion =
                    db.getVersion();

            /*
             * Never allow an older application build
             * to silently open a database created by
             * a newer schema version.
             *
             * Repositories in this application only
             * understand schemas up to DATABASE_VERSION.
             * Opening a newer schema could cause runtime
             * failures or corrupt data.
             *
             * Throwing here also allows the existing
             * initialization cleanup below to close
             * the local SQLCipher connection before
             * the error is returned to the caller.
             */
            if (currentVersion > DATABASE_VERSION) {

                throw new IllegalStateException(
                        "Database version "
                                + currentVersion
                                + " is newer than supported version "
                                + DATABASE_VERSION
                                + "."
                );
            }

            if (currentVersion == 0) {

                createVersion1Schema(
                        db
                );

                db.setVersion(
                        DATABASE_VERSION
                );

            } else if (
                    currentVersion < DATABASE_VERSION
            ) {

                migrateDatabase(
                        db,
                        currentVersion,
                        DATABASE_VERSION
                );
            }

            /*
             * Only store the connection in the
             * instance field after initialization
             * has completed successfully.
             */
            database = db;

            return database;

        } catch (
                RuntimeException
                | Error initializationError
        ) {

            /*
             * At this point the SQLCipher connection
             * may already be open, but database has
             * not yet been assigned.
             *
             * Close the local connection directly
             * before rethrowing the original error.
             */
            try {

                if (db.isOpen()) {
                    db.close();
                }

            } catch (
                    RuntimeException
                    | Error closeError
            ) {

                /*
                 * Preserve the original initialization
                 * failure while also retaining information
                 * about a possible close failure.
                 */
                initializationError.addSuppressed(
                        closeError
                );
            }

            throw initializationError;
        }
    }

    private void createVersion1Schema(
            SQLiteDatabase db
    ) {

        db.beginTransaction();

        try {

            createCredentialsTable(
                    db
            );

            createSecureNotesTable(
                    db
            );

            db.setTransactionSuccessful();

        } finally {

            db.endTransaction();
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

    private void migrateDatabase(
            SQLiteDatabase db,
            int oldVersion,
            int newVersion
    ) {

        int version =
                oldVersion;

        db.beginTransaction();

        try {

            while (version < newVersion) {

                switch (version) {

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

        if (database != null) {

            database.close();

            database = null;
        }
    }

    public boolean isOpen() {

        return database != null
                && database.isOpen();
    }
}
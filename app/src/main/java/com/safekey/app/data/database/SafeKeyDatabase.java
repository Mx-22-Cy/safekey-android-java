package com.safekey.app.data.database;

import android.content.Context;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.io.File;

public class SafeKeyDatabase {

    private static final String DATABASE_NAME = "safekey.db";
    private static final int DATABASE_VERSION = 1;

    private final Context context;
    private SQLiteDatabase database;

    static {
        System.loadLibrary("sqlcipher");
    }

    public SafeKeyDatabase(Context context) {
        this.context = context.getApplicationContext();
    }

    public SQLiteDatabase open(String password) {

        if (database != null && database.isOpen()) {
            return database;
        }

        File databaseFile =
                context.getDatabasePath(DATABASE_NAME);

        File parent = databaseFile.getParentFile();

        if (parent != null) {
            parent.mkdirs();
        }

        SQLiteDatabase db =
                SQLiteDatabase.openOrCreateDatabase(
                        databaseFile,
                        password,
                        null,
                        null,
                        null
                );

        db.execSQL("PRAGMA foreign_keys = ON");

        int currentVersion = db.getVersion();

        if (currentVersion == 0) {

            createVersion1Schema(db);

            db.setVersion(DATABASE_VERSION);

        } else if (currentVersion < DATABASE_VERSION) {

            migrateDatabase(
                    db,
                    currentVersion,
                    DATABASE_VERSION
            );
        }

        database = db;

        return database;
    }

    private void createVersion1Schema(
            SQLiteDatabase db
    ) {

        db.beginTransaction();

        try {

            createCredentialsTable(db);
            createSecureNotesTable(db);

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

        int version = oldVersion;

        db.beginTransaction();

        try {

            while (version < newVersion) {

                switch (version) {

                    // Future example:
                    //
                    // case 1:
                    //     migrateFrom1To2(db);
                    //     version = 2;
                    //     break;

                    default:
                        throw new IllegalStateException(
                                "No migration available from database version "
                                        + version
                        );
                }
            }

            db.setVersion(newVersion);

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
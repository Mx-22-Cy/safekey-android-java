package com.safekey.app.data.database;

import android.content.Context;

import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;

/**
 * Owner of one encrypted SQLCipher database connection.
 *
 * <p>The original open(byte[]) API is deliberately restricted to the v3
 * format while repository encryption support is being integrated. The new
 * openForItemEncryption(byte[], VaultItemCipher) entry point is the v4
 * migration seam. No normal app caller uses it until the repositories and
 * service have been switched over together.</p>
 */
public class SafeKeyDatabase {

    private static final String DEFAULT_DATABASE_NAME = "safekey.db";
    private static final int DATABASE_VERSION = 3;
    private static final int ITEM_ENCRYPTED_DATABASE_VERSION = 4;

    public static final int DATABASE_KEY_LENGTH_BYTES = 32;

    private final Context context;
    private final String databaseName;
    private SQLiteDatabase database;

    static {
        System.loadLibrary("sqlcipher");
    }

    public SafeKeyDatabase(Context context) {
        this(context, DEFAULT_DATABASE_NAME);
    }

    public SafeKeyDatabase(Context context, String databaseName) {
        if (databaseName == null || databaseName.trim().isEmpty()) {
            throw new IllegalArgumentException("Database name cannot be empty.");
        }
        this.context = Objects.requireNonNull(context, "context")
                .getApplicationContext();
        this.databaseName = databaseName;
    }

    /**
     * Legacy opening path, unchanged during staged integration. Refuses v4
     * databases instead of silently treating authenticated ciphertext as text.
     */
    public SQLiteDatabase open(byte[] databaseKey) {
        byte[] encodedDatabaseKey = SqlCipherKeyEncoder.encode(databaseKey);
        return openWithEncodedDatabaseKey(encodedDatabaseKey, null, DATABASE_VERSION);
    }

    /**
     * Opens and, if necessary, upgrades a v3 database to field-encryption v4.
     *
     * <p>The cipher must be derived from the same vault database key as this
     * call and is owned by the caller. Migration is atomic and the resulting
     * connection is published only after it succeeds. On any error the
     * connection is closed and no database handle is retained.</p>
     *
     * <p>Only call this method after the repositories have been prepared for
     * v4 field encryption. Until then, normal vault opening uses open().</p>
     */
    public SQLiteDatabase openForItemEncryption(
            byte[] databaseKey,
            VaultItemCipher itemCipher
    ) {
        Objects.requireNonNull(itemCipher, "itemCipher");
        if (itemCipher.isClosed()) {
            throw new IllegalStateException("Cannot open vault using a closed item cipher.");
        }
        byte[] encodedDatabaseKey = SqlCipherKeyEncoder.encode(databaseKey);
        return openWithEncodedDatabaseKey(
                encodedDatabaseKey, itemCipher, ITEM_ENCRYPTED_DATABASE_VERSION);
    }

    private SQLiteDatabase openWithEncodedDatabaseKey(
            byte[] encodedDatabaseKey,
            VaultItemCipher itemCipher,
            int targetVersion
    ) {
        SQLiteDatabase db = null;
        try {
            if (database != null && database.isOpen()) {
                db = database;
            } else {
                // The previous connection might have been closed directly.
                database = null;

                File databaseFile = context.getDatabasePath(databaseName);
                File parent = databaseFile.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                db = SQLiteDatabase.openOrCreateDatabase(
                        databaseFile, encodedDatabaseKey, null, null, null);
                db.execSQL("PRAGMA foreign_keys = ON");
            }

            int currentVersion = db.getVersion();
            if (currentVersion > targetVersion) {
                throw new IllegalStateException(
                        "Database version " + currentVersion
                                + " is newer than supported version "
                                + targetVersion + ".");
            }

            // Preserve the exact v0 -> v1 -> v2 -> v3 migration chain.
            if (currentVersion < DATABASE_VERSION) {
                migrateDatabase(db, currentVersion, DATABASE_VERSION);
                currentVersion = db.getVersion();
            }

            if (targetVersion == ITEM_ENCRYPTED_DATABASE_VERSION
                    && currentVersion == DATABASE_VERSION) {
                migrateItemEncryption(db, itemCipher);
            }

            if (db.getVersion() != targetVersion) {
                throw new IllegalStateException(
                        "Vault opened with an unexpected database version.");
            }

            database = db;
            return db;

        } catch (RuntimeException | Error initializationError) {
            try {
                if (db != null && db.isOpen()) {
                    db.close();
                }
            } catch (RuntimeException | Error closeError) {
                initializationError.addSuppressed(closeError);
            } finally {
                database = null;
            }
            throw initializationError;

        } finally {
            // SQLCipher has already consumed this encoded Java-memory key.
            Arrays.fill(encodedDatabaseKey, (byte) 0);
        }
    }

    private void migrateItemEncryption(
            SQLiteDatabase db,
            VaultItemCipher itemCipher
    ) {
        if (itemCipher == null || itemCipher.isClosed()) {
            throw new IllegalStateException("Vault item cipher is required for v4.");
        }

        db.beginTransaction();
        try {
            if (db.getVersion() != DATABASE_VERSION) {
                throw new IllegalStateException("Unexpected pre-migration database version.");
            }

            // DDL, encrypted field updates and user_version are one transaction.
            VaultItemEncryptionMigration.migrateVersion3(db, itemCipher);
            db.setVersion(ITEM_ENCRYPTED_DATABASE_VERSION);
            db.setTransactionSuccessful();
        } catch (AesGcmException encryptionError) {
            throw new IllegalStateException(
                    "Vault item encryption migration failed.", encryptionError);
        } finally {
            db.endTransaction();
        }
    }

    private void createCredentialsTable(SQLiteDatabase db) {
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
                        ")");
    }

    private void createSecureNotesTable(SQLiteDatabase db) {
        db.execSQL(
                "CREATE TABLE IF NOT EXISTS secure_notes (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                        "title TEXT NOT NULL, " +
                        "content_ciphertext TEXT NOT NULL, " +
                        "created_at INTEGER NOT NULL, " +
                        "updated_at INTEGER NOT NULL" +
                        ")");
    }

    private void createVaultProfileTable(SQLiteDatabase db) {
        db.execSQL(
                "CREATE TABLE IF NOT EXISTS vault_profile (" +
                        "id INTEGER PRIMARY KEY CHECK (id = 1), " +
                        "display_name TEXT NOT NULL DEFAULT 'Local Vault'" +
                        ")");
        db.execSQL(
                "INSERT OR IGNORE INTO vault_profile " +
                        "(id, display_name) VALUES (1, 'Local Vault')");
    }

    private void migrateDatabase(
            SQLiteDatabase db,
            int oldVersion,
            int newVersion
    ) {
        int version = oldVersion;
        db.beginTransaction();
        try {
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
                                        + "'NOT_CHECKED', 'NOT_FOUND', 'BREACHED', 'ERROR'))");
                        version = 2;
                        break;
                    case 2:
                        createVaultProfileTable(db);
                        version = 3;
                        break;
                    default:
                        throw new IllegalStateException(
                                "No migration available from database version " + version);
                }
            }

            db.setVersion(newVersion);
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
        return database != null && database.isOpen();
    }
}

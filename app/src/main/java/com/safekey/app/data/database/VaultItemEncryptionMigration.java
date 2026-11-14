package com.safekey.app.data.database;

import android.content.ContentValues;
import android.database.Cursor;

import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Transactional v3 legacy-data conversion for one unlocked SQLCipher vault.
 *
 * <p>This class deliberately does not open a vault, begin/commit a transaction,
 * or advance PRAGMA user_version. SafeKeyDatabase must invoke it only while
 * holding the open vault's item cipher and its single upgrade transaction.
 * Repository access must remain unavailable until that transaction commits.</p>
 *
 * <p>The caller must NEVER catch a cipher failure and return a plaintext value.
 * This migration is intended only for the unchanged v3 schema. If it encounters
 * partially altered schema, the ALTER statements fail closed; it must not guess
 * whether a field contains plaintext or ciphertext.</p>
 */
final class VaultItemEncryptionMigration {

    static final String RECORD_UUID_COLUMN = "record_uuid";
    static final String FIELD_VERSION_COLUMN = "field_encryption_version";

    private VaultItemEncryptionMigration() {
    }

    static void migrateVersion3(SQLiteDatabase database, VaultItemCipher cipher)
            throws AesGcmException {
        Objects.requireNonNull(database, "database");
        Objects.requireNonNull(cipher, "cipher");
        if (!database.inTransaction()) {
            throw new IllegalStateException(
                    "Item encryption migration requires an active upgrade transaction.");
        }
        if (cipher.isClosed()) {
            throw new IllegalStateException("Cannot migrate with a closed item cipher.");
        }

        // SQLite DDL and data updates must be committed together by the caller.
        addMetadata(database, "credentials");
        addMetadata(database, "secure_notes");

        List<CredentialLegacyRow> credentials = readLegacyCredentials(database);
        List<NoteLegacyRow> notes = readLegacyNotes(database);

        for (CredentialLegacyRow row : credentials) {
            String identity = UUID.randomUUID().toString();
            ContentValues values = new ContentValues();
            values.put(RECORD_UUID_COLUMN, identity);
            values.put(FIELD_VERSION_COLUMN, VaultItemCipher.ENCRYPTION_VERSION);
            values.put("password_ciphertext", cipher.encrypt(
                    VaultItemCipher.Field.CREDENTIAL_PASSWORD,
                    identity, row.password));
            values.put("notes_ciphertext", cipher.encrypt(
                    VaultItemCipher.Field.CREDENTIAL_NOTES,
                    identity, row.notes));
            int updated = database.update("credentials", values,
                    "id = ? AND " + FIELD_VERSION_COLUMN + " = 0 AND "
                            + RECORD_UUID_COLUMN + " IS NULL",
                    new String[]{Long.toString(row.id)});
            if (updated != 1) {
                throw new IllegalStateException("Credential migration changed an unexpected row count.");
            }
        }

        for (NoteLegacyRow row : notes) {
            String identity = UUID.randomUUID().toString();
            ContentValues values = new ContentValues();
            values.put(RECORD_UUID_COLUMN, identity);
            values.put(FIELD_VERSION_COLUMN, VaultItemCipher.ENCRYPTION_VERSION);
            values.put("content_ciphertext", cipher.encrypt(
                    VaultItemCipher.Field.SECURE_NOTE_CONTENT,
                    identity, row.content));
            int updated = database.update("secure_notes", values,
                    "id = ? AND " + FIELD_VERSION_COLUMN + " = 0 AND "
                            + RECORD_UUID_COLUMN + " IS NULL",
                    new String[]{Long.toString(row.id)});
            if (updated != 1) {
                throw new IllegalStateException("Note migration changed an unexpected row count.");
            }
        }

        // UNIQUE identity indices also prevent later identity reuse in each table.
        database.execSQL("CREATE UNIQUE INDEX idx_credentials_record_uuid "
                + "ON credentials(record_uuid)");
        database.execSQL("CREATE UNIQUE INDEX idx_secure_notes_record_uuid "
                + "ON secure_notes(record_uuid)");

        requireFullyConverted(database, "credentials");
        requireFullyConverted(database, "secure_notes");
    }

    private static void addMetadata(SQLiteDatabase database, String table) {
        // Table names are internal literals, never supplied by an external caller.
        database.execSQL("ALTER TABLE " + table
                + " ADD COLUMN " + RECORD_UUID_COLUMN + " TEXT");
        database.execSQL("ALTER TABLE " + table + " ADD COLUMN "
                + FIELD_VERSION_COLUMN + " INTEGER NOT NULL DEFAULT 0 "
                + "CHECK (" + FIELD_VERSION_COLUMN + " IN (0, 1))");
    }

    private static List<CredentialLegacyRow> readLegacyCredentials(SQLiteDatabase database) {
        List<CredentialLegacyRow> rows = new ArrayList<>();
        Cursor cursor = database.rawQuery(
                "SELECT id, password_ciphertext, notes_ciphertext FROM credentials", null);
        try {
            while (cursor.moveToNext()) {
                rows.add(new CredentialLegacyRow(cursor.getLong(0),
                        Objects.requireNonNull(cursor.getString(1), "Legacy password is null"),
                        Objects.requireNonNull(cursor.getString(2), "Legacy notes are null")));
            }
        } finally {
            cursor.close();
        }
        return rows;
    }

    private static List<NoteLegacyRow> readLegacyNotes(SQLiteDatabase database) {
        List<NoteLegacyRow> rows = new ArrayList<>();
        Cursor cursor = database.rawQuery(
                "SELECT id, content_ciphertext FROM secure_notes", null);
        try {
            while (cursor.moveToNext()) {
                rows.add(new NoteLegacyRow(cursor.getLong(0),
                        Objects.requireNonNull(cursor.getString(1), "Legacy note content is null")));
            }
        } finally {
            cursor.close();
        }
        return rows;
    }

    private static void requireFullyConverted(SQLiteDatabase database, String table) {
        Cursor cursor = database.rawQuery("SELECT COUNT(*) FROM " + table
                + " WHERE " + RECORD_UUID_COLUMN + " IS NULL OR "
                + FIELD_VERSION_COLUMN + " != ?",
                new String[]{Integer.toString(VaultItemCipher.ENCRYPTION_VERSION)});
        try {
            if (!cursor.moveToFirst() || cursor.getLong(0) != 0L) {
                throw new IllegalStateException("Vault contains unmigrated " + table + " records.");
            }
        } finally {
            cursor.close();
        }
    }

    private static final class CredentialLegacyRow {
        final long id;
        final String password;
        final String notes;

        CredentialLegacyRow(long id, String password, String notes) {
            this.id = id;
            this.password = password;
            this.notes = notes;
        }
    }

    private static final class NoteLegacyRow {
        final long id;
        final String content;

        NoteLegacyRow(long id, String content) {
            this.id = id;
            this.content = content;
        }
    }
}

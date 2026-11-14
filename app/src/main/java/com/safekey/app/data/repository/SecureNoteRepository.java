package com.safekey.app.data.repository;

import android.content.ContentValues;
import android.database.Cursor;

import com.safekey.app.data.model.SecureNote;
import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/**
 * Stores Secure Notes in one already-open SQLCipher vault database.
 *
 * <p>The one-argument constructor is restricted to legacy v3 databases.
 * The two-argument constructor is restricted to encrypted v4 databases and
 * receives the same per-vault cipher used by the other repositories.
 * Neither constructor authorizes a session; the owning VaultDataService must
 * enforce current Real/Decoy authentication before calling this repository.</p>
 *
 * <p>Encrypted rows must have explicit version-1 metadata and canonical UUIDs.
 * Cipher failures are errors, never signals to return stored text as plaintext.
 * The owning vault service is responsible for closing the cipher.</p>
 */
public class SecureNoteRepository {

    private static final String TABLE = "secure_notes";
    private static final String UUID_COLUMN = "record_uuid";
    private static final String VERSION_COLUMN = "field_encryption_version";
    private static final int LEGACY_DATABASE_VERSION = 3;
    private static final int ENCRYPTED_DATABASE_VERSION = 4;

    private final SQLiteDatabase database;
    private final VaultItemCipher itemCipher;
    private final int expectedDatabaseVersion;

    /** Legacy v3 path. It refuses a v4 database. */
    public SecureNoteRepository(SQLiteDatabase database) {
        this(database, null, LEGACY_DATABASE_VERSION);
    }

    /** Encryption-aware v4 path. The caller owns and closes the cipher. */
    public SecureNoteRepository(SQLiteDatabase database, VaultItemCipher itemCipher) {
        this(database, Objects.requireNonNull(itemCipher, "itemCipher"),
                ENCRYPTED_DATABASE_VERSION);
    }

    private SecureNoteRepository(
            SQLiteDatabase database,
            VaultItemCipher itemCipher,
            int expectedDatabaseVersion
    ) {
        this.database = Objects.requireNonNull(database, "database");
        this.itemCipher = itemCipher;
        this.expectedDatabaseVersion = expectedDatabaseVersion;
        requireUsable();
    }

    public long insert(SecureNote note) {
        requireUsable();
        Objects.requireNonNull(note, "note");

        ContentValues values = new ContentValues();
        values.put("title", note.getTitle());
        values.put("created_at", note.getCreatedAt());
        values.put("updated_at", note.getUpdatedAt());

        if (itemCipher != null) {
            String identity = UUID.randomUUID().toString();
            values.put(UUID_COLUMN, identity);
            values.put(VERSION_COLUMN, VaultItemCipher.ENCRYPTION_VERSION);
            values.put("content_ciphertext", encrypt(identity, note.getContent()));
        } else {
            values.put("content_ciphertext", note.getContent());
        }

        return database.insert(TABLE, null, values);
    }

    public List<SecureNote> getAll() {
        requireUsable();
        List<SecureNote> notes = new ArrayList<>();
        Cursor cursor = database.query(TABLE, null, null, null, null, null,
                "updated_at DESC");
        try {
            while (cursor.moveToNext()) {
                notes.add(fromCursor(cursor));
            }
        } finally {
            cursor.close();
        }
        return notes;
    }

    public SecureNote getById(long id) {
        requireUsable();
        Cursor cursor = database.query(TABLE, null, "id = ?",
                new String[]{Long.toString(id)}, null, null, null);
        try {
            return cursor.moveToFirst() ? fromCursor(cursor) : null;
        } finally {
            cursor.close();
        }
    }

    public int update(SecureNote note) {
        requireUsable();
        Objects.requireNonNull(note, "note");

        database.beginTransaction();
        try {
            // Authenticate the old ciphertext before any modification.
            SecureNote existing = getById(note.getId());
            if (existing == null) {
                database.setTransactionSuccessful();
                return 0;
            }

            ContentValues values = new ContentValues();
            values.put("title", note.getTitle());
            values.put("updated_at", System.currentTimeMillis());

            if (itemCipher != null) {
                String identity = requireRecordIdentity(note.getId());
                values.put("content_ciphertext", encrypt(identity, note.getContent()));
                // Never replace record_uuid or field_encryption_version on an edit.
            } else {
                values.put("content_ciphertext", note.getContent());
            }

            int changed = database.update(TABLE, values, "id = ?",
                    new String[]{Long.toString(note.getId())});
            database.setTransactionSuccessful();
            return changed;
        } finally {
            database.endTransaction();
        }
    }

    public int delete(long id) {
        requireUsable();
        return database.delete(TABLE, "id = ?", new String[]{Long.toString(id)});
    }

    /**
     * Content search is restricted to the opened repository. It decrypts and
     * authenticates each considered row in memory; SQL LIKE is never applied
     * to randomized content ciphertext. Search terms are literal, not SQL
     * wildcard patterns, and all intermediate values stay in this operation.
     */
    public List<SecureNote> search(String query) {
        requireUsable();
        String normalized = Objects.requireNonNull(query, "query")
                .trim().toLowerCase(Locale.ROOT);
        List<SecureNote> notes = new ArrayList<>();
        Cursor cursor = database.query(TABLE, null, null, null, null, null,
                "updated_at DESC");
        try {
            while (cursor.moveToNext()) {
                SecureNote note = fromCursor(cursor);
                String title = note.getTitle();
                String content = note.getContent();
                boolean titleMatches = title != null
                        && title.toLowerCase(Locale.ROOT).contains(normalized);
                boolean contentMatches = content != null
                        && content.toLowerCase(Locale.ROOT).contains(normalized);
                if (titleMatches || contentMatches) {
                    notes.add(note);
                }
            }
        } finally {
            cursor.close();
        }
        return notes;
    }

    private SecureNote fromCursor(Cursor cursor) {
        String content = cursor.getString(
                cursor.getColumnIndexOrThrow("content_ciphertext"));
        if (itemCipher != null) {
            String identity = identityFromCursor(cursor);
            content = decrypt(identity, content);
        }
        return new SecureNote(
                cursor.getLong(cursor.getColumnIndexOrThrow("id")),
                cursor.getString(cursor.getColumnIndexOrThrow("title")),
                content,
                cursor.getLong(cursor.getColumnIndexOrThrow("created_at")),
                cursor.getLong(cursor.getColumnIndexOrThrow("updated_at")));
    }

    private String requireRecordIdentity(long id) {
        Cursor cursor = database.query(TABLE,
                new String[]{UUID_COLUMN, VERSION_COLUMN}, "id = ?",
                new String[]{Long.toString(id)}, null, null, null);
        try {
            if (!cursor.moveToFirst()) {
                throw new IllegalStateException("Secure Note disappeared during update.");
            }
            return identityFromCursor(cursor);
        } finally {
            cursor.close();
        }
    }

    private static String identityFromCursor(Cursor cursor) {
        int version = cursor.getInt(cursor.getColumnIndexOrThrow(VERSION_COLUMN));
        String identity = cursor.getString(cursor.getColumnIndexOrThrow(UUID_COLUMN));
        if (version != VaultItemCipher.ENCRYPTION_VERSION || identity == null) {
            throw new IllegalStateException(
                    "Secure Note has missing or unsupported field-encryption metadata.");
        }
        try {
            if (!UUID.fromString(identity).toString().equals(identity)) {
                throw new IllegalArgumentException("Noncanonical record UUID.");
            }
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("Secure Note has invalid encryption identity.", invalid);
        }
        return identity;
    }

    private String encrypt(String identity, String content) {
        try {
            return itemCipher.encrypt(
                    VaultItemCipher.Field.SECURE_NOTE_CONTENT, identity, content);
        } catch (AesGcmException failure) {
            throw new IllegalStateException("Could not encrypt Secure Note content.", failure);
        }
    }

    private String decrypt(String identity, String encryptedContent) {
        try {
            return itemCipher.decrypt(
                    VaultItemCipher.Field.SECURE_NOTE_CONTENT, identity, encryptedContent);
        } catch (AesGcmException failure) {
            throw new IllegalStateException(
                    "Secure Note content authentication or decryption failed.", failure);
        }
    }

    private void requireUsable() {
        if (!database.isOpen() || database.getVersion() != expectedDatabaseVersion) {
            throw new IllegalStateException(
                    "Secure Note repository requires database version "
                            + expectedDatabaseVersion + ".");
        }
        if (itemCipher != null && itemCipher.isClosed()) {
            throw new IllegalStateException("Vault item cipher has been closed.");
        }
    }
}

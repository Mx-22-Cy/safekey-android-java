package com.safekey.app.data.repository;

import android.content.ContentValues;
import android.database.Cursor;

import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.data.model.Credential;
import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Stores credentials in a single already-opened SQLCipher vault.
 *
 * <p>The one-argument constructor remains available for version 3 until
 * VaultDataService switches to encryption-aware opening. It refuses version 4
 * rather than returning authenticated ciphertext as though it were plaintext.
 * The two-argument constructor requires version 4 and an active per-vault
 * VaultItemCipher. It never falls back to plaintext on a decryption failure.</p>
 *
 * <p>Repository access must be authorized by the owning vault service.
 * This class does not decide which Real/Decoy session is authenticated.</p>
 */
public class CredentialRepository {

    private static final int LEGACY_DATABASE_VERSION = 3;
    private static final int ENCRYPTED_DATABASE_VERSION = 4;
    private static final String TABLE = "credentials";
    private static final String UUID_COLUMN = "record_uuid";
    private static final String VERSION_COLUMN = "field_encryption_version";

    private final SQLiteDatabase database;
    private final VaultItemCipher itemCipher;
    private final int expectedDatabaseVersion;

    /** Legacy, version-3-only path. Must not be used after v4 activation. */
    public CredentialRepository(SQLiteDatabase database) {
        this(database, null, LEGACY_DATABASE_VERSION);
    }

    /** Encryption-aware version-4 path; caller owns and closes the cipher. */
    public CredentialRepository(SQLiteDatabase database, VaultItemCipher itemCipher) {
        this(database, Objects.requireNonNull(itemCipher, "itemCipher"),
                ENCRYPTED_DATABASE_VERSION);
    }

    private CredentialRepository(
            SQLiteDatabase database,
            VaultItemCipher itemCipher,
            int expectedDatabaseVersion
    ) {
        this.database = Objects.requireNonNull(database, "database");
        this.itemCipher = itemCipher;
        this.expectedDatabaseVersion = expectedDatabaseVersion;
        requireUsable();
    }

    public long insert(Credential credential) {
        requireUsable();
        Objects.requireNonNull(credential, "credential");
        ContentValues values = new ContentValues();
        values.put("title", credential.getTitle());
        values.put("username", credential.getUsername());
        values.put("website", credential.getWebsite());
        values.put("category", credential.getCategory());
        values.put("favorite", credential.isFavorite() ? 1 : 0);
        values.put("created_at", credential.getCreatedAt());
        values.put("updated_at", credential.getUpdatedAt());

        if (itemCipher != null) {
            // The record identity must be committed together with its fields.
            String identity = UUID.randomUUID().toString();
            values.put(UUID_COLUMN, identity);
            values.put(VERSION_COLUMN, VaultItemCipher.ENCRYPTION_VERSION);
            values.put("password_ciphertext", encrypt(
                    VaultItemCipher.Field.CREDENTIAL_PASSWORD,
                    identity, credential.getPassword()));
            values.put("notes_ciphertext", encrypt(
                    VaultItemCipher.Field.CREDENTIAL_NOTES,
                    identity, credential.getNotes()));
        } else {
            values.put("password_ciphertext", credential.getPassword());
            values.put("notes_ciphertext", credential.getNotes());
        }

        return database.insert(TABLE, null, values);
    }

    public List<Credential> getAll() {
        requireUsable();
        List<Credential> credentials = new ArrayList<>();
        Cursor cursor = database.query(TABLE, null, null, null, null, null,
                "favorite DESC, updated_at DESC");
        try {
            while (cursor.moveToNext()) {
                credentials.add(fromCursor(cursor));
            }
        } finally {
            cursor.close();
        }
        return credentials;
    }

    public Credential getById(long id) {
        requireUsable();
        Cursor cursor = database.query(TABLE, null, "id = ?",
                new String[]{Long.toString(id)}, null, null, null);
        try {
            return cursor.moveToFirst() ? fromCursor(cursor) : null;
        } finally {
            cursor.close();
        }
    }

    public int update(Credential credential) {
        requireUsable();
        Objects.requireNonNull(credential, "credential");
        database.beginTransaction();
        try {
            // Reading also authenticates stored ciphertext before modifying it.
            Credential existing = getById(credential.getId());
            if (existing == null) {
                database.setTransactionSuccessful();
                return 0;
            }

            ContentValues values = new ContentValues();
            values.put("title", credential.getTitle());
            values.put("username", credential.getUsername());
            values.put("website", credential.getWebsite());
            values.put("category", credential.getCategory());
            values.put("favorite", credential.isFavorite() ? 1 : 0);
            values.put("updated_at", System.currentTimeMillis());

            if (itemCipher != null) {
                String identity = requireRecordIdentity(credential.getId());
                values.put("password_ciphertext", encrypt(
                        VaultItemCipher.Field.CREDENTIAL_PASSWORD,
                        identity, credential.getPassword()));
                values.put("notes_ciphertext", encrypt(
                        VaultItemCipher.Field.CREDENTIAL_NOTES,
                        identity, credential.getNotes()));
                // Neither record_uuid nor field_encryption_version changes on edit.
            } else {
                values.put("password_ciphertext", credential.getPassword());
                values.put("notes_ciphertext", credential.getNotes());
            }

            if (!Objects.equals(existing.getPassword(), credential.getPassword())) {
                values.put("breach_status", PasswordBreachResult.Status.NOT_CHECKED.name());
            }

            int changed = database.update(TABLE, values, "id = ?",
                    new String[]{Long.toString(credential.getId())});
            database.setTransactionSuccessful();
            return changed;
        } finally {
            database.endTransaction();
        }
    }

    /**
     * Only saves a breach result for the password still in this row.
     * The check and the status update run inside the same transaction, so a
     * randomized encrypted password is never compared directly in SQL.
     */
    public PasswordBreachResult.Status updateBreachStatus(
            long id, String expectedPassword, PasswordBreachResult.Status incoming
    ) {
        requireUsable();
        Objects.requireNonNull(expectedPassword, "expectedPassword");
        Objects.requireNonNull(incoming, "incoming");
        database.beginTransaction();
        try {
            Credential current = getById(id);
            if (current == null || !expectedPassword.equals(current.getPassword())) {
                database.setTransactionSuccessful();
                return null;
            }

            PasswordBreachResult.Status stored = current.getBreachStatus();
            PasswordBreachResult.Status effective = incoming;
            if (stored == PasswordBreachResult.Status.BREACHED
                    || ((incoming == PasswordBreachResult.Status.ERROR
                    || incoming == PasswordBreachResult.Status.NOT_CHECKED)
                    && stored == PasswordBreachResult.Status.NOT_FOUND)) {
                effective = stored;
            }

            ContentValues values = new ContentValues();
            values.put("breach_status", effective.name());
            int changed = database.update(TABLE, values, "id = ?",
                    new String[]{Long.toString(id)});
            database.setTransactionSuccessful();
            return changed == 1 ? effective : null;
        } finally {
            database.endTransaction();
        }
    }

    public int delete(long id) {
        requireUsable();
        return database.delete(TABLE, "id = ?", new String[]{Long.toString(id)});
    }

    public List<Credential> search(String query) {
        requireUsable();
        String searchText = "%" + Objects.requireNonNull(query, "query").trim() + "%";
        List<Credential> credentials = new ArrayList<>();
        Cursor cursor = database.query(TABLE, null,
                "title LIKE ? OR username LIKE ? OR website LIKE ? OR category LIKE ?",
                new String[]{searchText, searchText, searchText, searchText},
                null, null, "favorite DESC, updated_at DESC");
        try {
            while (cursor.moveToNext()) {
                credentials.add(fromCursor(cursor));
            }
        } finally {
            cursor.close();
        }
        return credentials;
    }

    public int setFavorite(long id, boolean favorite) {
        requireUsable();
        ContentValues values = new ContentValues();
        values.put("favorite", favorite ? 1 : 0);
        values.put("updated_at", System.currentTimeMillis());
        return database.update(TABLE, values, "id = ?",
                new String[]{Long.toString(id)});
    }

    private Credential fromCursor(Cursor cursor) {
        long id = cursor.getLong(cursor.getColumnIndexOrThrow("id"));
        String password = cursor.getString(cursor.getColumnIndexOrThrow("password_ciphertext"));
        String notes = cursor.getString(cursor.getColumnIndexOrThrow("notes_ciphertext"));

        if (itemCipher != null) {
            // Strict metadata check: no encrypted value may become plaintext.
            String identity = identityFromCursor(cursor);
            password = decrypt(VaultItemCipher.Field.CREDENTIAL_PASSWORD, identity, password);
            notes = decrypt(VaultItemCipher.Field.CREDENTIAL_NOTES, identity, notes);
        }

        Credential credential = new Credential(
                id,
                cursor.getString(cursor.getColumnIndexOrThrow("title")),
                cursor.getString(cursor.getColumnIndexOrThrow("username")),
                password,
                cursor.getString(cursor.getColumnIndexOrThrow("website")),
                cursor.getString(cursor.getColumnIndexOrThrow("category")),
                notes,
                cursor.getInt(cursor.getColumnIndexOrThrow("favorite")) == 1,
                cursor.getLong(cursor.getColumnIndexOrThrow("created_at")),
                cursor.getLong(cursor.getColumnIndexOrThrow("updated_at")));

        try {
            credential.setBreachStatus(PasswordBreachResult.Status.valueOf(
                    cursor.getString(cursor.getColumnIndexOrThrow("breach_status"))));
        } catch (IllegalArgumentException | NullPointerException invalid) {
            credential.setBreachStatus(PasswordBreachResult.Status.ERROR);
        }
        return credential;
    }

    private String requireRecordIdentity(long id) {
        Cursor cursor = database.query(TABLE,
                new String[]{UUID_COLUMN, VERSION_COLUMN}, "id = ?",
                new String[]{Long.toString(id)}, null, null, null);
        try {
            if (!cursor.moveToFirst()) {
                throw new IllegalStateException("Credential disappeared during update.");
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
                    "Credential has missing or unsupported field-encryption metadata.");
        }
        // The cipher checks canonical UUIDs as part of authenticated decryption.
        return identity;
    }

    private String encrypt(VaultItemCipher.Field field, String identity, String text) {
        try {
            return itemCipher.encrypt(field, identity, text);
        } catch (AesGcmException failure) {
            throw new IllegalStateException("Could not encrypt credential field.", failure);
        }
    }

    private String decrypt(VaultItemCipher.Field field, String identity, String text) {
        try {
            return itemCipher.decrypt(field, identity, text);
        } catch (AesGcmException failure) {
            throw new IllegalStateException(
                    "Credential field authentication or decryption failed.", failure);
        }
    }

    private void requireUsable() {
        if (!database.isOpen() || database.getVersion() != expectedDatabaseVersion) {
            throw new IllegalStateException(
                    "Credential repository requires database version "
                            + expectedDatabaseVersion + ".");
        }
        if (itemCipher != null && itemCipher.isClosed()) {
            throw new IllegalStateException("Vault item cipher has been closed.");
        }
    }
}

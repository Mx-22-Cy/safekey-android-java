package com.safekey.app.data.repository;

import android.content.ContentValues;
import android.database.Cursor;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.Objects;

/**
 * Stores the display name of one encrypted vault.
 *
 * Each SQLCipher database contains its own vault_profile
 * table, so REAL and DECOY names remain independent.
 */
public final class VaultProfileRepository {

    public static final String DEFAULT_DISPLAY_NAME = "Local Vault";

    private static final int PROFILE_ID = 1;
    private static final int MAX_DISPLAY_NAME_LENGTH = 64;

    private final SQLiteDatabase database;

    public VaultProfileRepository(SQLiteDatabase database) {
        this.database = Objects.requireNonNull(database, "database");
    }

    /**
     * Returns the current vault display name.
     *
     * Requires an open encrypted vault database.
     */
    public String getDisplayName() {

        try (Cursor cursor = database.rawQuery(
                "SELECT display_name FROM vault_profile WHERE id = 1",
                null
        )) {

            if (!cursor.moveToFirst()) {
                throw new IllegalStateException(
                        "Vault profile has not been initialized."
                );
            }

            return cursor.getString(0);
        }
    }

    /**
     * Updates the display name stored in this vault database.
     *
     * Returns the number of updated rows.
     */
    public int updateDisplayName(String displayName) {

        String validatedName = validateDisplayName(displayName);

        ContentValues values = new ContentValues();
        values.put("display_name", validatedName);

        int updatedRows = database.update(
                "vault_profile",
                values,
                "id = ?",
                new String[]{String.valueOf(PROFILE_ID)}
        );

        if (updatedRows != 1) {
            throw new IllegalStateException(
                    "Vault profile could not be updated."
            );
        }

        return updatedRows;
    }

    /**
     * Prevents empty or excessively long display names.
     */
    private static String validateDisplayName(String displayName) {

        if (displayName == null) {
            throw new IllegalArgumentException(
                    "Vault display name cannot be null."
            );
        }

        String trimmedName = displayName.trim();

        if (trimmedName.isEmpty()) {
            throw new IllegalArgumentException(
                    "Vault display name cannot be empty."
            );
        }

        if (trimmedName.length() > MAX_DISPLAY_NAME_LENGTH) {
            throw new IllegalArgumentException(
                    "Vault display name cannot exceed "
                            + MAX_DISPLAY_NAME_LENGTH
                            + " characters."
            );
        }

        return trimmedName;
    }
}

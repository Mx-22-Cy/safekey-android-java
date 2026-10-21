package com.safekey.app.data.repository;

import android.database.Cursor;

import com.safekey.app.data.model.VaultCounts;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.Objects;

/**
 * Reads the three totals in one statement on the service worker.
 */
public final class VaultCountsRepository {

    private static final String COUNTS_QUERY =
            "SELECT "
                    + "(SELECT COUNT(*) FROM credentials), "
                    + "(SELECT COUNT(*) FROM credentials WHERE favorite = 1), "
                    + "(SELECT COUNT(*) FROM secure_notes)";

    private final SQLiteDatabase database;

    public VaultCountsRepository(SQLiteDatabase database) {
        this.database = Objects.requireNonNull(database, "database");
    }

    public VaultCounts getCounts() {
        try (Cursor cursor = database.rawQuery(COUNTS_QUERY, null)) {
            if (!cursor.moveToFirst()) {
                throw new IllegalStateException("Unable to read vault counts.");
            }

            return new VaultCounts(
                    cursor.getLong(0),
                    cursor.getLong(1),
                    cursor.getLong(2)
            );
        }
    }
}

package com.safekey.app.data.repository;

import android.content.ContentValues;
import android.database.Cursor;

import com.safekey.app.data.model.SecureNote;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.ArrayList;
import java.util.List;

public class SecureNoteRepository {

    private final SQLiteDatabase database;

    public SecureNoteRepository(
            SQLiteDatabase database
    ) {
        this.database = database;
    }

    public long insert(
            SecureNote note
    ) {
        ContentValues values =
                new ContentValues();

        values.put(
                "title",
                note.getTitle()
        );

        values.put(
                "content_ciphertext",
                note.getContent()
        );

        values.put(
                "created_at",
                note.getCreatedAt()
        );

        values.put(
                "updated_at",
                note.getUpdatedAt()
        );

        return database.insert(
                "secure_notes",
                null,
                values
        );
    }

    public List<SecureNote> getAll() {

        List<SecureNote> notes =
                new ArrayList<>();

        Cursor cursor =
                database.query(
                        "secure_notes",
                        null,
                        null,
                        null,
                        null,
                        null,
                        "updated_at DESC"
                );

        try {
            while (cursor.moveToNext()) {
                notes.add(
                        fromCursor(cursor)
                );
            }
        } finally {
            cursor.close();
        }

        return notes;
    }

    public SecureNote getById(
            long id
    ) {

        Cursor cursor =
                database.query(
                        "secure_notes",
                        null,
                        "id = ?",
                        new String[]{
                                String.valueOf(id)
                        },
                        null,
                        null,
                        null
                );

        try {
            if (cursor.moveToFirst()) {
                return fromCursor(cursor);
            }

            return null;

        } finally {
            cursor.close();
        }
    }

    public int update(
            SecureNote note
    ) {

        ContentValues values =
                new ContentValues();

        values.put(
                "title",
                note.getTitle()
        );

        values.put(
                "content_ciphertext",
                note.getContent()
        );

        values.put(
                "updated_at",
                System.currentTimeMillis()
        );

        return database.update(
                "secure_notes",
                values,
                "id = ?",
                new String[]{
                        String.valueOf(
                                note.getId()
                        )
                }
        );
    }

    public int delete(
            long id
    ) {

        return database.delete(
                "secure_notes",
                "id = ?",
                new String[]{
                        String.valueOf(id)
                }
        );
    }

    public List<SecureNote> search(
            String query
    ) {

        List<SecureNote> notes =
                new ArrayList<>();

        String searchText =
                "%" + query.trim() + "%";

        Cursor cursor =
                database.query(
                        "secure_notes",
                        null,
                        "title LIKE ? OR content_ciphertext LIKE ?",
                        new String[]{
                                searchText,
                                searchText
                        },
                        null,
                        null,
                        "updated_at DESC"
                );

        try {
            while (cursor.moveToNext()) {
                notes.add(
                        fromCursor(cursor)
                );
            }
        } finally {
            cursor.close();
        }

        return notes;
    }

    private SecureNote fromCursor(
            Cursor cursor
    ) {

        return new SecureNote(
                cursor.getLong(
                        cursor.getColumnIndexOrThrow(
                                "id"
                        )
                ),

                cursor.getString(
                        cursor.getColumnIndexOrThrow(
                                "title"
                        )
                ),

                cursor.getString(
                        cursor.getColumnIndexOrThrow(
                                "content_ciphertext"
                        )
                ),

                cursor.getLong(
                        cursor.getColumnIndexOrThrow(
                                "created_at"
                        )
                ),

                cursor.getLong(
                        cursor.getColumnIndexOrThrow(
                                "updated_at"
                        )
                )
        );
    }
}
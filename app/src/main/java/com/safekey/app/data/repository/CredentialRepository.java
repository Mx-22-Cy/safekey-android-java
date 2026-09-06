package com.safekey.app.data.repository;

import android.content.ContentValues;
import android.database.Cursor;

import com.safekey.app.data.model.Credential;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.ArrayList;
import java.util.List;

public class CredentialRepository {

    private final SQLiteDatabase database;

    public CredentialRepository(
            SQLiteDatabase database
    ) {
        this.database = database;
    }

    public long insert(
            Credential credential
    ) {

        ContentValues values =
                new ContentValues();

        values.put(
                "title",
                credential.getTitle()
        );

        values.put(
                "username",
                credential.getUsername()
        );

        values.put(
                "password_ciphertext",
                credential.getPassword()
        );

        values.put(
                "website",
                credential.getWebsite()
        );

        values.put(
                "category",
                credential.getCategory()
        );

        values.put(
                "notes_ciphertext",
                credential.getNotes()
        );

        values.put(
                "favorite",
                credential.isFavorite() ? 1 : 0
        );

        values.put(
                "created_at",
                credential.getCreatedAt()
        );

        values.put(
                "updated_at",
                credential.getUpdatedAt()
        );

        return database.insert(
                "credentials",
                null,
                values
        );
    }

    public List<Credential> getAll() {

        List<Credential> credentials =
                new ArrayList<>();

        Cursor cursor =
                database.query(
                        "credentials",
                        null,
                        null,
                        null,
                        null,
                        null,
                        "favorite DESC, updated_at DESC"
                );

        try {

            while (cursor.moveToNext()) {

                credentials.add(
                        fromCursor(cursor)
                );
            }

        } finally {

            cursor.close();
        }

        return credentials;
    }

    public Credential getById(
            long id
    ) {

        Cursor cursor =
                database.query(
                        "credentials",
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
            Credential credential
    ) {

        ContentValues values =
                new ContentValues();

        values.put(
                "title",
                credential.getTitle()
        );

        values.put(
                "username",
                credential.getUsername()
        );

        values.put(
                "password_ciphertext",
                credential.getPassword()
        );

        values.put(
                "website",
                credential.getWebsite()
        );

        values.put(
                "category",
                credential.getCategory()
        );

        values.put(
                "notes_ciphertext",
                credential.getNotes()
        );

        values.put(
                "favorite",
                credential.isFavorite() ? 1 : 0
        );

        values.put(
                "updated_at",
                System.currentTimeMillis()
        );

        return database.update(
                "credentials",
                values,
                "id = ?",
                new String[]{
                        String.valueOf(
                                credential.getId()
                        )
                }
        );
    }

    public int delete(
            long id
    ) {

        return database.delete(
                "credentials",
                "id = ?",
                new String[]{
                        String.valueOf(id)
                }
        );
    }

    public List<Credential> search(
            String query
    ) {

        List<Credential> credentials =
                new ArrayList<>();

        String searchText =
                "%" + query.trim() + "%";

        Cursor cursor =
                database.query(
                        "credentials",
                        null,
                        "title LIKE ? " +
                                "OR username LIKE ? " +
                                "OR website LIKE ? " +
                                "OR category LIKE ?",
                        new String[]{
                                searchText,
                                searchText,
                                searchText,
                                searchText
                        },
                        null,
                        null,
                        "favorite DESC, updated_at DESC"
                );

        try {

            while (cursor.moveToNext()) {

                credentials.add(
                        fromCursor(cursor)
                );
            }

        } finally {

            cursor.close();
        }

        return credentials;
    }

    public int setFavorite(
            long id,
            boolean favorite
    ) {

        ContentValues values =
                new ContentValues();

        values.put(
                "favorite",
                favorite ? 1 : 0
        );

        values.put(
                "updated_at",
                System.currentTimeMillis()
        );

        return database.update(
                "credentials",
                values,
                "id = ?",
                new String[]{
                        String.valueOf(id)
                }
        );
    }

    private Credential fromCursor(
            Cursor cursor
    ) {

        return new Credential(
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
                                "username"
                        )
                ),

                cursor.getString(
                        cursor.getColumnIndexOrThrow(
                                "password_ciphertext"
                        )
                ),

                cursor.getString(
                        cursor.getColumnIndexOrThrow(
                                "website"
                        )
                ),

                cursor.getString(
                        cursor.getColumnIndexOrThrow(
                                "category"
                        )
                ),

                cursor.getString(
                        cursor.getColumnIndexOrThrow(
                                "notes_ciphertext"
                        )
                ),

                cursor.getInt(
                        cursor.getColumnIndexOrThrow(
                                "favorite"
                        )
                ) == 1,

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
package com.safekey.app;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.repository.CredentialRepository;
import com.safekey.app.data.repository.SecureNoteRepository;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SAFEKEY_TEST";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView textView = new TextView(this);
        textView.setPadding(40, 80, 40, 40);
        textView.setTextSize(20);
        textView.setText(
                "SafeKey Java SQLCipher test running.\nCheck Logcat."
        );

        setContentView(textView);

        runDatabaseTest();
    }

    private void runDatabaseTest() {

        SafeKeyDatabase databaseManager =
                new SafeKeyDatabase(this);

        try {

            SQLiteDatabase database =
                    databaseManager.open(
                            "SafeKey-Test-Key-2026"
                    );

            Log.d(
                    TAG,
                    "SQLCipher database opened successfully"
            );

            CredentialRepository credentialRepository =
                    new CredentialRepository(database);

            SecureNoteRepository secureNoteRepository =
                    new SecureNoteRepository(database);

            // =====================================================
            // CREDENTIAL CRUD TEST
            // =====================================================

            Credential credential =
                    new Credential(
                            "GitHub",
                            "israa@example.com",
                            "TestPassword123!",
                            "github.com",
                            "Work",
                            "Temporary Java CRUD test"
                    );

            long credentialId =
                    credentialRepository.insert(
                            credential
                    );

            Log.d(
                    TAG,
                    "Credential inserted. ID = "
                            + credentialId
            );

            Credential savedCredential =
                    credentialRepository.getById(
                            credentialId
                    );

            if (savedCredential == null) {
                throw new IllegalStateException(
                        "Credential read failed"
                );
            }

            Log.d(
                    TAG,
                    "Credential read successfully"
            );

            savedCredential.setUsername(
                    "israa.updated@example.com"
            );

            int updatedRows =
                    credentialRepository.update(
                            savedCredential
                    );

            Log.d(
                    TAG,
                    "Credential updated. Rows = "
                            + updatedRows
            );

            credentialRepository.setFavorite(
                    credentialId,
                    true
            );

            Log.d(
                    TAG,
                    "Credential marked as favorite"
            );

            List<Credential> credentialSearch =
                    credentialRepository.search(
                            "GitHub"
                    );

            Log.d(
                    TAG,
                    "Credential search results = "
                            + credentialSearch.size()
            );

            // =====================================================
            // SECURE NOTE CRUD TEST
            // =====================================================

            SecureNote note =
                    new SecureNote(
                            "Test Note",
                            "SafeKey Java secure note test"
                    );

            long noteId =
                    secureNoteRepository.insert(
                            note
                    );

            Log.d(
                    TAG,
                    "Secure note inserted. ID = "
                            + noteId
            );

            SecureNote savedNote =
                    secureNoteRepository.getById(
                            noteId
                    );

            if (savedNote == null) {
                throw new IllegalStateException(
                        "Secure note read failed"
                );
            }

            Log.d(
                    TAG,
                    "Secure note read successfully"
            );

            savedNote.setContent(
                    "Updated secure note content"
            );

            int noteUpdatedRows =
                    secureNoteRepository.update(
                            savedNote
                    );

            Log.d(
                    TAG,
                    "Secure note updated. Rows = "
                            + noteUpdatedRows
            );

            List<SecureNote> noteSearch =
                    secureNoteRepository.search(
                            "Test"
                    );

            Log.d(
                    TAG,
                    "Secure note search results = "
                            + noteSearch.size()
            );

            // =====================================================
            // DELETE TEST
            // =====================================================

            credentialRepository.delete(
                    credentialId
            );

            secureNoteRepository.delete(
                    noteId
            );

            Log.d(
                    TAG,
                    "Temporary test records deleted"
            );

            Log.d(
                    TAG,
                    "ALL JAVA CRUD TESTS COMPLETED"
            );

        } catch (Exception e) {

            Log.e(
                    TAG,
                    "Java SQLCipher test failed",
                    e
            );

        } finally {

            databaseManager.close();

            Log.d(
                    TAG,
                    "SQLCipher database closed successfully"
            );
        }
    }
}
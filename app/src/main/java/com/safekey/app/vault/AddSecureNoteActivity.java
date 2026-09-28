package com.safekey.app.vault;

import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;

public class AddSecureNoteActivity extends AppCompatActivity {

    private AppCompatEditText editSecureNoteTitle;
    private AppCompatEditText editSecureNoteContent;

    @Override
    protected void onCreate(
            Bundle savedInstanceState
    ) {

        super.onCreate(
                savedInstanceState
        );

        WindowCompat.enableEdgeToEdge(
                getWindow()
        );

        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.setAppearanceLightStatusBars(
                false
        );

        insetsController.setAppearanceLightNavigationBars(
                false
        );

        setContentView(
                R.layout.activity_add_secure_note
        );

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(
                        R.id.rootAddSecureNote
                ),
                (view, windowInsets) -> {

                    Insets systemBars =
                            windowInsets.getInsets(
                                    WindowInsetsCompat.Type.systemBars()
                            );

                    view.setPadding(
                            systemBars.left,
                            systemBars.top,
                            systemBars.right,
                            systemBars.bottom
                    );

                    return windowInsets;
                }
        );

        bindViews();
        setupActions();
    }

    private void bindViews() {

        editSecureNoteTitle =
                findViewById(
                        R.id.editSecureNoteTitle
                );

        editSecureNoteContent =
                findViewById(
                        R.id.editSecureNoteContent
                );
    }

    private void setupActions() {

        TextView buttonCancel =
                findViewById(
                        R.id.buttonCancelAddSecureNote
                );

        TextView buttonSave =
                findViewById(
                        R.id.buttonSaveSecureNote
                );

        buttonCancel.setOnClickListener(
                view ->
                        finish()
        );

        buttonSave.setOnClickListener(
                view ->
                        validateAndContinue()
        );
    }

    private void validateAndContinue() {

        clearErrors();

        String title =
                readText(
                        editSecureNoteTitle
                );

        String content =
                readText(
                        editSecureNoteContent
                );

        boolean valid =
                true;

        if (title.isEmpty()) {

            editSecureNoteTitle.setError(
                    getString(
                            R.string.add_secure_note_error_title_required
                    )
            );

            valid =
                    false;
        }

        if (content.isEmpty()) {

            editSecureNoteContent.setError(
                    getString(
                            R.string.add_secure_note_error_content_required
                    )
            );

            valid =
                    false;
        }

        if (!valid) {
            return;
        }

        /*
         * WEEK 4 UI ONLY.
         *
         * Do not save directly here yet.
         * Encrypted persistence will be connected through
         * the approved data/service layer.
         */
        Toast.makeText(
                this,
                R.string.add_secure_note_save_pending,
                Toast.LENGTH_SHORT
        ).show();
    }

    private void clearErrors() {

        editSecureNoteTitle.setError(
                null
        );

        editSecureNoteContent.setError(
                null
        );
    }

    private String readText(
            AppCompatEditText editText
    ) {

        if (editText.getText() == null) {
            return "";
        }

        return editText
                .getText()
                .toString()
                .trim();
    }
}
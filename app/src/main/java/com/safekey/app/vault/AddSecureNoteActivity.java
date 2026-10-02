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
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;

public class AddSecureNoteActivity extends AppCompatActivity {

    public static final String EXTRA_EDIT_MODE =
            "secure_note_edit_mode";
    public static final String EXTRA_ID =
            "secure_note_id";
    private boolean editMode = false;
    private long secureNoteId = 0L;
    private SecureVaultCoordinator secureVaultCoordinator;
    private SecureNote loadedSecureNote;
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

        secureVaultCoordinator =
                ((SafeKeyApplication) getApplication())
                        .getSecureVaultCoordinator();

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
        loadEditData();
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

    private void loadEditData() {

        editMode =
                getIntent().getBooleanExtra(
                        EXTRA_EDIT_MODE,
                        false
                );

        if (!editMode) {
            return;
        }

        secureNoteId =
                getIntent().getLongExtra(
                        EXTRA_ID,
                        0L
                );

        TextView textTitle =
                findViewById(
                        R.id.textAddSecureNoteTitle
                );

        TextView textSubtitle =
                findViewById(
                        R.id.textAddSecureNoteSubtitle
                );

        TextView buttonSave =
                findViewById(
                        R.id.buttonSaveSecureNote
                );

        textTitle.setText(
                R.string.edit_secure_note_title
        );

        textSubtitle.setText(
                R.string.edit_secure_note_subtitle
        );

        buttonSave.setText(
                R.string.edit_secure_note_save
        );

        if (secureNoteId <= 0L) {

            Toast.makeText(
                    this,
                    R.string.secure_note_load_error,
                    Toast.LENGTH_SHORT
            ).show();

            finish();
            return;
        }

        secureVaultCoordinator.getSecureNote(
                secureNoteId,
                new VaultDataService.ResultCallback<SecureNote>() {

                    @Override
                    public void onSuccess(
                            SecureNote note
                    ) {

                        if (note == null) {

                            Toast.makeText(
                                    AddSecureNoteActivity.this,
                                    R.string.secure_note_load_error,
                                    Toast.LENGTH_SHORT
                            ).show();

                            finish();
                            return;
                        }

                        loadedSecureNote =
                                note;

                        editSecureNoteTitle.setText(
                                note.getTitle()
                        );

                        editSecureNoteContent.setText(
                                note.getContent()
                        );
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        Toast.makeText(
                                AddSecureNoteActivity.this,
                                R.string.secure_note_load_error,
                                Toast.LENGTH_SHORT
                        ).show();

                        finish();
                    }
                }
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

        if (editMode) {

            if (loadedSecureNote == null) {

                Toast.makeText(
                        this,
                        R.string.secure_note_load_error,
                        Toast.LENGTH_SHORT
                ).show();

                return;
            }

            loadedSecureNote.setTitle(
                    title
            );

            loadedSecureNote.setContent(
                    content
            );

            secureVaultCoordinator.updateSecureNote(
                    loadedSecureNote,
                    new VaultDataService.ResultCallback<Integer>() {

                        @Override
                        public void onSuccess(
                                Integer rows
                        ) {

                            if (rows == null || rows <= 0) {
                                showSaveError();
                                return;
                            }

                            finish();
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {
                            showSaveError();
                        }
                    }
            );

            return;
        }

        SecureNote secureNote =
                new SecureNote(
                        title,
                        content
                );

        secureVaultCoordinator.addSecureNote(
                secureNote,
                new VaultDataService.ResultCallback<Long>() {

                    @Override
                    public void onSuccess(
                            Long id
                    ) {

                        if (id == null || id <= 0L) {
                            showSaveError();
                            return;
                        }

                        finish();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {
                        showSaveError();
                    }
                }
        );
    }

    private void showSaveError() {

        Toast.makeText(
                this,
                R.string.secure_note_save_error,
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
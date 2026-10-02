package com.safekey.app.vault;

import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;
import android.content.Intent;

import androidx.appcompat.app.AppCompatActivity;
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

public class SecureNoteDetailsActivity extends AppCompatActivity {

    private long secureNoteId = 0L;
    private SecureVaultCoordinator secureVaultCoordinator;
    public static final String EXTRA_ID =
            "secure_note_id";
    public static final String EXTRA_TITLE =
            "secure_note_title";

    public static final String EXTRA_CONTENT =
            "secure_note_content";

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
                R.layout.activity_secure_note_details
        );

        secureVaultCoordinator =
                ((SafeKeyApplication) getApplication())
                        .getSecureVaultCoordinator();

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(
                        R.id.rootSecureNoteDetails
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

        bindData();
        setupActions();
    }

    private void bindData() {

        TextView textTitle =
                findViewById(
                        R.id.textSecureNoteDetailsTitle
                );

        TextView textContent =
                findViewById(
                        R.id.textSecureNoteDetailsContent
                );

        secureNoteId =
                getIntent().getLongExtra(
                        EXTRA_ID,
                        0L
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
                                    SecureNoteDetailsActivity.this,
                                    R.string.secure_note_load_error,
                                    Toast.LENGTH_SHORT
                            ).show();

                            finish();
                            return;
                        }

                        String title =
                                note.getTitle();

                        String content =
                                note.getContent();

                        if (title == null
                                || title.trim().isEmpty()) {

                            textTitle.setText(
                                    R.string.secure_note_details_title
                            );

                        } else {

                            textTitle.setText(
                                    title
                            );
                        }

                        if (content == null
                                || content.trim().isEmpty()) {

                            textContent.setText(
                                    R.string.secure_note_details_not_provided
                            );

                        } else {

                            textContent.setText(
                                    content
                            );
                        }
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        Toast.makeText(
                                SecureNoteDetailsActivity.this,
                                R.string.secure_note_load_error,
                                Toast.LENGTH_SHORT
                        ).show();

                        finish();
                    }
                }
        );
    }

    private void setupActions() {

        TextView buttonBack =
                findViewById(
                        R.id.buttonBackSecureNoteDetails
                );

        TextView buttonEdit =
                findViewById(
                        R.id.buttonEditSecureNote
                );

        TextView buttonDelete =
                findViewById(
                        R.id.buttonDeleteSecureNote
                );

        buttonBack.setOnClickListener(
                view ->
                        finish()
        );

        buttonEdit.setOnClickListener(
                view ->
                        openEditSecureNoteScreen()
        );

        buttonDelete.setOnClickListener(
                view ->
                        Toast.makeText(
                                this,
                                R.string.secure_note_details_delete_pending,
                                Toast.LENGTH_SHORT
                        ).show()
        );
    }

    private void openEditSecureNoteScreen() {

        Intent intent =
                new Intent(
                        SecureNoteDetailsActivity.this,
                        AddSecureNoteActivity.class
                );

        intent.putExtra(
                AddSecureNoteActivity.EXTRA_EDIT_MODE,
                true
        );

        intent.putExtra(
                AddSecureNoteActivity.EXTRA_ID,
                secureNoteId
        );

        startActivity(
                intent
        );
    }
}
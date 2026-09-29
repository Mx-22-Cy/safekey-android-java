package com.safekey.app.vault;

import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import com.safekey.app.session.ProtectedActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;

public class SecureNoteDetailsActivity extends ProtectedActivity {

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

        String title =
                getIntent().getStringExtra(
                        EXTRA_TITLE
                );

        String content =
                getIntent().getStringExtra(
                        EXTRA_CONTENT
                );

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
                        Toast.makeText(
                                this,
                                R.string.secure_note_details_edit_pending,
                                Toast.LENGTH_SHORT
                        ).show()
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
}

package com.safekey.app.vault;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.appcompat.widget.AppCompatImageButton;

import com.safekey.app.R;

public class AddCredentialActivity extends AppCompatActivity {

    private AppCompatEditText editCredentialName;
    private AppCompatEditText editCredentialUsername;
    private AppCompatEditText editCredentialPassword;
    private AppCompatEditText editCredentialWebsite;
    private AppCompatEditText editCredentialCategory;
    private AppCompatEditText editCredentialNotes;

    private AppCompatImageButton buttonToggleCredentialPassword;

    private boolean passwordVisible = false;
    private boolean editMode = false;

    public static final String EXTRA_EDIT_MODE =
            "edit_mode";

    public static final String EXTRA_NAME =
            "edit_credential_name";

    public static final String EXTRA_USERNAME =
            "edit_credential_username";

    public static final String EXTRA_PASSWORD =
            "edit_credential_password";

    public static final String EXTRA_WEBSITE =
            "edit_credential_website";

    public static final String EXTRA_CATEGORY =
            "edit_credential_category";

    public static final String EXTRA_NOTES =
            "edit_credential_notes";

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
                R.layout.activity_add_credential
        );

        View rootAddCredential =
                findViewById(
                        R.id.rootAddCredential
                );

        ViewCompat.setOnApplyWindowInsetsListener(
                rootAddCredential,
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

        ViewCompat.requestApplyInsets(
                rootAddCredential
        );

        bindViews();
        loadEditData();
        setupActions();
    }

    private void bindViews() {

        editCredentialName =
                findViewById(
                        R.id.editCredentialName
                );

        editCredentialUsername =
                findViewById(
                        R.id.editCredentialUsername
                );

        editCredentialPassword =
                findViewById(
                        R.id.editCredentialPassword
                );

        buttonToggleCredentialPassword =
                findViewById(
                        R.id.buttonToggleCredentialPassword
                );

        editCredentialWebsite =
                findViewById(
                        R.id.editCredentialWebsite
                );

        editCredentialCategory =
                findViewById(
                        R.id.editCredentialCategory
                );

        editCredentialNotes =
                findViewById(
                        R.id.editCredentialNotes
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

        TextView textTitle =
                findViewById(
                        R.id.textAddCredentialTitle
                );

        TextView textSubtitle =
                findViewById(
                        R.id.textAddCredentialSubtitle
                );

        TextView buttonSave =
                findViewById(
                        R.id.buttonSaveCredential
                );

        textTitle.setText(
                R.string.edit_credential_title
        );

        textSubtitle.setText(
                R.string.edit_credential_subtitle
        );

        buttonSave.setText(
                R.string.edit_credential_save
        );

        editCredentialName.setText(
                getIntent().getStringExtra(
                        EXTRA_NAME
                )
        );

        editCredentialUsername.setText(
                getIntent().getStringExtra(
                        EXTRA_USERNAME
                )
        );

        editCredentialPassword.setText(
                getIntent().getStringExtra(
                        EXTRA_PASSWORD
                )
        );

        editCredentialWebsite.setText(
                getIntent().getStringExtra(
                        EXTRA_WEBSITE
                )
        );

        editCredentialCategory.setText(
                getIntent().getStringExtra(
                        EXTRA_CATEGORY
                )
        );

        editCredentialNotes.setText(
                getIntent().getStringExtra(
                        EXTRA_NOTES
                )
        );
    }

    private void setupActions() {

        TextView buttonCancel =
                findViewById(
                        R.id.buttonCancelAddCredential
                );

        TextView buttonSave =
                findViewById(
                        R.id.buttonSaveCredential
                );

        buttonCancel.setOnClickListener(
                view ->
                        finish()
        );

        buttonSave.setOnClickListener(
                view ->
                        validateAndContinue()
        );

        buttonToggleCredentialPassword.setOnClickListener(
                view ->
                        togglePasswordVisibility()
        );
    }

    private void togglePasswordVisibility() {

        passwordVisible =
                !passwordVisible;

        if (passwordVisible) {

            editCredentialPassword.setTransformationMethod(
                    HideReturnsTransformationMethod.getInstance()
            );

            buttonToggleCredentialPassword.setImageResource(
                    R.drawable.ic_password_hidden
            );

            buttonToggleCredentialPassword.setContentDescription(
                    getString(
                            R.string.hide_password_content_description
                    )
            );

        } else {

            editCredentialPassword.setTransformationMethod(
                    PasswordTransformationMethod.getInstance()
            );

            buttonToggleCredentialPassword.setImageResource(
                    R.drawable.ic_password_visible
            );

            buttonToggleCredentialPassword.setContentDescription(
                    getString(
                            R.string.show_password_content_description
                    )
            );
        }

        editCredentialPassword.setSelection(
                editCredentialPassword.length()
        );
    }

    private void validateAndContinue() {

        clearErrors();

        String name =
                readText(
                        editCredentialName
                );

        String username =
                readText(
                        editCredentialUsername
                );

        String password =
                readText(
                        editCredentialPassword
                );

        boolean valid =
                true;

        if (name.isEmpty()) {

            editCredentialName.setError(
                    getString(
                            R.string.add_credential_error_name_required
                    )
            );

            valid =
                    false;
        }

        if (username.isEmpty()) {

            editCredentialUsername.setError(
                    getString(
                            R.string.add_credential_error_username_required
                    )
            );

            valid =
                    false;
        }

        if (password.isEmpty()) {

            editCredentialPassword.setError(
                    getString(
                            R.string.add_credential_error_password_required
                    )
            );

            valid =
                    false;
        }

        if (!valid) {
            return;
        }

        /*
         * UI validation is complete.
         *
         * Do not persist the plaintext password here.
         * Real saving will be connected through the
         * approved encrypted VaultDataService flow.
         */
        int messageResource =
                editMode
                        ? R.string.edit_credential_save_pending
                        : R.string.add_credential_save_pending;

        Toast.makeText(
                this,
                messageResource,
                Toast.LENGTH_SHORT
        ).show();
    }

    private void clearErrors() {

        editCredentialName.setError(
                null
        );

        editCredentialUsername.setError(
                null
        );

        editCredentialPassword.setError(
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
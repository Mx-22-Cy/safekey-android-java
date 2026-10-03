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
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;

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
    private long credentialId = 0L;
    private SecureVaultCoordinator secureVaultCoordinator;
    private Credential loadedCredential;

    public static final String EXTRA_EDIT_MODE =
            "edit_mode";

    public static final String EXTRA_ID =
            "edit_credential_id";

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

        secureVaultCoordinator =
                ((SafeKeyApplication) getApplication())
                        .getSecureVaultCoordinator();

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

        credentialId =
                getIntent().getLongExtra(
                        EXTRA_ID,
                        0L
                );

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

        if (credentialId <= 0L) {

            Toast.makeText(
                    this,
                    R.string.credential_load_error,
                    Toast.LENGTH_SHORT
            ).show();

            finish();
            return;
        }

        secureVaultCoordinator.getCredential(
                credentialId,
                new VaultDataService.ResultCallback<Credential>() {

                    @Override
                    public void onSuccess(
                            Credential credential
                    ) {

                        if (credential == null) {

                            Toast.makeText(
                                    AddCredentialActivity.this,
                                    R.string.credential_load_error,
                                    Toast.LENGTH_SHORT
                            ).show();

                            finish();
                            return;
                        }

                        loadedCredential =
                                credential;

                        editCredentialName.setText(
                                credential.getTitle()
                        );

                        editCredentialUsername.setText(
                                credential.getUsername()
                        );

                        editCredentialPassword.setText(
                                credential.getPassword()
                        );

                        editCredentialWebsite.setText(
                                credential.getWebsite()
                        );

                        editCredentialCategory.setText(
                                credential.getCategory()
                        );

                        editCredentialNotes.setText(
                                credential.getNotes()
                        );
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        Toast.makeText(
                                AddCredentialActivity.this,
                                R.string.credential_load_error,
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

        String website =
                readText(
                        editCredentialWebsite
                );

        String category =
                readText(
                        editCredentialCategory
                );

        String notes =
                readText(
                        editCredentialNotes
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

        if (editMode) {

            if (loadedCredential == null) {

                Toast.makeText(
                        this,
                        R.string.credential_load_error,
                        Toast.LENGTH_SHORT
                ).show();

                return;
            }

            loadedCredential.setTitle(
                    name
            );

            loadedCredential.setUsername(
                    username
            );

            loadedCredential.setPassword(
                    password
            );

            loadedCredential.setWebsite(
                    website
            );

            loadedCredential.setCategory(
                    category
            );

            loadedCredential.setNotes(
                    notes
            );

            secureVaultCoordinator.updateCredential(
                    loadedCredential,
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

        Credential credential =
                new Credential(
                        name,
                        username,
                        password,
                        website,
                        category,
                        notes
                );

        secureVaultCoordinator.addCredential(
                credential,
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
                R.string.credential_save_error,
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
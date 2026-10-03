package com.safekey.app.vault;

import android.content.Intent;
import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.widget.TextView;
import android.widget.Toast;

import com.safekey.app.session.ProtectedActivity;
import androidx.appcompat.widget.AppCompatImageButton;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.appcompat.app.AlertDialog;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;

public class CredentialDetailsActivity extends ProtectedActivity {

    public static final String EXTRA_ID =
            "credential_id";

    public static final String EXTRA_NAME =
            "credential_name";

    public static final String EXTRA_USERNAME =
            "credential_username";

    public static final String EXTRA_PASSWORD =
            "credential_password";

    public static final String EXTRA_WEBSITE =
            "credential_website";

    public static final String EXTRA_CATEGORY =
            "credential_category";

    public static final String EXTRA_NOTES =
            "credential_notes";

    private TextView textPassword;
    private AppCompatImageButton buttonTogglePassword;

    private boolean passwordVisible = false;
    private long credentialId = 0L;
    private SecureVaultCoordinator secureVaultCoordinator;

    @Override
    protected void onCreate(
            Bundle savedInstanceState
    ) {

        super.onCreate(savedInstanceState);

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
                R.layout.activity_credential_details
        );

        secureVaultCoordinator =
                ((SafeKeyApplication) getApplication())
                        .getSecureVaultCoordinator();

        credentialId =
                getIntent().getLongExtra(
                        EXTRA_ID,
                        0L
                );

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(
                        R.id.rootCredentialDetails
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

    @Override
    protected void onRestart() {

        super.onRestart();

        bindData();
    }

    private void bindData() {

        TextView textName =
                findViewById(
                        R.id.textCredentialDetailsName
                );

        TextView textDomain =
                findViewById(
                        R.id.textCredentialDetailsDomain
                );

        TextView textUsername =
                findViewById(
                        R.id.textCredentialDetailsUsername
                );

        textPassword =
                findViewById(
                        R.id.textCredentialDetailsPassword
                );

        TextView textWebsite =
                findViewById(
                        R.id.textCredentialDetailsWebsite
                );

        TextView textCategory =
                findViewById(
                        R.id.textCredentialDetailsCategory
                );

        TextView textNotes =
                findViewById(
                        R.id.textCredentialDetailsNotes
                );

        TextView textLogo =
                findViewById(
                        R.id.textCredentialDetailsLogo
                );

        buttonTogglePassword =
                findViewById(
                        R.id.buttonToggleDetailsPassword
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
                                    CredentialDetailsActivity.this,
                                    R.string.credential_load_error,
                                    Toast.LENGTH_SHORT
                            ).show();

                            finish();
                            return;
                        }

                        String name =
                                credential.getTitle();

                        String username =
                                credential.getUsername();

                        String password =
                                credential.getPassword();

                        String website =
                                credential.getWebsite();

                        String category =
                                credential.getCategory();

                        String notes =
                                credential.getNotes();

                        if (name != null
                                && !name.trim().isEmpty()) {

                            textLogo.setText(
                                    name.trim()
                                            .substring(
                                                    0,
                                                    1
                                            )
                                            .toUpperCase(
                                                    java.util.Locale.ROOT
                                            )
                            );

                        } else {

                            textLogo.setText(
                                    "?"
                            );
                        }

                        textName.setText(
                                valueOrPlaceholder(
                                        name
                                )
                        );

                        textDomain.setText(
                                valueOrPlaceholder(
                                        website
                                )
                        );

                        textUsername.setText(
                                valueOrPlaceholder(
                                        username
                                )
                        );

                        passwordVisible =
                                false;

                        if (password == null
                                || password.trim().isEmpty()) {

                            textPassword.setText(
                                    R.string.credential_details_not_provided
                            );

                            textPassword.setTransformationMethod(
                                    null
                            );

                            buttonTogglePassword.setEnabled(
                                    false
                            );

                            buttonTogglePassword.setVisibility(
                                    android.view.View.GONE
                            );

                        } else {

                            textPassword.setText(
                                    password
                            );

                            textPassword.setTransformationMethod(
                                    PasswordTransformationMethod.getInstance()
                            );

                            buttonTogglePassword.setImageResource(
                                    R.drawable.ic_password_visible
                            );

                            buttonTogglePassword.setContentDescription(
                                    getString(
                                            R.string.show_password_content_description
                                    )
                            );

                            buttonTogglePassword.setEnabled(
                                    true
                            );

                            buttonTogglePassword.setVisibility(
                                    android.view.View.VISIBLE
                            );
                        }

                        textWebsite.setText(
                                valueOrPlaceholder(
                                        website
                                )
                        );

                        textCategory.setText(
                                valueOrPlaceholder(
                                        category
                                )
                        );

                        textNotes.setText(
                                valueOrPlaceholder(
                                        notes
                                )
                        );
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        Toast.makeText(
                                CredentialDetailsActivity.this,
                                R.string.credential_load_error,
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
                        R.id.buttonBackCredentialDetails
                );

        TextView buttonEdit =
                findViewById(
                        R.id.buttonEditCredential
                );

        TextView buttonDelete =
                findViewById(
                        R.id.buttonDeleteCredential
                );

        buttonBack.setOnClickListener(
                view ->
                        finish()
        );

        buttonTogglePassword.setOnClickListener(
                view ->
                        togglePasswordVisibility()
        );

        buttonEdit.setOnClickListener(
                view ->
                        openEditCredentialScreen()
        );

        buttonDelete.setOnClickListener(
                view ->
                        showDeleteConfirmation()
        );
    }

    private void showDeleteConfirmation() {

        new AlertDialog.Builder(
                this
        )
                .setTitle(
                        R.string.credential_delete_title
                )
                .setMessage(
                        R.string.credential_delete_message
                )
                .setNegativeButton(
                        R.string.credential_delete_cancel,
                        null
                )
                .setPositiveButton(
                        R.string.credential_delete_confirm,
                        (dialog, which) ->
                                deleteCredential()
                )
                .show();
    }

    private void deleteCredential() {

        secureVaultCoordinator.deleteCredential(
                credentialId,
                new VaultDataService.ResultCallback<Integer>() {

                    @Override
                    public void onSuccess(
                            Integer rows
                    ) {

                        if (rows == null || rows <= 0) {

                            Toast.makeText(
                                    CredentialDetailsActivity.this,
                                    R.string.credential_delete_error,
                                    Toast.LENGTH_SHORT
                            ).show();

                            return;
                        }

                        finish();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        Toast.makeText(
                                CredentialDetailsActivity.this,
                                R.string.credential_delete_error,
                                Toast.LENGTH_SHORT
                        ).show();
                    }
                }
        );
    }
    private void openEditCredentialScreen() {

        Intent intent =
                new Intent(
                        CredentialDetailsActivity.this,
                        AddCredentialActivity.class
                );

        intent.putExtra(
                AddCredentialActivity.EXTRA_EDIT_MODE,
                true
        );

        intent.putExtra(
                AddCredentialActivity.EXTRA_ID,
                credentialId
        );

        startActivity(
                intent
        );
    }
    private void togglePasswordVisibility() {

        passwordVisible =
                !passwordVisible;

        if (passwordVisible) {

            textPassword.setTransformationMethod(
                    HideReturnsTransformationMethod.getInstance()
            );

            buttonTogglePassword.setImageResource(
                    R.drawable.ic_password_hidden
            );

            buttonTogglePassword.setContentDescription(
                    getString(
                            R.string.hide_password_content_description
                    )
            );

        } else {

            textPassword.setTransformationMethod(
                    PasswordTransformationMethod.getInstance()
            );

            buttonTogglePassword.setImageResource(
                    R.drawable.ic_password_visible
            );

            buttonTogglePassword.setContentDescription(
                    getString(
                            R.string.show_password_content_description
                    )
            );
        }
    }

    private String valueOrPlaceholder(
            String value
    ) {

        if (value == null
                || value.trim().isEmpty()) {

            return getString(
                    R.string.credential_details_not_provided
            );
        }

        return value;
    }
}

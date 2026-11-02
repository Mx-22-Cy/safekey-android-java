package com.safekey.app.securityui;

import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.WindowManager;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.Button;
import android.widget.TextView;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.widget.AppCompatEditText;
import androidx.appcompat.widget.AppCompatImageButton;
import androidx.activity.OnBackPressedCallback;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.safekey.app.R;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordValidationResult;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.Arrays;

public final class SetupDecoyVaultActivity extends ProtectedActivity {

    private AppCompatEditText decoyPassword;
    private AppCompatEditText confirmDecoyPassword;

    private AppCompatImageButton toggleDecoyPassword;
    private AppCompatImageButton toggleConfirmDecoyPassword;

    private boolean decoyPasswordVisible;
    private boolean confirmPasswordVisible;
    private Button createDecoyButton;

    private TextView decoyPasswordError;
    private TextView confirmPasswordError;
    private TextView generalError;
    private boolean creationInProgress;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);

        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());

        WindowCompat.getInsetsController(
                getWindow(),
                getWindow().getDecorView()
        ).setAppearanceLightStatusBars(false);

        WindowCompat.getInsetsController(
                getWindow(),
                getWindow().getDecorView()
        ).setAppearanceLightNavigationBars(false);
        setContentView(R.layout.activity_setup_decoy_vault);
        View root = findViewById(R.id.rootSetupDecoyVault);

        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(
                    WindowInsetsCompat.Type.systemBars()
            );

            view.setPadding(
                    bars.left,
                    bars.top,
                    bars.right,
                    bars.bottom
            );

            return insets;
        });

        ViewCompat.requestApplyInsets(root);
        createDecoyButton = findViewById(R.id.buttonCreateDecoyVault);

        decoyPasswordError = findViewById(R.id.textDecoyPasswordError);
        confirmPasswordError = findViewById(R.id.textDecoyConfirmError);
        generalError = findViewById(R.id.textDecoyGeneralError);

        decoyPassword = findViewById(R.id.editDecoyPassword);
        confirmDecoyPassword = findViewById(R.id.editConfirmDecoyPassword);

        toggleDecoyPassword = findViewById(R.id.buttonToggleDecoyPassword);
        toggleConfirmDecoyPassword =
                findViewById(R.id.buttonToggleConfirmDecoyPassword);

        toggleDecoyPassword.setOnClickListener(view -> {
            decoyPasswordVisible = !decoyPasswordVisible;
            updateVisibility(decoyPassword, toggleDecoyPassword, decoyPasswordVisible);
        });

        toggleConfirmDecoyPassword.setOnClickListener(view -> {
            confirmPasswordVisible = !confirmPasswordVisible;
            updateVisibility(confirmDecoyPassword,
                    toggleConfirmDecoyPassword, confirmPasswordVisible);
        });

        findViewById(R.id.buttonDecoyBack)
                .setOnClickListener(view -> cancelSetupIfIdle());

        findViewById(R.id.buttonCancelDecoySetup)
                .setOnClickListener(view -> cancelSetupIfIdle());

        getOnBackPressedDispatcher().addCallback(
                this,
                new OnBackPressedCallback(true) {
                    @Override
                    public void handleOnBackPressed() {
                        cancelSetupIfIdle();
                    }
                }
        );

        TextWatcher passwordWatcher = new TextWatcher() {

            @Override
            public void beforeTextChanged(
                    CharSequence text,
                    int start,
                    int count,
                    int after
            ) {
            }

            @Override
            public void onTextChanged(
                    CharSequence text,
                    int start,
                    int before,
                    int count
            ) {
                updateCreateButtonState();
                clearValidationErrors();
            }

            @Override
            public void afterTextChanged(Editable text) {
            }
        };

        decoyPassword.addTextChangedListener(passwordWatcher);
        confirmDecoyPassword.addTextChangedListener(passwordWatcher);

        updateCreateButtonState();

        createDecoyButton.setOnClickListener(view -> validateDecoyPasswords());
    }

    private void updateVisibility(
            AppCompatEditText field,
            AppCompatImageButton toggle,
            boolean visible
    ) {
        field.setTransformationMethod(visible
                ? HideReturnsTransformationMethod.getInstance()
                : PasswordTransformationMethod.getInstance());

        toggle.setImageResource(visible
                ? R.drawable.ic_password_hidden
                : R.drawable.ic_password_visible);

        toggle.setContentDescription(getString(visible
                ? R.string.hide_password_content_description
                : R.string.show_password_content_description));

        field.setSelection(field.length());
    }
    private void updateCreateButtonState() {
        boolean hasPassword = decoyPassword.length() > 0;
        boolean hasConfirmation = confirmDecoyPassword.length() > 0;

        createDecoyButton.setEnabled(
                !creationInProgress && hasPassword && hasConfirmation
        );
    }

    private void setCreationInProgress(boolean inProgress) {
        creationInProgress = inProgress;

        decoyPassword.setEnabled(!inProgress);
        confirmDecoyPassword.setEnabled(!inProgress);

        toggleDecoyPassword.setEnabled(!inProgress);
        toggleConfirmDecoyPassword.setEnabled(!inProgress);

        findViewById(R.id.buttonDecoyBack).setEnabled(!inProgress);
        findViewById(R.id.buttonCancelDecoySetup).setEnabled(!inProgress);

        createDecoyButton.setText(inProgress
                ? R.string.t27_decoy_creating
                : R.string.t27_decoy_create);

        updateCreateButtonState();
    }

    private void clearValidationErrors() {
        decoyPasswordError.setVisibility(View.GONE);
        confirmPasswordError.setVisibility(View.GONE);
        generalError.setVisibility(View.GONE);
    }

    private void showPasswordError(int messageResId) {
        decoyPasswordError.setText(messageResId);
        decoyPasswordError.setVisibility(android.view.View.VISIBLE);
    }

    private void showConfirmationError(int messageResId) {
        confirmPasswordError.setText(messageResId);
        confirmPasswordError.setVisibility(android.view.View.VISIBLE);
    }

    private void showGeneralError(int messageResId) {
        generalError.setText(messageResId);
        generalError.setVisibility(View.VISIBLE);
    }

    private boolean isSessionStillUnlocked() {
        return SafeKeySession.getState() == SessionState.UNLOCKED
                && !isFinishing()
                && !isDestroyed();
    }

    private void clearSensitiveInputs() {
        if (decoyPassword != null && decoyPassword.getText() != null) {
            decoyPassword.getText().clear();
        }

        if (confirmDecoyPassword != null
                && confirmDecoyPassword.getText() != null) {
            confirmDecoyPassword.getText().clear();
        }
    }

    private void cancelSetupIfIdle() {
        if (!creationInProgress) {
            clearSensitiveInputs();
            finish();
        }
    }

    @Override
    protected void onRuntimeStop() {
        clearSensitiveInputs();
        super.onRuntimeStop();
    }

    @Override
    protected void onRuntimeDestroy() {
        clearSensitiveInputs();
        super.onRuntimeDestroy();
    }

    private void validateDecoyPasswords() {
        clearValidationErrors();

        char[] password = new char[decoyPassword.length()];
        char[] confirmation = new char[confirmDecoyPassword.length()];

        try {
            decoyPassword.getText().getChars(
                    0, password.length, password, 0
            );

            confirmDecoyPassword.getText().getChars(
                    0, confirmation.length, confirmation, 0
            );

            MasterPasswordValidationResult result =
                    MasterPasswordPolicy.validateForEnrollment(
                            password,
                            confirmation
                    );

            switch (result) {
                case REQUIRED:
                    showPasswordError(R.string.t27_decoy_password_required);
                    return;

                case TOO_SHORT:
                    showPasswordError(R.string.t27_password_min_length);
                    return;

                case TOO_LONG:
                    showPasswordError(R.string.t27_decoy_password_too_long);
                    return;

                case EASILY_GUESSED:
                    showPasswordError(R.string.t27_decoy_password_weak);
                    return;

                case CONFIRMATION_REQUIRED:
                    showConfirmationError(R.string.t27_decoy_confirm_required);
                    return;

                case PASSWORDS_DO_NOT_MATCH:
                    showConfirmationError(R.string.t27_passwords_mismatch);
                    return;

                case VALID:
                    createDecoyVault(password);
                    return;

                default:
                    showPasswordError(R.string.t27_decoy_creation_failed);
            }

        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    private void createDecoyVault(char[] password) {
        if (creationInProgress) {
            return;
        }

        final DecoyVaultCoordinator coordinator;

        try {
            SafeKeyApplication application =
                    (SafeKeyApplication) getApplication();

            coordinator = application.getDecoyVaultCoordinator();

            if (coordinator.hasDecoyVault()) {
                showGeneralError(R.string.t27_decoy_already_exists);
                return;
            }

            setCreationInProgress(true);

            coordinator.createDecoyVault(
                    password,
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            // Enrollment opens the Decoy Vault.
                            // Close it before reporting success.
                            closeCreatedDecoyVault(coordinator);
                        }

                        @Override
                        public void onError(Exception exception) {
                            if (!isFinishing() && !isDestroyed()) {
                                setCreationInProgress(false);
                                showGeneralError(
                                        R.string.t27_decoy_creation_failed
                                );
                            }
                        }
                    }
            );

        } catch (RuntimeException exception) {
            if (!isFinishing() && !isDestroyed()) {
                setCreationInProgress(false);
                showGeneralError(R.string.t27_decoy_creation_failed);
            }
        }
    }

    private void closeCreatedDecoyVault(
            DecoyVaultCoordinator coordinator
    ) {
        try {
            coordinator.closeDecoyVault(
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            if (!isSessionStillUnlocked()) {
                                return;
                            }

                            clearSensitiveInputs();

                            Toast.makeText(
                                    getApplicationContext(),
                                    R.string.t27_decoy_success,
                                    Toast.LENGTH_SHORT
                            ).show();

                            finish();
                        }

                        @Override
                        public void onError(Exception exception) {
                            if (isSessionStillUnlocked()) {
                                // Keep the form locked because the Decoy Vault
                                // may still be open after a failed close.
                                showGeneralError(R.string.t27_decoy_creation_failed);
                            }
                        }
                    }
            );
        } catch (RuntimeException exception) {
            if (isSessionStillUnlocked()) {
                // Do not permit another enrollment attempt
                // when closing the Decoy Vault failed.
                showGeneralError(R.string.t27_decoy_creation_failed);
            }
        }
    }
}
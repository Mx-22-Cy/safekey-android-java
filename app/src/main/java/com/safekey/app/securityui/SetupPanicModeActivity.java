package com.safekey.app.securityui;

import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.WindowManager;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.Button;
import android.widget.CheckBox;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import android.content.Intent;

import androidx.appcompat.widget.AppCompatEditText;
import androidx.appcompat.widget.AppCompatImageButton;
import androidx.activity.OnBackPressedCallback;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.safekey.app.R;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.security.panic.PanicPasswordPolicy;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.security.panic.PanicBackend;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.auth.SignInActivity;

import java.util.Arrays;

public final class SetupPanicModeActivity extends ProtectedActivity {

    private AppCompatEditText masterPassword;
    private AppCompatEditText decoyPassword;
    private AppCompatEditText newPanicPassword;
    private AppCompatEditText confirmPanicPassword;
    private CheckBox panicConfirmation;
    private Button enablePanicButton;
    private TextView panicFormError;
    private boolean enrollmentInProgress;

    private volatile PanicBackend.EnrollmentRequest enrollmentRequest;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);

        getWindow().addFlags(
                WindowManager.LayoutParams.FLAG_SECURE
        );

        WindowCompat.enableEdgeToEdge(getWindow());

        WindowCompat.getInsetsController(
                getWindow(),
                getWindow().getDecorView()
        ).setAppearanceLightStatusBars(false);

        WindowCompat.getInsetsController(
                getWindow(),
                getWindow().getDecorView()
        ).setAppearanceLightNavigationBars(false);

        setContentView(R.layout.activity_setup_panic_mode);

        View root = findViewById(R.id.rootSetupPanicMode);

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

        masterPassword = findViewById(R.id.editPanicMasterPassword);
        decoyPassword = findViewById(R.id.editPanicDecoyPassword);
        newPanicPassword = findViewById(R.id.editPanicNewPassword);
        confirmPanicPassword = findViewById(R.id.editPanicConfirmPassword);
        panicConfirmation = findViewById(R.id.checkPanicConfirmation);
        enablePanicButton = findViewById(R.id.buttonEnablePanic);
        panicFormError = findViewById(R.id.textPanicFormError);

        setupPasswordToggle(
                masterPassword,
                R.id.buttonTogglePanicMaster
        );

        setupPasswordToggle(
                decoyPassword,
                R.id.buttonTogglePanicDecoy
        );

        setupPasswordToggle(
                newPanicPassword,
                R.id.buttonTogglePanicNew
        );

        setupPasswordToggle(
                confirmPanicPassword,
                R.id.buttonTogglePanicConfirm
        );

        findViewById(R.id.buttonPanicBack)
                .setOnClickListener(view -> finish());

        findViewById(R.id.buttonCancelPanic)
                .setOnClickListener(view -> finish());

        TextWatcher passwordWatcher = new TextWatcher() {
            @Override
            public void beforeTextChanged(
                    CharSequence text, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(
                    CharSequence text, int start, int before, int count) {
                updateEnableButtonState();
            }

            @Override
            public void afterTextChanged(Editable text) {
            }
        };

        masterPassword.addTextChangedListener(passwordWatcher);
        decoyPassword.addTextChangedListener(passwordWatcher);
        newPanicPassword.addTextChangedListener(passwordWatcher);
        confirmPanicPassword.addTextChangedListener(passwordWatcher);

        panicConfirmation.setOnCheckedChangeListener(
                (buttonView, isChecked) -> updateEnableButtonState()
        );

        updateEnableButtonState();

        enablePanicButton.setOnClickListener(
                view -> validatePanicPasswords()
        );

        getOnBackPressedDispatcher().addCallback(
                this,
                new OnBackPressedCallback(true) {
                    @Override
                    public void handleOnBackPressed() {
                        if (!enrollmentInProgress) {
                            clearSensitiveInputs();
                            finish();
                        }
                    }
                }
        );

        requireRealVaultSession();
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();

        requireRealVaultSession();
    }

    private void setupPasswordToggle(
            AppCompatEditText field,
            int buttonId
    ) {
        AppCompatImageButton button = findViewById(buttonId);

        button.setOnClickListener(view -> {
            boolean currentlyHidden =
                    field.getTransformationMethod()
                            instanceof PasswordTransformationMethod;

            boolean showPassword = currentlyHidden;

            field.setTransformationMethod(showPassword
                    ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());

            button.setImageResource(showPassword
                    ? R.drawable.ic_password_hidden
                    : R.drawable.ic_password_visible);

            button.setContentDescription(getString(showPassword
                    ? R.string.hide_password_content_description
                    : R.string.show_password_content_description));

            field.setSelection(field.length());
        });
    }

    private void updateEnableButtonState() {
        boolean allFieldsFilled =
                masterPassword.length() > 0
                        && decoyPassword.length() > 0
                        && newPanicPassword.length() > 0
                        && confirmPanicPassword.length() > 0;

        enablePanicButton.setEnabled(
                !enrollmentInProgress
                        && allFieldsFilled
                        && panicConfirmation.isChecked()
        );
    }

    private void showPanicError(int messageResId) {
        panicFormError.setText(messageResId);
        panicFormError.setVisibility(View.VISIBLE);
    }

    private void clearPanicError() {
        panicFormError.setVisibility(View.GONE);
    }

    private static char[] readPassword(AppCompatEditText field) {
        char[] value = new char[field.length()];

        field.getText().getChars(
                0,
                value.length,
                value,
                0
        );

        return value;
    }

    private void validatePanicPasswords() {
        if (!requireRealVaultSession()) {
            return;
        }

        clearPanicError();

        char[] master = readPassword(masterPassword);
        char[] decoy = readPassword(decoyPassword);
        char[] panic = readPassword(newPanicPassword);
        char[] confirmation = readPassword(confirmPanicPassword);

        try {
            PanicPasswordPolicy.Result result =
                    PanicPasswordPolicy.validate(
                            master,
                            decoy,
                            panic,
                            confirmation
                    );

            switch (result) {
                case MASTER_REQUIRED:
                    showPanicError(R.string.t27_panic_master_required);
                    return;

                case DECOY_REQUIRED:
                    showPanicError(R.string.t27_panic_decoy_required);
                    return;

                case INVALID_PANIC_PASSWORD:
                    showPanicError(R.string.t27_panic_password_invalid);
                    return;

                case CONFIRMATION_MISMATCH:
                    showPanicError(R.string.t27_panic_passwords_mismatch);
                    return;

                case PASSWORDS_MUST_DIFFER:
                    showPanicError(R.string.t27_panic_passwords_must_differ);
                    return;

                case VALID:
                    startPanicEnrollment(
                            master,
                            decoy,
                            panic,
                            confirmation
                    );
                    return;

                default:
                    showPanicError(R.string.t27_panic_enrollment_failed);
            }

        } finally {
            Arrays.fill(master, '\0');
            Arrays.fill(decoy, '\0');
            Arrays.fill(panic, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    private boolean isAuthorizedRealSession() {
        SafeKeyApplication application =
                (SafeKeyApplication) getApplication();

        return SafeKeySession.getState() == SessionState.UNLOCKED
                && application.getActiveVault()
                == SafeKeyApplication.ActiveVault.REAL
                && !isFinishing()
                && !isDestroyed();
    }

    private boolean requireRealVaultSession() {
        if (isAuthorizedRealSession()) {
            return true;
        }

        PanicBackend.EnrollmentRequest request = enrollmentRequest;
        enrollmentRequest = null;

        if (request != null) {
            request.close();
        }

        clearSensitiveInputs();

        if (SafeKeySession.getState() == SessionState.LOCKED
                && !isFinishing()
                && !isDestroyed()) {

            Intent intent = new Intent(this, SignInActivity.class);

            intent.addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK
                            | Intent.FLAG_ACTIVITY_CLEAR_TASK
            );

            startActivity(intent);
        }

        finish();
        return false;
    }

    private void clearSensitiveInputs() {
        if (masterPassword != null && masterPassword.getText() != null) {
            masterPassword.getText().clear();
        }

        if (decoyPassword != null && decoyPassword.getText() != null) {
            decoyPassword.getText().clear();
        }

        if (newPanicPassword != null && newPanicPassword.getText() != null) {
            newPanicPassword.getText().clear();
        }

        if (confirmPanicPassword != null
                && confirmPanicPassword.getText() != null) {
            confirmPanicPassword.getText().clear();
        }
    }

    @Override
    protected void onRuntimeStop() {
        PanicBackend.EnrollmentRequest request = enrollmentRequest;

        enrollmentRequest = null;

        if (request != null) {
            request.close();
        }

        clearSensitiveInputs();

        if (panicConfirmation != null) {
            panicConfirmation.setChecked(false);
        }

        setEnrollmentInProgress(false);

        super.onRuntimeStop();
    }

    @Override
    protected void onRuntimeDestroy() {
        PanicBackend.EnrollmentRequest request = enrollmentRequest;

        if (request != null) {
            request.close();
        }

        clearSensitiveInputs();

        super.onRuntimeDestroy();
    }

    private void setEnrollmentInProgress(boolean inProgress) {
        enrollmentInProgress = inProgress;

        masterPassword.setEnabled(!inProgress);
        decoyPassword.setEnabled(!inProgress);
        newPanicPassword.setEnabled(!inProgress);
        confirmPanicPassword.setEnabled(!inProgress);

        panicConfirmation.setEnabled(!inProgress);

        findViewById(R.id.buttonTogglePanicMaster).setEnabled(!inProgress);
        findViewById(R.id.buttonTogglePanicDecoy).setEnabled(!inProgress);
        findViewById(R.id.buttonTogglePanicNew).setEnabled(!inProgress);
        findViewById(R.id.buttonTogglePanicConfirm).setEnabled(!inProgress);

        findViewById(R.id.buttonPanicBack).setEnabled(!inProgress);
        findViewById(R.id.buttonCancelPanic).setEnabled(!inProgress);

        enablePanicButton.setText(inProgress
                ? R.string.t27_panic_enabling
                : R.string.t27_panic_enable);

        updateEnableButtonState();
    }

    private void startPanicEnrollment(
            char[] master,
            char[] decoy,
            char[] panic,
            char[] confirmation
    ) {
        if (enrollmentInProgress
                || !isAuthorizedRealSession()
                || !panicConfirmation.isChecked()) {
            return;
        }

        final PanicBackend.EnrollmentRequest request;

        try {
            SafeKeyApplication application =
                    (SafeKeyApplication) getApplication();

            PanicBackend backend = application.getPanicBackend();

            request = backend.prepareEnrollment(
                    master,
                    decoy,
                    panic,
                    confirmation,
                    panicConfirmation.isChecked()
            );

        } catch (RuntimeException exception) {
            if (isAuthorizedRealSession()) {
                showPanicError(R.string.t27_panic_enrollment_failed);
            }
            return;
        }

        enrollmentRequest = request;
        setEnrollmentInProgress(true);

        // The backend request now owns independent password copies.
        clearSensitiveInputs();

        Thread worker = new Thread(() -> {
            boolean succeeded = false;

            try {
                request.run();
                succeeded = true;
            } catch (Exception exception) {
                // Do not expose authentication or security details in the UI.
            } finally {
                request.close();
            }

            final boolean enrollmentSucceeded = succeeded;

            runOnUiThread(() -> {
                if (enrollmentRequest != request) {
                    return;
                }

                enrollmentRequest = null;

                if (!isAuthorizedRealSession()) {
                    return;
                }

                if (enrollmentSucceeded) {
                    clearSensitiveInputs();

                    Toast.makeText(
                            getApplicationContext(),
                            R.string.t27_panic_success,
                            Toast.LENGTH_SHORT
                    ).show();

                    finish();
                } else {
                    setEnrollmentInProgress(false);
                    showPanicError(R.string.t27_panic_enrollment_failed);
                }
            });

        }, "SafeKey-PanicEnrollment");

        try {
            worker.start();
        } catch (RuntimeException exception) {
            request.close();
            enrollmentRequest = null;

            if (isAuthorizedRealSession()) {
                setEnrollmentInProgress(false);
                showPanicError(R.string.t27_panic_enrollment_failed);
            }
        }
    }
}
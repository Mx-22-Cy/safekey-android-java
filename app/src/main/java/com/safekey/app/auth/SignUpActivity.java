package com.safekey.app.auth;

import com.safekey.app.security.panic.PanicRuntimeScope;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;
import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordScreening;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.session.SafeKeySession;

import java.util.Arrays;

public class SignUpActivity extends com.safekey.app.StartupGuardActivity {
    private PanicRuntimeScope.Registration panicCancellation;


    private Button buttonCreateVault;
    private Button buttonGoToSignIn;
    private MasterPasswordScreening.Request pendingCheck;
    private VaultUnlockFlow.Request pendingCreation;
    private AlertDialog offlineDialog;
    private char[] pendingPassword;
    private long enrollmentGeneration;
    private boolean resumed;
    private boolean busy;
    private boolean navigating;

    private EditText editMasterPassword;
    private EditText editConfirmPassword;
    private CheckBox checkShowPasswords;
    private TextView textValidationMessage;
    private TextView textPasswordStrength;

    private View strengthBar1;
    private View strengthBar2;
    private View strengthBar3;
    private View strengthBar4;
    private View strengthBar5;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        SafeKeySession.lock();

        if (new VaultKeyEnvelopeStore(this).hasEnvelope()) {
            Intent intent = new Intent(this, SignInActivity.class);

            intent.addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK
                            | Intent.FLAG_ACTIVITY_CLEAR_TASK
            );

            startActivity(intent);
            finish();
            return;
        }

        WindowCompat.enableEdgeToEdge(
                getWindow()
        );

        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.setAppearanceLightStatusBars(false);
        insetsController.setAppearanceLightNavigationBars(false);

        setContentView(
                R.layout.activity_sign_up
        );

        View rootSignUp =
                findViewById(
                        R.id.rootSignUp
                );

        ViewCompat.setOnApplyWindowInsetsListener(
                rootSignUp,
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
                rootSignUp
        );

        editMasterPassword =
                findViewById(
                        R.id.editMasterPassword
                );

        editConfirmPassword =
                findViewById(
                        R.id.editConfirmPassword
                );

        checkShowPasswords =
                findViewById(
                        R.id.checkShowPasswords
                );

        textValidationMessage =
                findViewById(
                        R.id.textValidationMessage
                );

        buttonCreateVault =
                findViewById(
                        R.id.buttonCreateVault
                );

        buttonGoToSignIn =
                findViewById(
                        R.id.buttonGoToSignIn
                );

        editMasterPassword.setSaveEnabled(false);
        editConfirmPassword.setSaveEnabled(false);

        checkShowPasswords.setOnCheckedChangeListener(
                (buttonView, isChecked) ->
                        setPasswordVisibility(
                                isChecked
                        )
        );

        strengthBar1 = findViewById(R.id.strengthBar1);
        strengthBar2 = findViewById(R.id.strengthBar2);
        strengthBar3 = findViewById(R.id.strengthBar3);
        strengthBar4 = findViewById(R.id.strengthBar4);
        strengthBar5 = findViewById(R.id.strengthBar5);

        textPasswordStrength =
                findViewById(
                        R.id.textPasswordStrength
                );

        editMasterPassword.addTextChangedListener(
                new TextWatcher() {

                    @Override
                    public void beforeTextChanged(
                            CharSequence s,
                            int start,
                            int count,
                            int after
                    ) {
                    }

                    @Override
                    public void onTextChanged(
                            CharSequence s,
                            int start,
                            int before,
                            int count
                    ) {
                        updatePasswordStrength(
                                s
                        );
                    }

                    @Override
                    public void afterTextChanged(
                            Editable s
                    ) {
                    }
                }
        );

        buttonCreateVault.setOnClickListener(
                view ->
                        validateSignUpForm()
        );

        buttonGoToSignIn.setOnClickListener(
                view -> {

                    Intent intent =
                            new Intent(
                                    SignUpActivity.this,
                                    SignInActivity.class
                            );

                    startActivity(intent);
                    finish();
                }
        );

        panicCancellation = com.safekey.app.security.panic.PanicSensitiveUi.bind(
                this, () -> { resumed = false; cancelEnrollment(); });
    }

    private void setPasswordVisibility(
            boolean visible
    ) {

        int masterPosition =
                editMasterPassword
                        .getSelectionStart();

        int confirmPosition =
                editConfirmPassword
                        .getSelectionStart();

        if (visible) {

            editMasterPassword
                    .setTransformationMethod(
                            HideReturnsTransformationMethod
                                    .getInstance()
                    );

            editConfirmPassword
                    .setTransformationMethod(
                            HideReturnsTransformationMethod
                                    .getInstance()
                    );

        } else {

            editMasterPassword
                    .setTransformationMethod(
                            PasswordTransformationMethod
                                    .getInstance()
                    );

            editConfirmPassword
                    .setTransformationMethod(
                            PasswordTransformationMethod
                                    .getInstance()
                    );
        }

        if (masterPosition >= 0) {

            editMasterPassword.setSelection(
                    Math.min(
                            masterPosition,
                            editMasterPassword.length()
                    )
            );
        }

        if (confirmPosition >= 0) {

            editConfirmPassword.setSelection(
                    Math.min(
                            confirmPosition,
                            editConfirmPassword.length()
                    )
            );
        }
    }

    private void updatePasswordStrength(
            CharSequence password
    ) {

        View[] bars = {
                strengthBar1,
                strengthBar2,
                strengthBar3,
                strengthBar4,
                strengthBar5
        };

        int inactiveColor =
                ContextCompat.getColor(
                        this,
                        R.color.auth_strength_inactive
                );

        for (View bar : bars) {
            bar.setBackgroundColor(
                    inactiveColor
            );
        }

        boolean hasLower = false;
        boolean hasUpper = false;
        boolean hasDigit = false;
        boolean hasSymbol = false;

        int characterCount = 0;

        for (
                int offset = 0;
                offset < password.length();
        ) {

            int codePoint =
                    Character.codePointAt(
                            password,
                            offset
                    );

            characterCount++;

            if (
                    codePoint >= 'a'
                            && codePoint <= 'z'
            ) {

                hasLower = true;

            } else if (
                    codePoint >= 'A'
                            && codePoint <= 'Z'
            ) {

                hasUpper = true;

            } else if (
                    codePoint >= '0'
                            && codePoint <= '9'
            ) {

                hasDigit = true;

            } else {

                hasSymbol = true;
            }

            offset +=
                    Character.charCount(
                            codePoint
                    );
        }

        int categories = 0;

        if (hasLower) {
            categories++;
        }

        if (hasUpper) {
            categories++;
        }

        if (hasDigit) {
            categories++;
        }

        if (hasSymbol) {
            categories++;
        }

        int strength;

        if (password.length() == 0) {

            strength = 0;

        } else if (
                isObviouslyRepetitive(
                        password
                )
        ) {

            strength = 1;

        } else if (categories == 1) {

            strength = 1;

        } else if (
                categories == 2
                        || categories == 3
        ) {

            strength = 3;

        } else if (
                categories == 4
                        && characterCount
                        >= MasterPasswordPolicy.MIN_LENGTH
        ) {

            strength = 5;

        } else {

            strength = 3;
        }

        int activeColor;

        if (strength <= 1) {

            activeColor =
                    ContextCompat.getColor(
                            this,
                            R.color.auth_strength_weak
                    );

        } else if (strength == 3) {

            activeColor =
                    ContextCompat.getColor(
                            this,
                            R.color.auth_strength_medium
                    );

        } else {

            activeColor =
                    ContextCompat.getColor(
                            this,
                            R.color.auth_strength_strong
                    );
        }

        if (strength == 0) {

            textPasswordStrength
                    .setVisibility(
                            View.GONE
                    );

        } else if (strength == 1) {

            textPasswordStrength.setText(
                    R.string.password_strength_weak
            );

            textPasswordStrength.setTextColor(
                    ContextCompat.getColor(
                            this,
                            R.color.auth_strength_weak
                    )
            );

            textPasswordStrength
                    .setVisibility(
                            View.VISIBLE
                    );

        } else if (strength == 3) {

            textPasswordStrength.setText(
                    R.string.password_strength_medium
            );

            textPasswordStrength.setTextColor(
                    ContextCompat.getColor(
                            this,
                            R.color.auth_strength_medium
                    )
            );

            textPasswordStrength
                    .setVisibility(
                            View.VISIBLE
                    );

        } else {

            textPasswordStrength.setText(
                    R.string.password_strength_strong
            );

            textPasswordStrength.setTextColor(
                    ContextCompat.getColor(
                            this,
                            R.color.auth_strength_strong
                    )
            );

            textPasswordStrength
                    .setVisibility(
                            View.VISIBLE
                    );
        }

        for (int i = 0; i < strength; i++) {

            bars[i].setBackgroundColor(
                    activeColor
            );
        }
    }

    private boolean isObviouslyRepetitive(
            CharSequence password
    ) {

        if (password.length() < 2) {
            return false;
        }

        // Advisory strength warning only.
        // Detect repeated characters or short repeated patterns
        // without creating immutable password Strings.
        for (
                int unitLength = 1;
                unitLength <= 4;
                unitLength++
        ) {

            if (
                    password.length()
                            % unitLength != 0
            ) {
                continue;
            }

            boolean repeated = true;

            for (
                    int i = unitLength;
                    i < password.length();
                    i++
            ) {

                if (
                        password.charAt(i)
                                != password.charAt(
                                i % unitLength
                        )
                ) {

                    repeated = false;
                    break;
                }
            }

            if (repeated) {
                return true;
            }
        }

        return false;
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        resumed = true;
        if (!navigating && !isFinishing() && new VaultKeyEnvelopeStore(this).hasEnvelope()) {
            startActivity(new Intent(this, SignInActivity.class));
            finish();
        }
    }

    @Override
    protected void onRuntimePause() {
        resumed = false;
        if (!navigating) { cancelEnrollment(); }
        super.onRuntimePause();
    }

    @Override
    protected void onRuntimeDestroy() {
        if (panicCancellation != null) { panicCancellation.close(); }

        cancelEnrollment();
        super.onRuntimeDestroy();
    }

    private void validateSignUpForm() {
        if (!resumed || busy) { return; }
        char[] password = read(editMasterPassword);
        char[] confirmation = read(editConfirmPassword);
        long token = ++enrollmentGeneration;
        pendingPassword = password;
        setEnrollmentBusy(true);
        textValidationMessage.setText(R.string.master_password_checking);
        try {
            pendingCheck = ((SafeKeyApplication) getApplication()).getMasterPasswordHealth()
                    .getScreening().checkNewPassword(password, confirmation,
                            result -> onScreened(token, result));
        } catch (RuntimeException error) {
            rejectEnrollment(getString(R.string.master_password_check_failed));
        } finally {
            Arrays.fill(confirmation, '\0');
        }
    }

    private void onScreened(long token, MasterPasswordScreening.Result result) {
        if (!isCurrentEnrollment(token)) { return; }
        switch (result.getOutcome()) {
            case LOCAL_REJECTION:
                rejectEnrollment(MasterPasswordMessages.validation(this, result.getValidation()));
                if (result.getValidation()
                        == com.safekey.app.auth.logic.MasterPasswordValidationResult.EASILY_GUESSED) {
                    editMasterPassword.setError(getString(R.string.error_password_easily_guessed));
                }
                break;
            case BREACHED:
                rejectEnrollment(getString(R.string.master_password_breached_rejected));
                editMasterPassword.setText("");
                editConfirmPassword.setText("");
                break;
            case CHECKED_ACCEPTABLE:
                createScreenedVault(token, MasterPasswordCheckStatus.CHECKED);
                break;
            case OFFLINE_CHOICE_REQUIRED:
                offlineDialog = new AlertDialog.Builder(this)
                        .setTitle(R.string.master_password_offline_title)
                        .setMessage(R.string.master_password_offline_message)
                        .setPositiveButton(R.string.master_password_continue_offline, (dialog, which) -> {
                            offlineDialog = null;
                            if (isCurrentEnrollment(token)) {
                                createScreenedVault(token, MasterPasswordCheckStatus.PENDING);
                            }
                        })
                        .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                            offlineDialog = null;
                            rejectEnrollment(getString(R.string.master_password_check_cancelled));
                        })
                        .setOnCancelListener(dialog -> {
                            offlineDialog = null;
                            rejectEnrollment(getString(R.string.master_password_check_cancelled));
                        }).create();
                offlineDialog.show();
                if (offlineDialog.getWindow() != null) {
                    offlineDialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                }
                break;
            default:
                rejectEnrollment(getString(R.string.master_password_check_failed));
        }
    }

    private void createScreenedVault(long token, MasterPasswordCheckStatus status) {
        if (!isCurrentEnrollment(token) || pendingPassword == null) { return; }
        textValidationMessage.setText(R.string.master_password_creating);
        try {
            pendingCreation = ((SafeKeyApplication) getApplication()).getSecureVaultCoordinator()
                    .createVaultForEnrollment(pendingPassword, status,
                            new VaultDataService.SimpleCallback() {
                                @Override public void onSuccess() {
                                    if (!isCurrentEnrollment(token) || pendingCreation == null) { return; }
                                    if (!pendingCreation.claimSession()) {
                                        rejectEnrollment(getString(R.string.signup_vault_creation_error));
                                        return;
                                    }
                                    pendingCreation = null;
                                    navigating = true;
                                    clearPendingPassword();
                                    editMasterPassword.setText("");
                                    editConfirmPassword.setText("");
                                    SafeKeySession.unlockAfterAuthentication();
                                    try {
                                        Intent intent = new Intent(SignUpActivity.this, HomeActivity.class);
                                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                                        startActivity(intent);
                                        finish();
                                    } catch (RuntimeException error) {
                                        navigating = false;
                                        SafeKeySession.lock();
                                        rejectEnrollment(getString(R.string.signup_vault_creation_error));
                                    }
                                }
                                @Override public void onError(Exception error) {
                                    if (isCurrentEnrollment(token)) {
                                        rejectEnrollment(getString(R.string.signup_vault_creation_error));
                                    }
                                }
                            });
        } catch (RuntimeException error) {
            rejectEnrollment(getString(R.string.signup_vault_creation_error));
        } finally {
            clearPendingPassword();
        }
    }

    private boolean isCurrentEnrollment(long token) {
        return token == enrollmentGeneration && resumed && !navigating
                && !isFinishing() && !isDestroyed();
    }

    private void rejectEnrollment(String message) {
        cancelEnrollment();
        textValidationMessage.setText(message);
        editMasterPassword.requestFocus();
    }

    private void cancelEnrollment() {
        enrollmentGeneration++;
        if (pendingCheck != null) { pendingCheck.close(); pendingCheck = null; }
        if (pendingCreation != null) { pendingCreation.close(); pendingCreation = null; }
        if (offlineDialog != null) { offlineDialog.dismiss(); offlineDialog = null; }
        clearPendingPassword();
        if (editMasterPassword != null && !resumed) {
            editMasterPassword.setText("");
            editConfirmPassword.setText("");
            checkShowPasswords.setChecked(false);
        }
        setEnrollmentBusy(false);
    }

    private void clearPendingPassword() {
        if (pendingPassword != null) {
            Arrays.fill(pendingPassword, '\0');
            pendingPassword = null;
        }
    }

    private void setEnrollmentBusy(boolean value) {
        busy = value;
        if (buttonCreateVault != null) {
            buttonCreateVault.setEnabled(!value);
            buttonGoToSignIn.setEnabled(!value);
            editMasterPassword.setEnabled(!value);
            editConfirmPassword.setEnabled(!value);
            checkShowPasswords.setEnabled(!value);
        }
    }

    private static char[] read(EditText field) {
        Editable text = field.getText();
        char[] result = new char[text == null ? 0 : text.length()];
        if (text != null) { text.getChars(0, text.length(), result, 0); }
        return result;
    }
}

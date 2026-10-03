package com.safekey.app.auth;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;
import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordValidationResult;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.session.SafeKeySession;

import java.util.Arrays;

public class SignUpActivity extends AppCompatActivity {

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
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

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

        Button buttonCreateVault =
                findViewById(
                        R.id.buttonCreateVault
                );

        Button buttonGoToSignIn =
                findViewById(
                        R.id.buttonGoToSignIn
                );

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

    private void validateSignUpForm() {

        Editable masterEditable =
                editMasterPassword.getText();

        Editable confirmEditable =
                editConfirmPassword.getText();

        char[] masterPasswordChars =
                new char[masterEditable.length()];

        char[] confirmPasswordChars =
                new char[confirmEditable.length()];

        masterEditable.getChars(
                0,
                masterEditable.length(),
                masterPasswordChars,
                0
        );

        confirmEditable.getChars(
                0,
                confirmEditable.length(),
                confirmPasswordChars,
                0
        );

        try {

            MasterPasswordValidationResult validationResult =
                    MasterPasswordPolicy
                            .validateForEnrollment(
                                    masterPasswordChars,
                                    confirmPasswordChars
                            );

            textValidationMessage.setText(null);

            switch (validationResult) {

                case REQUIRED:

                    editMasterPassword.setError(
                            getString(
                                    R.string.error_master_password_required
                            )
                    );

                    editMasterPassword.requestFocus();
                    return;

                case TOO_SHORT:

                    editMasterPassword.setError(
                            getResources().getQuantityString(
                                    R.plurals.error_password_too_short,
                                    MasterPasswordPolicy.MIN_LENGTH,
                                    MasterPasswordPolicy.MIN_LENGTH
                            )
                    );

                    editMasterPassword.requestFocus();
                    return;

                case TOO_LONG:

                    editMasterPassword.setError(
                            getResources().getQuantityString(
                                    R.plurals.error_password_too_long,
                                    MasterPasswordPolicy.MAX_LENGTH,
                                    MasterPasswordPolicy.MAX_LENGTH
                            )
                    );

                    editMasterPassword.requestFocus();
                    return;

                case CONFIRMATION_REQUIRED:

                    editConfirmPassword.setError(
                            getString(
                                    R.string.error_confirmation_required
                            )
                    );

                    editConfirmPassword.requestFocus();
                    return;

                case PASSWORDS_DO_NOT_MATCH:

                    editConfirmPassword.setError(
                            getString(
                                    R.string.error_passwords_do_not_match
                            )
                    );

                    editConfirmPassword.requestFocus();
                    return;

                case EASILY_GUESSED:

                    editMasterPassword.setError(
                            getString(
                                    R.string.error_password_easily_guessed
                            )
                    );

                    editMasterPassword.requestFocus();
                    return;

                case VALID:
                    break;
            }

            SecureVaultCoordinator secureVaultCoordinator =
                    ((SafeKeyApplication) getApplication())
                            .getSecureVaultCoordinator();

            secureVaultCoordinator.createVault(
                    masterPasswordChars,
                    new VaultDataService.SimpleCallback() {

                        @Override
                        public void onSuccess() {

                            SafeKeySession
                                    .getManager()
                                    .unlockAfterAuthentication();

                            editMasterPassword.setText("");
                            editConfirmPassword.setText("");

                            Intent intent =
                                    new Intent(
                                            SignUpActivity.this,
                                            HomeActivity.class
                                    );

                            intent.addFlags(
                                    Intent.FLAG_ACTIVITY_NEW_TASK
                                            | Intent.FLAG_ACTIVITY_CLEAR_TASK
                            );

                            startActivity(
                                    intent
                            );

                            finish();
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {

                            textValidationMessage.setText(
                                    R.string.signup_vault_creation_error
                            );
                        }
                    }
            );

        } finally {

            Arrays.fill(
                    masterPasswordChars,
                    '\0'
            );

            Arrays.fill(
                    confirmPasswordChars,
                    '\0'
            );
        }
    }
}
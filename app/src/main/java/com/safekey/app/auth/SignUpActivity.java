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
                                s.toString()
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
            String password
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

        boolean hasLower =
                password.matches(
                        ".*[a-z].*"
                );

        boolean hasUpper =
                password.matches(
                        ".*[A-Z].*"
                );

        boolean hasDigit =
                password.matches(
                        ".*\\d.*"
                );

        boolean hasSymbol =
                password.matches(
                        ".*[^A-Za-z0-9].*"
                );

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

        int characterCount =
                password.codePointCount(
                        0,
                        password.length()
                );

        int strength;

        if (password.isEmpty()) {

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
            String password
    ) {

        if (password.length() < 2) {
            return false;
        }

        // Advisory strength warning only.
        // Same character repeated:
        // aaaaaaaa, 11111111, @@@@@@@@
        if (password.matches(
                "^(.)\\1+$"
        )) {
            return true;
        }

        // Short pattern repeated:
        // 1a1a1a1a, abcabcabc, abcdabcd
        for (
                int unitLength = 2;
                unitLength <= 4;
                unitLength++
        ) {

            if (
                    password.length()
                            % unitLength != 0
            ) {
                continue;
            }

            String unit =
                    password.substring(
                            0,
                            unitLength
                    );

            boolean repeated = true;

            for (
                    int i = unitLength;
                    i < password.length();
                    i += unitLength
            ) {

                if (
                        !password.substring(
                                i,
                                i + unitLength
                        ).equals(unit)
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

            /*
             * TODO: Connect this screen to the remaining security and key-management logic later.
             *
             * Do not save or log the master password.
             * The master password should not be used directly as the
             * SQLCipher database password.
             *
             * Later, the security layer will:
             * - derive the required key using Argon2id;
             * - open/unlock the encrypted database;
             * - protect keys using Android Keystore;
             * - clear temporary sensitive values when possible.
             */

            textValidationMessage.setText(
                    R.string.signup_pending_integration
            );

            Toast.makeText(
                    this,
                    R.string.signup_pending_integration_toast,
                    Toast.LENGTH_LONG
            ).show();

            editMasterPassword.setText("");
            editConfirmPassword.setText("");

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
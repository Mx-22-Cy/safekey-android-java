package com.safekey.app.auth;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.text.TextUtils;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.R;
import android.view.View;
import android.text.Editable;
import android.text.TextWatcher;

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

        getWindow().setStatusBarColor(
                Color.parseColor("#050B15")
        );

        getWindow().setNavigationBarColor(
                Color.parseColor("#050B15")
        );

        setContentView(
                R.layout.activity_sign_up
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

        textPasswordStrength = findViewById(R.id.textPasswordStrength);

        editMasterPassword.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                updatePasswordStrength(s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });

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
    private void updatePasswordStrength(String password) {
        View[] bars = {
                strengthBar1,
                strengthBar2,
                strengthBar3,
                strengthBar4,
                strengthBar5
        };

        int inactiveColor = Color.parseColor("#2A3142");

        for (View bar : bars) {
            bar.setBackgroundColor(inactiveColor);
        }

        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSymbol = password.matches(".*[^A-Za-z0-9].*");

        int categories = 0;

        if (hasLower) categories++;
        if (hasUpper) categories++;
        if (hasDigit) categories++;
        if (hasSymbol) categories++;

        int strength;

        if (password.isEmpty()) {
            strength = 0;
        } else if (isObviouslyRepetitive(password)) {
            strength = 1;
        } else if (categories == 1) {
            strength = 1;
        } else if (categories == 2 || categories == 3) {
            strength = 3;
        } else if (categories == 4 && password.length() >= 15) {
            strength = 5;
        } else {
            strength = 3;
        }

        int activeColor;

        if (strength <= 1) {
            activeColor = Color.parseColor("#EF4444"); // Weak
        } else if (strength == 3) {
            activeColor = Color.parseColor("#EAB308"); // Medium
        } else {
            activeColor = Color.parseColor("#2DD4B0"); // Strong
        }

        if (strength == 0) {
            textPasswordStrength.setVisibility(View.GONE);
        } else if (strength == 1) {
            textPasswordStrength.setText("Weak");
            textPasswordStrength.setTextColor(Color.parseColor("#EF4444"));
            textPasswordStrength.setVisibility(View.VISIBLE);
        } else if (strength == 3) {
            textPasswordStrength.setText("Medium");
            textPasswordStrength.setTextColor(Color.parseColor("#EAB308"));
            textPasswordStrength.setVisibility(View.VISIBLE);
        } else {
            textPasswordStrength.setText("Strong");
            textPasswordStrength.setTextColor(Color.parseColor("#2DD4B0"));
            textPasswordStrength.setVisibility(View.VISIBLE);
        }

        for (int i = 0; i < strength; i++) {
            bars[i].setBackgroundColor(activeColor);
        }
    }

    private boolean isObviouslyRepetitive(String password) {
        if (password.length() < 2) {
            return false;
        }

        // Same character repeated: aaaaaaaa, 11111111, @@@@@@@@
        if (password.matches("^(.)\\1+$")) {
            return true;
        }

        // Short pattern repeated: 1a1a1a1a, abcabcabc, abcdabcd
        for (int unitLength = 2; unitLength <= 4; unitLength++) {
            if (password.length() % unitLength != 0) {
                continue;
            }

            String unit = password.substring(0, unitLength);
            boolean repeated = true;

            for (int i = unitLength; i < password.length(); i += unitLength) {
                if (!password.substring(i, i + unitLength).equals(unit)) {
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

        String masterPassword =
                editMasterPassword
                        .getText()
                        .toString();

        String confirmPassword =
                editConfirmPassword
                        .getText()
                        .toString();

        textValidationMessage.setText("");

        if (TextUtils.isEmpty(
                masterPassword
        )) {

            editMasterPassword.setError(
                    "Enter a master password."
            );

            editMasterPassword.requestFocus();

            return;
        }

        if (masterPassword.length() < 15) {

            editMasterPassword.setError(
                    "Use at least 15 characters."
            );

            editMasterPassword.requestFocus();

            return;
        }
        if (masterPassword.length() > 128) {
            editMasterPassword.setError("Use 128 characters or fewer.");
            return;
        }

        if (TextUtils.isEmpty(
                confirmPassword
        )) {

            editConfirmPassword.setError(
                    "Confirm the master password."
            );

            editConfirmPassword.requestFocus();

            return;
        }

        if (!masterPassword.equals(
                confirmPassword
        )) {

            editConfirmPassword.setError(
                    "Passwords do not match."
            );

            editConfirmPassword.requestFocus();

            return;
        }

        /*
         * TODO(Maryam/security integration):
         *
         * Do NOT save the raw master password.
         *
         * Do NOT pass the raw master password directly
         * to SafeKeyDatabase as the SQLCipher passphrase.
         *
         * Maryam's security/key-management layer should:
         *
         * 1. Derive cryptographic key material using Argon2id.
         * 2. Produce/unlock the SQLCipher database passphrase.
         * 3. Protect long-lived key material with Android
         *    Keystore / hardware-backed protection.
         * 4. Clear sensitive temporary values when possible.
         *
         * Never log the master password,
         * derived key, or database passphrase.
         */

        textValidationMessage.setText(
                "Sign-up UI is ready. Security integration is pending."
        );

        Toast.makeText(
                this,
                "Sign-up screen ready for security integration.",
                Toast.LENGTH_LONG
        ).show();

        editMasterPassword.setText("");
        editConfirmPassword.setText("");
    }
}
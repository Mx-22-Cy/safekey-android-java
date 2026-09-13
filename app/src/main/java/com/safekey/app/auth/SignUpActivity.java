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

public class SignUpActivity extends AppCompatActivity {

    private EditText editMasterPassword;
    private EditText editConfirmPassword;
    private CheckBox checkShowPasswords;
    private TextView textValidationMessage;

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

        if (masterPassword.length() < 12) {

            editMasterPassword.setError(
                    "Use at least 12 characters."
            );

            editMasterPassword.requestFocus();

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
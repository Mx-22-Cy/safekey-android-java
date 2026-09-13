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

public class SignInActivity extends AppCompatActivity {

    private EditText editMasterPassword;
    private CheckBox checkShowPassword;
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
                R.layout.activity_sign_in
        );

        editMasterPassword =
                findViewById(
                        R.id.editMasterPassword
                );

        checkShowPassword =
                findViewById(
                        R.id.checkShowPassword
                );

        textValidationMessage =
                findViewById(
                        R.id.textValidationMessage
                );

        Button buttonUnlockVault =
                findViewById(
                        R.id.buttonUnlockVault
                );

        Button buttonGoToSignUp =
                findViewById(
                        R.id.buttonGoToSignUp
                );

        checkShowPassword.setOnCheckedChangeListener(
                (buttonView, isChecked) ->
                        setPasswordVisibility(
                                isChecked
                        )
        );

        buttonUnlockVault.setOnClickListener(
                view ->
                        validateSignInForm()
        );

        buttonGoToSignUp.setOnClickListener(
                view -> {

                    Intent intent =
                            new Intent(
                                    SignInActivity.this,
                                    SignUpActivity.class
                            );

                    startActivity(intent);
                    finish();
                }
        );
    }

    private void setPasswordVisibility(
            boolean visible
    ) {

        int cursorPosition =
                editMasterPassword
                        .getSelectionStart();

        if (visible) {

            editMasterPassword
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
        }

        if (cursorPosition >= 0) {

            editMasterPassword.setSelection(
                    Math.min(
                            cursorPosition,
                            editMasterPassword.length()
                    )
            );
        }
    }

    private void validateSignInForm() {

        String masterPassword =
                editMasterPassword
                        .getText()
                        .toString();

        textValidationMessage.setText("");

        if (TextUtils.isEmpty(
                masterPassword
        )) {

            editMasterPassword.setError(
                    "Enter your master password."
            );

            editMasterPassword.requestFocus();

            return;
        }

        /*
         * TODO(Maryam/security integration):
         *
         * Replace this UI-only validation with
         * the approved vault unlock workflow.
         *
         * The raw master password must NOT become
         * the final SQLCipher database passphrase.
         *
         * Maryam's key-management layer should
         * derive/unlock the required key material
         * before VaultDataService opens the vault.
         *
         * Hardware-backed biometric authentication
         * can also be connected here later.
         *
         * Never log passwords or keys.
         */

        textValidationMessage.setText(
                "Sign-in UI is ready. Vault security integration is pending."
        );

        Toast.makeText(
                this,
                "Sign-in screen ready for security integration.",
                Toast.LENGTH_LONG
        ).show();

        editMasterPassword.setText("");
    }
}
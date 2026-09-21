package com.safekey.app.auth;

import android.content.Intent;
import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;

public class SignInActivity extends AppCompatActivity {

    private EditText editMasterPassword;
    private ImageButton buttonTogglePassword;
    private boolean passwordVisible = false;
    private TextView textValidationMessage;

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
                R.layout.activity_sign_in
        );

        View rootSignIn =
                findViewById(
                        R.id.rootSignIn
                );

        ViewCompat.setOnApplyWindowInsetsListener(
                rootSignIn,
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
                rootSignIn
        );

        editMasterPassword =
                findViewById(
                        R.id.editMasterPassword
                );

        buttonTogglePassword =
                findViewById(
                        R.id.buttonTogglePassword
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

        buttonTogglePassword.setOnClickListener(
                view -> {

                    passwordVisible =
                            !passwordVisible;

                    setPasswordVisibility(
                            passwordVisible
                    );

                    if (passwordVisible) {

                        buttonTogglePassword.setImageResource(
                                R.drawable.ic_visibility_off
                        );

                        buttonTogglePassword.setContentDescription(
                                getString(
                                        R.string.hide_password_content_description
                                )
                        );

                    } else {

                        buttonTogglePassword.setImageResource(
                                R.drawable.ic_visibility
                        );

                        buttonTogglePassword.setContentDescription(
                                getString(
                                        R.string.show_password_content_description
                                )
                        );
                    }
                }
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

        textValidationMessage.setText(null);

        if (editMasterPassword
                .getText()
                .length() == 0) {

            editMasterPassword.setError(
                    getString(
                            R.string.error_master_password_required
                    )
            );

            editMasterPassword.requestFocus();
            return;
        }

        /*
         * TODO: Connect this screen to the real vault unlock logic later.
         *
         * Do not save or log the master password.
         * The password should not be used directly as the SQLCipher password.
         *
         * Later, the security layer will verify the password,
         * unlock the required key material, and open the encrypted vault.
         */

        textValidationMessage.setText(
                R.string.signin_pending_integration
        );

        Toast.makeText(
                this,
                R.string.signin_pending_integration_toast,
                Toast.LENGTH_LONG
        ).show();

        editMasterPassword.setText("");
    }
}
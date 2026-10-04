package com.safekey.app.auth;

import android.content.Intent;
import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.text.Editable;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.graphics.drawable.ColorDrawable;
import android.view.Window;
import android.view.WindowManager;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.appcompat.app.AlertDialog;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.security.biometric.BiometricAuthenticator;
import com.safekey.app.auth.logic.BiometricSignInPolicy;

import java.util.Arrays;

public class SignInActivity extends AppCompatActivity {

    private EditText editMasterPassword;
    private ImageButton buttonTogglePassword;
    private boolean passwordVisible = false;
    private TextView textValidationMessage;
    private SecureVaultCoordinator secureVaultCoordinator;
    private LinearLayout biometricUnlockSection;

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

        biometricUnlockSection =
                findViewById(
                        R.id.biometricUnlockSection
                );

        TextView biometricUnlockArea =
                findViewById(
                        R.id.biometricUnlockArea
                );

        secureVaultCoordinator =
                ((SafeKeyApplication) getApplication())
                        .getSecureVaultCoordinator();

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

        biometricUnlockArea.setOnClickListener(
                view ->
                        unlockVaultWithBiometrics()
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

    @Override
    protected void onResume() {
        super.onResume();

        updateBiometricUnlockVisibility();
    }

    private void updateBiometricUnlockVisibility() {

        boolean shouldShowBiometricUnlock = false;

        try {

            boolean biometricAvailable =
                    secureVaultCoordinator.getBiometricAvailability(this)
                            == BiometricAuthenticator.Availability.AVAILABLE;

            boolean biometricConfigured =
                    secureVaultCoordinator.isBiometricUnlockConfigured(this);

            shouldShowBiometricUnlock =
                    BiometricSignInPolicy.shouldShowUnlockOption(
                            biometricAvailable,
                            biometricConfigured
                    );

        } catch (Exception exception) {

            shouldShowBiometricUnlock = false;
        }

        biometricUnlockSection.setVisibility(
                shouldShowBiometricUnlock
                        ? View.VISIBLE
                        : View.GONE
        );
    }
    private boolean shouldOfferBiometricEnrollment() {

        try {

            boolean biometricAvailable =
                    secureVaultCoordinator.getBiometricAvailability(this)
                            == BiometricAuthenticator.Availability.AVAILABLE;

            boolean biometricConfigured =
                    secureVaultCoordinator.isBiometricUnlockConfigured(this);

            return BiometricSignInPolicy.shouldOfferEnrollment(
                    biometricAvailable,
                    biometricConfigured
            );

        } catch (Exception exception) {

            return false;
        }
    }

    private void hideKeyboard() {

        editMasterPassword.clearFocus();

        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.hide(
                WindowInsetsCompat.Type.ime()
        );
    }

    private void showBiometricEnrollmentDialog(
            Runnable onNotNow,
            Runnable onEnable
    ) {
        hideKeyboard();

        View dialogView =
                getLayoutInflater().inflate(
                        R.layout.dialog_enable_biometric,
                        null
                );

        AlertDialog dialog =
                new AlertDialog.Builder(this)
                        .setView(dialogView)
                        .create();

        dialog.setCancelable(false);
        dialog.setCanceledOnTouchOutside(false);

        Button buttonNotNow =
                dialogView.findViewById(
                        R.id.buttonBiometricNotNow
                );

        Button buttonEnable =
                dialogView.findViewById(
                        R.id.buttonBiometricEnable
                );

        buttonNotNow.setOnClickListener(
                view -> {
                    dialog.dismiss();
                    onNotNow.run();
                }
        );

        buttonEnable.setOnClickListener(
                view -> {
                    dialog.dismiss();
                    onEnable.run();
                }
        );

        dialog.setOnShowListener(
                ignored -> {

                    Window window =
                            dialog.getWindow();

                    if (window != null) {

                        window.setBackgroundDrawable(
                                new ColorDrawable(
                                        android.graphics.Color.TRANSPARENT
                                )
                        );

                        window.addFlags(
                                WindowManager.LayoutParams.FLAG_DIM_BEHIND
                        );

                        WindowManager.LayoutParams attributes =
                                window.getAttributes();

                        attributes.dimAmount = 0.72f;

                        window.setAttributes(
                                attributes
                        );
                    }
                }
        );

        dialog.show();
    }

    private void unlockVaultWithBiometrics() {

        textValidationMessage.setText(null);

        try {

            secureVaultCoordinator.unlockVaultWithBiometrics(
                    this,
                    getString(
                            R.string.biometric_unlock_prompt_title
                    ),
                    getString(
                            R.string.biometric_unlock_prompt_subtitle
                    ),
                    new SecureVaultCoordinator.BiometricUnlockCallback() {

                        @Override
                        public void onSuccess() {
                            continueToHome();
                        }

                        @Override
                        public void onError(
                                String message
                        ) {
                            updateBiometricUnlockVisibility();
                        }

                        @Override
                        public void onFailed() {
                            // Android keeps the biometric prompt open
                            // so the user can try again.
                        }
                    }
            );

        } catch (RuntimeException exception) {

            updateBiometricUnlockVisibility();
        }
    }

    private void enableBiometricEnrollment(
            char[] masterPassword
    ) {

        try {

            secureVaultCoordinator.enableBiometricUnlock(
                    this,
                    masterPassword,
                    getString(
                            R.string.biometric_enable_title
                    ),
                    getString(
                            R.string.biometric_enable_message
                    ),
                    new SecureVaultCoordinator.BiometricSetupCallback() {

                        @Override
                        public void onEnabled() {
                            updateBiometricUnlockVisibility();
                            continueToHome();
                        }

                        @Override
                        public void onError(
                                String message
                        ) {
                            continueToHome();
                        }

                        @Override
                        public void onFailed() {
                            // Android biometric prompt remains available
                            // for another authentication attempt.
                        }
                    }
            );

        } catch (RuntimeException exception) {

            continueToHome();

        } finally {

            Arrays.fill(
                    masterPassword,
                    '\0'
            );
        }
    }

    private void continueToHome() {

        SafeKeySession
                .getManager()
                .unlockAfterAuthentication();

        editMasterPassword.setText("");

        Intent intent =
                new Intent(
                        SignInActivity.this,
                        HomeActivity.class
                );

        intent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK
                        | Intent.FLAG_ACTIVITY_CLEAR_TASK
        );

        startActivity(intent);
        finish();
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

        Editable masterEditable =
                editMasterPassword.getText();

        if (masterEditable.length() == 0) {

            editMasterPassword.setError(
                    getString(
                            R.string.error_master_password_required
                    )
            );

            editMasterPassword.requestFocus();
            return;
        }

        char[] masterPasswordChars =
                new char[masterEditable.length()];

        masterEditable.getChars(
                0,
                masterEditable.length(),
                masterPasswordChars,
                0
        );

        char[] biometricEnrollmentPassword =
                Arrays.copyOf(
                        masterPasswordChars,
                        masterPasswordChars.length
                );

        try {

            secureVaultCoordinator.unlockVault(
                    masterPasswordChars,
                    new VaultDataService.SimpleCallback() {

                        @Override
                        public void onSuccess() {

                            if (shouldOfferBiometricEnrollment()) {

                                showBiometricEnrollmentDialog(
                                        () -> {
                                            Arrays.fill(
                                                    biometricEnrollmentPassword,
                                                    '\0'
                                            );

                                            continueToHome();
                                        },
                                        () ->
                                                enableBiometricEnrollment(
                                                        biometricEnrollmentPassword
                                                )
                                );

                            } else {

                                Arrays.fill(
                                        biometricEnrollmentPassword,
                                        '\0'
                                );

                                continueToHome();
                            }
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {

                            Arrays.fill(
                                    biometricEnrollmentPassword,
                                    '\0'
                            );

                            editMasterPassword.setText("");

                            textValidationMessage.setText(
                                    R.string.signin_vault_unlock_error
                            );

                            editMasterPassword.requestFocus();
                        }
                    }
            );

        } catch (RuntimeException exception) {

            Arrays.fill(
                    biometricEnrollmentPassword,
                    '\0'
            );

            editMasterPassword.setText("");

            textValidationMessage.setText(
                    R.string.signin_vault_unlock_error
            );

            editMasterPassword.requestFocus();

        } finally {

            Arrays.fill(
                    masterPasswordChars,
                    '\0'
            );
        }
    }
}
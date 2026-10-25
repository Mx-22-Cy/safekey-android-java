package com.safekey.app.auth;

import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.Editable;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.fragment.app.Fragment;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.logic.BiometricSignInPolicy;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.biometric.BiometricAuthenticator;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.security.totp.VaultUnlockGate;
import com.safekey.app.session.SafeKeySession;

import java.util.Arrays;

public class SignInActivity extends AppCompatActivity
        implements TotpCodeDialogFragment.Listener {

    public static final String REQUIRE_MASTER_PASSWORD =
            "com.safekey.app.auth.REQUIRE_MASTER_PASSWORD";

    private char[] pendingMasterPasswordRecheck;

    private final Handler handler = new Handler(Looper.getMainLooper());

    private EditText editMasterPassword;
    private ImageButton buttonTogglePassword;
    private Button buttonUnlockVault;
    private Button buttonGoToSignUp;
    private TextView biometricUnlockArea;
    private TextView textValidationMessage;
    private LinearLayout biometricUnlockSection;

    private SecureVaultCoordinator secureVaultCoordinator;
    private VaultUnlockFlow.Request pendingUnlock;
    private AlertDialog biometricEnrollmentDialog;
    private char[] pendingBiometricEnrollmentPassword;
    private Runnable pendingUiAction;
    private Runnable postAuthenticationTimeout;

    private long postAuthenticationStarted;
    private long generation;
    private boolean passwordVisible;
    private boolean resumed;
    private boolean busy;
    private boolean authenticated;
    private boolean navigatingToHome;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());

        WindowInsetsControllerCompat insets = WindowCompat.getInsetsController(
                getWindow(), getWindow().getDecorView());
        insets.setAppearanceLightStatusBars(false);
        insets.setAppearanceLightNavigationBars(false);

        setContentView(R.layout.activity_sign_in);

        View root = findViewById(R.id.rootSignIn);
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, windowInsets) -> {
            Insets systemBars = windowInsets.getInsets(
                    WindowInsetsCompat.Type.systemBars());

            view.setPadding(systemBars.left, systemBars.top,
                    systemBars.right, systemBars.bottom);
            return windowInsets;
        });
        ViewCompat.requestApplyInsets(root);

        editMasterPassword = findViewById(R.id.editMasterPassword);
        buttonTogglePassword = findViewById(R.id.buttonTogglePassword);
        textValidationMessage = findViewById(R.id.textValidationMessage);
        biometricUnlockSection = findViewById(R.id.biometricUnlockSection);
        biometricUnlockArea = findViewById(R.id.biometricUnlockArea);
        buttonUnlockVault = findViewById(R.id.buttonUnlockVault);
        buttonGoToSignUp = findViewById(R.id.buttonGoToSignUp);

        editMasterPassword.setSaveEnabled(false);

        secureVaultCoordinator = ((SafeKeyApplication) getApplication())
                .getSecureVaultCoordinator();

        SafeKeySession.lock();

        buttonGoToSignUp.setVisibility(
                new VaultKeyEnvelopeStore(this).hasEnvelope()
                        ? View.GONE : View.VISIBLE);

        buttonTogglePassword.setOnClickListener(view -> {
            passwordVisible = !passwordVisible;
            setPasswordVisibility(passwordVisible);
        });

        buttonUnlockVault.setOnClickListener(view -> validateSignInForm());
        biometricUnlockArea.setOnClickListener(view -> unlockVaultWithBiometrics());

        buttonGoToSignUp.setOnClickListener(view -> {
            if (!busy) {
                startActivity(new Intent(this, SignUpActivity.class));
                finish();
            }
        });

        // A restored dialog cannot restore its former authentication request.
        dismissTotpDialog();
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;

        if (authenticated
                && SystemClock.elapsedRealtime() - postAuthenticationStarted
                >= VaultUnlockGate.ATTEMPT_LIFETIME_MILLIS) {
            abortSignIn(R.string.totp_signin_expired);
            return;
        }

        updateBiometricUnlockVisibility();

        Runnable pending = pendingUiAction;
        pendingUiAction = null;

        if (pending != null) {
            pending.run();
        }
    }

    @Override
    protected void onPause() {
        resumed = false;
        super.onPause();
    }

    @Override
    protected void onStop() {
        resumed = false;

        if (!navigatingToHome) {
            abortSignIn(0);
        }

        super.onStop();
    }

    @Override
    protected void onDestroy() {
        if (!navigatingToHome) {
            abortSignIn(0);
        }

        clearPendingMasterPasswordRecheck();
        clearPendingBiometricEnrollmentPassword();
        removePostAuthenticationTimeout();
        super.onDestroy();
    }

    private void validateSignInForm() {
        if (!resumed || busy) {
            return;
        }

        Editable editable = editMasterPassword.getText();

        if (editable == null || editable.length() == 0) {
            editMasterPassword.setError(
                    getString(R.string.error_master_password_required));
            editMasterPassword.requestFocus();
            return;
        }

        char[] password = new char[editable.length()];
        editable.getChars(0, editable.length(), password, 0);

        long token = ++generation;
        authenticated = false;
        textValidationMessage.setText(null);
        setBusy(true);
        hideKeyboard();
        clearPendingBiometricEnrollmentPassword();

        if (shouldOfferBiometricEnrollment()) {
            pendingBiometricEnrollmentPassword = password.clone();
        }
        clearPendingMasterPasswordRecheck();
        if (((SafeKeyApplication) getApplication()).getMasterPasswordHealth().getStatus()
                != com.safekey.app.security.storage.MasterPasswordCheckStatus.CHECKED) {
            pendingMasterPasswordRecheck = password.clone();
        }

        try {
            pendingUnlock = secureVaultCoordinator.unlockVault(
                    password,
                    new SecureVaultCoordinator.TotpUnlockCallback() {
                        @Override
                        public void onSuccess() {
                            dispatchUi(token,
                                    () -> authenticationCompleted(token));
                        }

                        @Override
                        public void onError(Exception error) {
                            dispatchUi(token, () -> abortSignIn(
                                    totpDialog() != null
                                            ? R.string.totp_signin_failed
                                            : R.string.signin_vault_unlock_error));
                        }

                        @Override
                        public void onTotpRequired(
                                VaultUnlockFlow.Request request
                        ) {
                            showTotpChallenge(token, request);
                        }
                    });
        } catch (RuntimeException error) {
            abortSignIn(R.string.signin_vault_unlock_error);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void unlockVaultWithBiometrics() {
        if (getIntent().getBooleanExtra(REQUIRE_MASTER_PASSWORD, false)) { return; }
        if (!resumed || busy) {
            return;
        }

        long token = ++generation;
        authenticated = false;
        clearPendingBiometricEnrollmentPassword();
        editMasterPassword.setText("");
        textValidationMessage.setText(null);
        setBusy(true);
        hideKeyboard();

        try {
            pendingUnlock = secureVaultCoordinator.unlockVaultWithBiometrics(
                    this,
                    getString(R.string.biometric_unlock_prompt_title),
                    getString(R.string.biometric_unlock_prompt_subtitle),
                    new SecureVaultCoordinator.TotpBiometricUnlockCallback() {
                        @Override
                        public void onSuccess() {
                            dispatchUi(token,
                                    () -> authenticationCompleted(token));
                        }

                        @Override
                        public void onError(String message) {
                            dispatchUi(token,
                                    () -> handleBiometricUnlockError(message));
                        }

                        @Override
                        public void onFailed() {
                            // The system prompt remains available for retry.
                        }

                        @Override
                        public void onTotpRequired(
                                VaultUnlockFlow.Request request
                        ) {
                            showTotpChallenge(token, request);
                        }
                    });
        } catch (RuntimeException error) {
            abortSignIn(R.string.biometric_unlock_error);
        }
    }

    private void showTotpChallenge(
            long token,
            VaultUnlockFlow.Request request
    ) {
        if (!isCurrent(token)) {
            request.close();
            return;
        }

        dispatchUi(token, () -> {
            if (!request.isActive()
                    || getSupportFragmentManager().isStateSaved()) {
                request.close();
                abortSignIn(R.string.totp_signin_expired);
                return;
            }

            pendingUnlock = request;
            editMasterPassword.setText("");

            if (totpDialog() == null) {
                new TotpCodeDialogFragment().show(
                        getSupportFragmentManager(),
                        TotpCodeDialogFragment.TAG);
            }
        });
    }

    @Override
    public boolean hasPendingTotpChallenge() {
        return isCurrent(generation)
                && !authenticated
                && pendingUnlock != null
                && pendingUnlock.isActive();
    }

    @Override
    public void onTotpCodeSubmitted(char[] code) {
        if (!resumed || !hasPendingTotpChallenge()) {
            abortSignIn(R.string.totp_signin_expired);
            return;
        }

        long token = generation;

        try {
            pendingUnlock.submitCode(code, result -> dispatchUi(token, () -> {
                TotpCodeDialogFragment dialog = totpDialog();

                if (dialog != null) {
                    dialog.showResult(result);
                }
            }));
        } catch (RuntimeException error) {
            abortSignIn(R.string.totp_signin_failed);
        }
    }

    @Override
    public void onTotpCancelled() {
        if (!navigatingToHome && pendingUnlock != null) {
            abortSignIn(R.string.totp_signin_cancelled);
        }
    }

    private void authenticationCompleted(long token) {
        if (!isCurrent(token) || pendingUnlock == null) {
            return;
        }

        dismissTotpDialog();
        editMasterPassword.setText("");
        authenticated = true;
        postAuthenticationStarted = SystemClock.elapsedRealtime();
        removePostAuthenticationTimeout();

        postAuthenticationTimeout = () -> {
            if (isCurrent(token) && authenticated) {
                abortSignIn(R.string.totp_signin_expired);
            }
        };

        if (!handler.postDelayed(postAuthenticationTimeout,
                VaultUnlockGate.ATTEMPT_LIFETIME_MILLIS)) {
            abortSignIn(R.string.totp_signin_failed);
            return;
        }

        if (pendingBiometricEnrollmentPassword != null
                && shouldOfferBiometricEnrollment()) {
            showBiometricEnrollmentDialog(token);
        } else {
            clearPendingBiometricEnrollmentPassword();
            continueToHome(token);
        }
    }

    private void continueToHome(long token) {
        if (!resumed || !isCurrent(token)
                || !authenticated || pendingUnlock == null) {
            return;
        }

        if (!pendingUnlock.claimSession()) {
            abortSignIn(R.string.totp_signin_expired);
            return;
        }

        pendingUnlock = null;
        removePostAuthenticationTimeout();
        clearPendingBiometricEnrollmentPassword();
        dismissTotpDialog();

        authenticated = false;
        pendingUiAction = null;
        generation++;
        navigatingToHome = true;

        SafeKeySession.unlockAfterAuthentication();
        try {
            ((SafeKeyApplication) getApplication()).getMasterPasswordHealth()
                    .recheckAfterAuthentication(pendingMasterPasswordRecheck);
        } catch (RuntimeException ignored) {
            // Checking availability cannot turn a valid authentication into a failure.
        } finally {
            clearPendingMasterPasswordRecheck();
        }

        try {
            Intent intent = new Intent(this, HomeActivity.class);
            intent.addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK
                            | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        } catch (RuntimeException error) {
            SafeKeySession.lock();
            navigatingToHome = false;
            abortSignIn(R.string.signin_vault_unlock_error);
        }
    }

    private void abortSignIn(int messageId) {
        clearPendingMasterPasswordRecheck();
        generation++;
        pendingUiAction = null;
        authenticated = false;
        removePostAuthenticationTimeout();

        VaultUnlockFlow.Request request = pendingUnlock;
        pendingUnlock = null;

        if (request != null) {
            request.close();
        }

        dismissTotpDialog();

        AlertDialog dialog = biometricEnrollmentDialog;
        biometricEnrollmentDialog = null;

        if (dialog != null && dialog.isShowing()) {
            dialog.dismiss();
        }

        clearPendingBiometricEnrollmentPassword();

        if (editMasterPassword != null) {
            editMasterPassword.setText("");
            passwordVisible = false;
            setPasswordVisibility(false);
        }

        setBusy(false);

        if (textValidationMessage != null) {
            textValidationMessage.setText(
                    messageId == 0 ? null : getString(messageId));
        }
    }

    private boolean isCurrent(long token) {
        return token == generation
                && !isFinishing()
                && !isDestroyed()
                && !navigatingToHome;
    }

    private void dispatchUi(long token, Runnable action) {
        if (!isCurrent(token)) {
            return;
        }

        if (resumed) {
            action.run();
        } else {
            pendingUiAction = () -> {
                if (isCurrent(token)) {
                    action.run();
                }
            };
        }
    }

    private void setBusy(boolean value) {
        busy = value;

        if (buttonUnlockVault != null) {
            buttonUnlockVault.setEnabled(!value);
            buttonTogglePassword.setEnabled(!value);
            buttonGoToSignUp.setEnabled(!value);
            editMasterPassword.setEnabled(!value);
            biometricUnlockArea.setEnabled(!value);
        }
    }

    private void updateBiometricUnlockVisibility() {
        boolean show = false;

        try {
            show = BiometricSignInPolicy.shouldShowUnlockOption(
                    secureVaultCoordinator.getBiometricAvailability(this)
                            == BiometricAuthenticator.Availability.AVAILABLE,
                    secureVaultCoordinator.isBiometricUnlockConfigured(this));
        } catch (Exception ignored) {
            // Master-password sign-in remains available.
        }

        biometricUnlockSection.setVisibility(
                show && !getIntent().getBooleanExtra(REQUIRE_MASTER_PASSWORD, false)
                        ? View.VISIBLE : View.GONE);
    }

    private boolean shouldOfferBiometricEnrollment() {
        try {
            return BiometricSignInPolicy.shouldOfferEnrollment(
                    secureVaultCoordinator.getBiometricAvailability(this)
                            == BiometricAuthenticator.Availability.AVAILABLE,
                    secureVaultCoordinator.isBiometricUnlockConfigured(this));
        } catch (Exception ignored) {
            return false;
        }
    }

    private void handleBiometricUnlockError(String message) {
        boolean totpWasVisible = totpDialog() != null;

        abortSignIn(totpWasVisible
                ? R.string.totp_signin_failed
                : R.string.biometric_unlock_error);

        if (totpWasVisible
                || !BiometricSignInPolicy.requiresReEnrollment(message)) {
            return;
        }

        textValidationMessage.setText(
                R.string.biometric_reenrollment_required);
        biometricUnlockSection.setVisibility(View.GONE);

        long token = generation;

        try {
            secureVaultCoordinator.disableBiometricUnlock(
                    this,
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            refresh();
                        }

                        @Override
                        public void onError(Exception error) {
                            refresh();
                        }

                        private void refresh() {
                            if (resumed && isCurrent(token) && !busy) {
                                updateBiometricUnlockVisibility();
                                textValidationMessage.setText(
                                        R.string.biometric_reenrollment_required);
                                editMasterPassword.requestFocus();
                            }
                        }
                    });
        } catch (RuntimeException ignored) {
            editMasterPassword.requestFocus();
        }
    }

    private void showBiometricEnrollmentDialog(long token) {
        hideKeyboard();

        View content = getLayoutInflater()
                .inflate(R.layout.dialog_enable_biometric, null);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(content)
                .create();

        biometricEnrollmentDialog = dialog;
        dialog.setCancelable(false);
        dialog.setCanceledOnTouchOutside(false);

        dialog.setOnDismissListener(ignored -> {
            if (biometricEnrollmentDialog == dialog) {
                biometricEnrollmentDialog = null;
                dispatchUi(token,
                        () -> abortSignIn(R.string.totp_signin_cancelled));
            }
        });

        Button notNow = content.findViewById(R.id.buttonBiometricNotNow);
        Button enable = content.findViewById(R.id.buttonBiometricEnable);

        notNow.setOnClickListener(view -> {
            if (!isCurrent(token)) {
                return;
            }

            biometricEnrollmentDialog = null;
            dialog.dismiss();
            clearPendingBiometricEnrollmentPassword();
            continueToHome(token);
        });

        enable.setOnClickListener(view -> {
            if (!isCurrent(token)) {
                return;
            }

            biometricEnrollmentDialog = null;
            dialog.dismiss();

            char[] password = pendingBiometricEnrollmentPassword;
            pendingBiometricEnrollmentPassword = null;

            if (password == null) {
                abortSignIn(R.string.totp_signin_failed);
                return;
            }

            enableBiometricEnrollment(token, password);
        });

        dialog.setOnShowListener(ignored -> {
            Window window = dialog.getWindow();

            if (window != null) {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE
                        | WindowManager.LayoutParams.FLAG_DIM_BEHIND);
                window.setBackgroundDrawable(
                        new ColorDrawable(Color.TRANSPARENT));

                WindowManager.LayoutParams attributes =
                        window.getAttributes();
                attributes.dimAmount = 0.72f;
                window.setAttributes(attributes);
            }
        });

        dialog.show();
    }

    private void enableBiometricEnrollment(long token, char[] password) {
        try {
            secureVaultCoordinator.enableBiometricUnlock(
                    this,
                    password,
                    getString(R.string.biometric_enable_title),
                    getString(R.string.biometric_enable_message),
                    new SecureVaultCoordinator.BiometricSetupCallback() {
                        @Override
                        public void onEnabled() {
                            dispatchUi(token, () -> continueToHome(token));
                        }

                        @Override
                        public void onError(String message) {
                            dispatchUi(token, () -> {
                                Toast.makeText(
                                        SignInActivity.this,
                                        R.string.biometric_setup_error,
                                        Toast.LENGTH_LONG).show();
                                continueToHome(token);
                            });
                        }

                        @Override
                        public void onFailed() {
                            // The system prompt remains available for retry.
                        }
                    });
        } catch (RuntimeException error) {
            Toast.makeText(this, R.string.biometric_setup_error,
                    Toast.LENGTH_LONG).show();
            continueToHome(token);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void clearPendingMasterPasswordRecheck() {
        if (pendingMasterPasswordRecheck != null) {
            Arrays.fill(pendingMasterPasswordRecheck, '\0');
            pendingMasterPasswordRecheck = null;
        }
    }

    private void clearPendingBiometricEnrollmentPassword() {
        if (pendingBiometricEnrollmentPassword != null) {
            Arrays.fill(pendingBiometricEnrollmentPassword, '\0');
            pendingBiometricEnrollmentPassword = null;
        }
    }

    private void removePostAuthenticationTimeout() {
        if (postAuthenticationTimeout != null) {
            handler.removeCallbacks(postAuthenticationTimeout);
            postAuthenticationTimeout = null;
        }
    }

    private TotpCodeDialogFragment totpDialog() {
        Fragment fragment = getSupportFragmentManager()
                .findFragmentByTag(TotpCodeDialogFragment.TAG);

        return fragment instanceof TotpCodeDialogFragment
                ? (TotpCodeDialogFragment) fragment
                : null;
    }

    private void dismissTotpDialog() {
        TotpCodeDialogFragment dialog = totpDialog();

        if (dialog != null) {
            dialog.dismissSilently();
        }
    }

    private void hideKeyboard() {
        editMasterPassword.clearFocus();
        WindowCompat.getInsetsController(
                        getWindow(), getWindow().getDecorView())
                .hide(WindowInsetsCompat.Type.ime());
    }

    private void setPasswordVisibility(boolean visible) {
        int cursor = editMasterPassword.getSelectionStart();

        editMasterPassword.setTransformationMethod(visible
                ? HideReturnsTransformationMethod.getInstance()
                : PasswordTransformationMethod.getInstance());

        buttonTogglePassword.setImageResource(visible
                ? R.drawable.ic_visibility_off
                : R.drawable.ic_visibility);

        buttonTogglePassword.setContentDescription(getString(visible
                ? R.string.hide_password_content_description
                : R.string.show_password_content_description));

        if (cursor >= 0) {
            editMasterPassword.setSelection(
                    Math.min(cursor, editMasterPassword.length()));
        }
    }
}

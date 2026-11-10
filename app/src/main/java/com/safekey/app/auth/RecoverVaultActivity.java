package com.safekey.app.auth;

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
import android.widget.ImageButton;
import android.widget.TextView;
import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AlertDialog;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordScreening;
import com.safekey.app.auth.logic.MasterPasswordValidationResult;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.MasterPasswordChangeRequest;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.session.SafeKeySession;
import java.util.Arrays;

/** T43: locked-only local recovery; never unlocks the vault after a reset. */
public final class RecoverVaultActivity extends com.safekey.app.StartupGuardActivity {
    private EditText recoveryKey, newPassword, confirmPassword;
    private CheckBox showKey, showPasswords;
    private TextView keyError, passwordError, confirmError, status;
    private Button reset, cancel;
    private View form, success;
    private MasterPasswordScreening.Request screeningRequest;
    private MasterPasswordChangeRequest resetRequest;
    private AlertDialog offlineDialog;
    private char[] pendingKey;
    private char[] pendingPassword;
    private long generation;
    private boolean resumed;
    private boolean busy;
    private boolean completed;
    private boolean recoveryUnavailable;

    @Override protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        WindowInsetsControllerCompat controller = WindowCompat.getInsetsController(
                getWindow(), getWindow().getDecorView());
        controller.setAppearanceLightStatusBars(false);
        controller.setAppearanceLightNavigationBars(false);
        setContentView(R.layout.activity_recover_vault);
        View root = findViewById(R.id.rootRecoverVault);
        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(root);
        SafeKeySession.lock();
        recoveryKey = findViewById(R.id.editRecoveryKey);
        newPassword = findViewById(R.id.editNewRecoveryPassword);
        confirmPassword = findViewById(R.id.editConfirmRecoveryPassword);
        showKey = findViewById(R.id.checkShowRecoveryKey);
        showPasswords = findViewById(R.id.checkShowRecoveryPasswords);
        keyError = findViewById(R.id.textRecoveryKeyError);
        passwordError = findViewById(R.id.textNewPasswordError);
        confirmError = findViewById(R.id.textConfirmPasswordError);
        status = findViewById(R.id.textRecoveryStatus);
        reset = findViewById(R.id.buttonResetMasterPassword);
        cancel = findViewById(R.id.buttonCancelRecovery);
        form = findViewById(R.id.recoveryForm);
        success = findViewById(R.id.recoverySuccess);
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (!busy) finishRecovery();
            }
        });
        findViewById(R.id.buttonBackRecovery).setOnClickListener(v -> finishRecovery());
        cancel.setOnClickListener(v -> finishRecovery());
        findViewById(R.id.buttonRecoverySuccessSignIn).setOnClickListener(v -> finishRecovery());
        showKey.setOnCheckedChangeListener((v, checked) -> recoveryKey.setTransformationMethod(
                checked ? HideReturnsTransformationMethod.getInstance() : PasswordTransformationMethod.getInstance()));
        showPasswords.setOnCheckedChangeListener((v, checked) -> {
            newPassword.setTransformationMethod(checked ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());
            confirmPassword.setTransformationMethod(checked ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());
        });
        ImageButton eyeKey = findViewById(R.id.buttonEyeRecoveryKey);
        ImageButton eyeNew = findViewById(R.id.buttonEyeNewRecoveryPassword);
        ImageButton eyeConfirm = findViewById(R.id.buttonEyeConfirmRecoveryPassword);
        eyeKey.setOnClickListener(v -> showKey.setChecked(!showKey.isChecked()));
        eyeNew.setOnClickListener(v -> toggleVisibility(newPassword));
        eyeConfirm.setOnClickListener(v -> toggleVisibility(confirmPassword));
        TextWatcher watcher = new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { updateValid(); }
            @Override public void afterTextChanged(Editable s) { }
        };
        recoveryKey.addTextChangedListener(watcher);
        newPassword.addTextChangedListener(watcher);
        confirmPassword.addTextChangedListener(watcher);
        reset.setOnClickListener(v -> beginReset());
        View.OnFocusChangeListener validationOnBlur = (view, hasFocus) -> {
            if (!hasFocus) updateValid();
        };
        recoveryKey.setOnFocusChangeListener(validationOnBlur);
        newPassword.setOnFocusChangeListener(validationOnBlur);
        confirmPassword.setOnFocusChangeListener(validationOnBlur);
        if (!new VaultKeyEnvelopeStore(this).hasEnvelope()) {
            setDisabled(getString(R.string.t43_recovery_unavailable));
        }
        updateValid();
    }

    @Override protected void onRuntimeResume() {
        super.onRuntimeResume();
        resumed = true;
        if (!recoveryUnavailable && !completed) setBusy(false);
        updateValid();
    }

    @Override protected void onRuntimeStop() {
        resumed = false;
        if (!completed) {
            cancelWork();
            clearInputs();
        }
        super.onRuntimeStop();
    }

    @Override protected void onRuntimeDestroy() {
        cancelWork();
        clearInputs();
        super.onRuntimeDestroy();
    }

    /** Show local validation feedback before submission, without contacting the backend. */
    private void updateValid() {
        if (reset == null || completed || busy) return;
        if (recoveryUnavailable || !new VaultKeyEnvelopeStore(this).hasEnvelope()) {
            setResetEnabled(false);
            return;
        }
        char[] key = normalizedKey();
        char[] password = read(newPassword);
        char[] confirmation = read(confirmPassword);
        try {
            boolean keyValid = key != null;
            MasterPasswordValidationResult passwordResult = MasterPasswordPolicy.validate(password);
            boolean passwordValid = passwordResult == MasterPasswordValidationResult.VALID;
            boolean matches = passwordValid && confirmation.length > 0
                    && Arrays.equals(password, confirmation);

            // A disabled button must never look actionable, and invalid populated
            // fields must explain what needs fixing without requiring a click.
            if (recoveryKey.length() > 0 && !keyValid) {
                keyError.setText(getString(R.string.t43_recovery_key_invalid));
            } else if (keyError.getText().length() > 0) {
                keyError.setText(null);
            }
            if (password.length > 0 && !passwordValid) {
                passwordError.setText(MasterPasswordMessages.validation(this, passwordResult));
            } else {
                passwordError.setText(null);
            }
            if (confirmation.length > 0 && passwordValid && !matches) {
                confirmError.setText(getString(R.string.t43_password_mismatch));
            } else {
                confirmError.setText(null);
            }
            updatePasswordMeter(password.length, passwordValid);
            setResetEnabled(keyValid && matches);
        } finally {
            if (key != null) Arrays.fill(key, '\0');
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    /** Policy indicator, not a guessed password entropy score. */
    private void updatePasswordMeter(int length, boolean policyValid) {
        TextView label = findViewById(R.id.textRecoveryStrength);
        int active = length == 0 ? 0 : (policyValid ? 5 : Math.min(4, Math.max(1, length / 4)));
        int[] segmentIds = {
                R.id.recoveryStrengthSegment1,
                R.id.recoveryStrengthSegment2,
                R.id.recoveryStrengthSegment3,
                R.id.recoveryStrengthSegment4,
                R.id.recoveryStrengthSegment5
        };
        for (int index = 0; index < segmentIds.length; index++) {
            View segment = findViewById(segmentIds[index]);
            if (segment != null) segment.setBackgroundColor(index < active
                    ? (policyValid ? 0xFF2DD4B0 : 0xFFE5575C) : 0xFF303849);
        }
        label.setText(length == 0 ? "" : (policyValid
                ? getString(R.string.t43_password_policy_met) : getString(R.string.t43_password_policy_not_met)));
        label.setTextColor(policyValid ? 0xFF2DD4B0 : 0xFFE5848A);
    }

    private void setResetEnabled(boolean enabled) {
        reset.setEnabled(enabled);
        reset.setAlpha(enabled ? 1.0f : 0.38f);
    }

    private static void toggleVisibility(EditText field) {
        int selection = field.getSelectionStart();
        boolean currentlyHidden = field.getTransformationMethod()
                instanceof PasswordTransformationMethod;
        field.setTransformationMethod(currentlyHidden
                ? HideReturnsTransformationMethod.getInstance()
                : PasswordTransformationMethod.getInstance());
        if (selection >= 0) field.setSelection(Math.min(selection, field.length()));
    }

    private static char[] read(EditText field) {
        Editable input = field.getText();
        char[] out = new char[input.length()];
        input.getChars(0, input.length(), out, 0);
        return out;
    }

    /** Whitespace between groups is allowed; all other characters must be ASCII hex. */
    private char[] normalizedKey() {
        Editable raw = recoveryKey.getText();
        char[] result = new char[32];
        int size = 0;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == ' ' || c == '\n' || c == '\t') { continue; }
            if (size == result.length || !((c >= '0' && c <= '9')
                    || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                Arrays.fill(result, '\0');
                return null;
            }
            result[size++] = Character.toUpperCase(c);
        }
        if (size != result.length) {
            Arrays.fill(result, '\0');
            return null;
        }
        return result;
    }

    private void beginReset() {
        if (!resumed || busy || completed || !reset.isEnabled()) { return; }
        clearErrors();
        char[] key = normalizedKey();
        char[] password = read(newPassword);
        char[] confirmation = read(confirmPassword);
        if (key == null) {
            keyError.setText(getString(R.string.t43_recovery_key_invalid_short));
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
            return;
        }
        MasterPasswordValidationResult result = MasterPasswordPolicy.validateForEnrollment(password, confirmation);
        Arrays.fill(confirmation, '\0');
        if (result != MasterPasswordValidationResult.VALID) {
            passwordError.setText(MasterPasswordMessages.validation(this, result));
            Arrays.fill(key, '\0');
            Arrays.fill(password, '\0');
            return;
        }
        pendingKey = key;
        pendingPassword = password;
        busy = true;
        setBusy(true);
        status.setText(getString(R.string.t43_password_checking));
        long token = ++generation;
        try {
            screeningRequest = ((SafeKeyApplication) getApplication()).getMasterPasswordHealth()
                    .getScreening().checkNewPassword(password, password,
                            check -> runOnUiThread(() -> onScreened(token, check)));
        } catch (RuntimeException error) {
            fail(getString(R.string.t43_password_check_failed));
        }
    }

    private void onScreened(long token, MasterPasswordScreening.Result result) {
        if (!current(token)) { return; }
        screeningRequest = null;
        switch (result.getOutcome()) {
            case CHECKED_ACCEPTABLE:
                submitReset(token, MasterPasswordCheckStatus.CHECKED);
                break;
            case OFFLINE_CHOICE_REQUIRED:
                offlineDialog = new AlertDialog.Builder(this)
                        .setTitle(R.string.master_password_offline_title)
                        .setMessage(R.string.master_password_offline_message)
                        .setPositiveButton(R.string.master_password_continue_offline, (dialog, which) -> {
                            offlineDialog = null;
                            if (current(token)) submitReset(token, MasterPasswordCheckStatus.PENDING);
                        })
                        .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                            offlineDialog = null;
                            if (current(token)) fail(getString(R.string.t43_password_check_cancelled));
                        })
                        .setOnCancelListener(dialog -> {
                            offlineDialog = null;
                            if (current(token)) fail(getString(R.string.t43_password_check_cancelled));
                        }).create();
                offlineDialog.show();
                if (offlineDialog.getWindow() != null) {
                    offlineDialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                }
                break;
            case BREACHED:
                fail(getString(R.string.master_password_breached_rejected));
                break;
            case LOCAL_REJECTION:
                fail(MasterPasswordMessages.validation(this, result.getValidation()));
                break;
            default:
                fail(getString(R.string.master_password_check_failed));
        }
    }

    private void submitReset(long token, MasterPasswordCheckStatus checkStatus) {
        if (!current(token) || pendingKey == null || pendingPassword == null) { return; }
        try {
            resetRequest = ((SafeKeyApplication) getApplication()).getSecureVaultCoordinator()
                    .resetMasterPasswordWithRecovery(pendingKey, pendingPassword, checkStatus,
                            new VaultDataService.SimpleCallback() {
                                @Override public void onSuccess() {
                                    runOnUiThread(() -> {
                                        if (!current(token)) { return; }
                                        completed = true;
                                        cancelWork();
                                        clearInputs();
                                        form.setVisibility(View.GONE);
                                        success.setVisibility(View.VISIBLE);
                                        findViewById(R.id.buttonBackRecovery).setVisibility(View.GONE);
                                    });
                                }
                                @Override public void onError(Exception error) {
                                    runOnUiThread(() -> {
                                        if (!current(token)) { return; }
                                        if (error instanceof IllegalStateException && error.getMessage() != null
                                                && error.getMessage().contains("unavailable")) {
                                            setDisabled(getString(R.string.t43_recovery_unavailable));
                                        } else {
                                            fail(getString(R.string.t43_recovery_invalid_or_failed));
                                        }
                                    });
                                }
                            });
        } catch (RuntimeException error) {
            fail(getString(R.string.t43_recovery_failed));
        }
    }

    private boolean current(long token) {
        return resumed && !isFinishing() && token == generation && busy;
    }

    private void clearErrors() {
        keyError.setText(null);
        passwordError.setText(null);
        confirmError.setText(null);
        status.setText(null);
    }

    private void setBusy(boolean value) {
        busy = value;
        recoveryKey.setEnabled(!value);
        newPassword.setEnabled(!value);
        confirmPassword.setEnabled(!value);
        showKey.setEnabled(!value);
        showPasswords.setEnabled(!value);
        findViewById(R.id.buttonEyeRecoveryKey).setEnabled(!value);
        findViewById(R.id.buttonEyeNewRecoveryPassword).setEnabled(!value);
        findViewById(R.id.buttonEyeConfirmRecoveryPassword).setEnabled(!value);
        cancel.setEnabled(!value);
        findViewById(R.id.buttonBackRecovery).setEnabled(!value);
        setResetEnabled(false);
        if (!value) updateValid();
    }

    private void setDisabled(String message) {
        cancelWork();
        clearInputs();
        recoveryUnavailable = true;
        status.setText(message);
        form.setVisibility(View.VISIBLE);
        recoveryKey.setEnabled(false);
        newPassword.setEnabled(false);
        confirmPassword.setEnabled(false);
        showKey.setEnabled(false);
        showPasswords.setEnabled(false);
        findViewById(R.id.buttonEyeRecoveryKey).setEnabled(false);
        findViewById(R.id.buttonEyeNewRecoveryPassword).setEnabled(false);
        findViewById(R.id.buttonEyeConfirmRecoveryPassword).setEnabled(false);
        setResetEnabled(false);
    }

    private void fail(String message) {
        cancelWork();
        status.setText(message);
        setBusy(false);
    }

    private void cancelWork() {
        generation++;
        if (screeningRequest != null) { screeningRequest.close(); screeningRequest = null; }
        if (resetRequest != null) { resetRequest.close(); resetRequest = null; }
        if (offlineDialog != null) {
            AlertDialog old = offlineDialog;
            offlineDialog = null;
            old.dismiss();
        }
        if (pendingKey != null) { Arrays.fill(pendingKey, '\0'); pendingKey = null; }
        if (pendingPassword != null) { Arrays.fill(pendingPassword, '\0'); pendingPassword = null; }
        busy = false;
    }

    private void clearInputs() {
        if (recoveryKey != null) recoveryKey.setText(null);
        if (newPassword != null) newPassword.setText(null);
        if (confirmPassword != null) confirmPassword.setText(null);
    }

    private void finishRecovery() {
        if (busy) return;
        cancelWork();
        clearInputs();
        finish();
    }

}

package com.safekey.app.auth;

import com.safekey.app.security.panic.PanicRuntimeScope;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.logic.MasterPasswordScreening;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.MasterPasswordChangeRequest;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.session.SafeKeySession;

import java.util.Arrays;

/** Accessible from Home until the team's Settings integration is ready. */
public final class ChangeMasterPasswordActivity extends ProtectedActivity {
    private PanicRuntimeScope.Registration panicCancellation;

    private EditText currentInput;
    private EditText newInput;
    private EditText confirmationInput;
    private TextView message;
    private Button save;
    private Button back;
    private char[] currentPassword;
    private char[] newPassword;
    private MasterPasswordScreening.Request screening;
    private MasterPasswordChangeRequest change;
    private AlertDialog offlineDialog;
    private boolean active;
    private boolean busy;
    private long generation;
    private long authentication;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView())
                .setAppearanceLightStatusBars(false);
        WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView())
                .setAppearanceLightNavigationBars(false);
        setContentView(R.layout.activity_change_master_password);
        View root = findViewById(R.id.rootChangeMasterPassword);
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(root);
        currentInput = findViewById(R.id.editCurrentMasterPassword);
        newInput = findViewById(R.id.editNewMasterPassword);
        confirmationInput = findViewById(R.id.editConfirmNewMasterPassword);
        message = findViewById(R.id.textMasterPasswordChangeMessage);
        save = findViewById(R.id.buttonSaveMasterPassword);
        back = findViewById(R.id.buttonCancelMasterPasswordChange);
        currentInput.setSaveEnabled(false);
        newInput.setSaveEnabled(false);
        confirmationInput.setSaveEnabled(false);
        save.setOnClickListener(view -> submit());
        back.setOnClickListener(view -> finish());

        panicCancellation = com.safekey.app.security.panic.PanicSensitiveUi.bind(
                this, () -> { active = false; cancelPending();
                    if (currentInput != null) { currentInput.setText(""); }
                    if (newInput != null) { newInput.setText(""); }
                    if (confirmationInput != null) { confirmationInput.setText(""); } });
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        authentication = SafeKeySession.getManager().getAuthenticationGeneration();
        active = !isFinishing() && authentication >= 0L;
    }

    @Override
    protected void onRuntimePause() {
        active = false;
        cancelPending();
        currentInput.setText("");
        newInput.setText("");
        confirmationInput.setText("");
        super.onRuntimePause();
    }

    @Override
    protected void onRuntimeDestroy() {
        if (panicCancellation != null) { panicCancellation.close(); }

        cancelPending();
        super.onRuntimeDestroy();
    }

    private void submit() {
        if (!active || busy || !SafeKeySession.recordActivity()) { return; }
        currentPassword = read(currentInput);
        newPassword = read(newInput);
        char[] confirmation = read(confirmationInput);
        if (currentPassword.length == 0 || Arrays.equals(currentPassword, newPassword)) {
            Arrays.fill(confirmation, '\0');
            reject(getString(currentPassword.length == 0
                    ? R.string.master_password_current_required
                    : R.string.master_password_choose_different));
            return;
        }
        long token = ++generation;
        setBusy(true);
        message.setText(R.string.master_password_checking);
        try {
            screening = ((SafeKeyApplication) getApplication()).getMasterPasswordHealth()
                    .getScreening().checkNewPassword(newPassword, confirmation,
                            result -> screened(token, result));
        } catch (RuntimeException error) {
            reject(getString(R.string.master_password_check_failed));
        } finally {
            Arrays.fill(confirmation, '\0');
        }
    }

    private void screened(long token, MasterPasswordScreening.Result result) {
        if (!isCurrent(token)) { return; }
        switch (result.getOutcome()) {
            case LOCAL_REJECTION:
                reject(MasterPasswordMessages.validation(this, result.getValidation()));
                break;
            case BREACHED:
                reject(getString(R.string.master_password_breached_rejected));
                newInput.setText("");
                confirmationInput.setText("");
                break;
            case CHECKED_ACCEPTABLE:
                saveScreenedPassword(token, MasterPasswordCheckStatus.CHECKED);
                break;
            case OFFLINE_CHOICE_REQUIRED:
                offlineDialog = new AlertDialog.Builder(this)
                        .setTitle(R.string.master_password_offline_title)
                        .setMessage(R.string.master_password_offline_message)
                        .setPositiveButton(R.string.master_password_continue_offline, (dialog, which) -> {
                            offlineDialog = null;
                            if (isCurrent(token)) {
                                saveScreenedPassword(token, MasterPasswordCheckStatus.PENDING);
                            }
                        })
                        .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                            offlineDialog = null;
                            reject(getString(R.string.master_password_check_cancelled));
                        })
                        .setOnCancelListener(dialog -> {
                            offlineDialog = null;
                            reject(getString(R.string.master_password_check_cancelled));
                        }).create();
                offlineDialog.show();
                if (offlineDialog.getWindow() != null) {
                    offlineDialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                }
                break;
            default:
                reject(getString(R.string.master_password_check_failed));
        }
    }

    private void saveScreenedPassword(long token, MasterPasswordCheckStatus status) {
        if (!isCurrent(token) || currentPassword == null || newPassword == null) { return; }
        message.setText(R.string.master_password_changing);
        try {
            change = ((SafeKeyApplication) getApplication()).getSecureVaultCoordinator()
                    .changeMasterPassword(currentPassword, newPassword, status,
                            new VaultDataService.SimpleCallback() {
                                @Override public void onSuccess() {
                                    if (!isCurrent(token)) { return; }
                                    Toast.makeText(ChangeMasterPasswordActivity.this,
                                            R.string.master_password_changed, Toast.LENGTH_LONG).show();
                                    SafeKeySession.lock();
                                    Intent intent = new Intent(ChangeMasterPasswordActivity.this,
                                            SignInActivity.class);
                                    intent.putExtra(SignInActivity.REQUIRE_MASTER_PASSWORD, true);
                                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                                            | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                                    startActivity(intent);
                                    finish();
                                }
                                @Override public void onError(Exception error) {
                                    if (isCurrent(token)) {
                                        reject(getString(R.string.master_password_change_failed));
                                    }
                                }
                            });
        } catch (RuntimeException error) {
            reject(getString(R.string.master_password_change_failed));
        } finally {
            clearPasswords();
        }
    }

    private boolean isCurrent(long token) {
        return active && token == generation && !isFinishing() && !isDestroyed()
                && SafeKeySession.getManager().getAuthenticationGeneration() == authentication;
    }

    private void reject(String text) {
        cancelPending();
        message.setText(text);
    }

    private void cancelPending() {
        generation++;
        if (screening != null) { screening.close(); screening = null; }
        if (change != null) { change.close(); change = null; }
        if (offlineDialog != null) { offlineDialog.dismiss(); offlineDialog = null; }
        clearPasswords();
        setBusy(false);
    }

    private void clearPasswords() {
        if (currentPassword != null) { Arrays.fill(currentPassword, '\0'); currentPassword = null; }
        if (newPassword != null) { Arrays.fill(newPassword, '\0'); newPassword = null; }
    }

    private void setBusy(boolean value) {
        busy = value;
        if (save != null) {
            save.setEnabled(!value);
            currentInput.setEnabled(!value);
            newInput.setEnabled(!value);
            confirmationInput.setEnabled(!value);
        }
    }

    private static char[] read(EditText field) {
        Editable text = field.getText();
        char[] result = new char[text == null ? 0 : text.length()];
        if (text != null) { text.getChars(0, text.length(), result, 0); }
        return result;
    }
}

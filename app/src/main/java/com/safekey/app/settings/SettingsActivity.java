package com.safekey.app.settings;

import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.text.Editable;
import android.text.method.PasswordTransformationMethod;
import android.widget.Toast;
import java.util.Arrays;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.alerts.AlertsActivity;
import com.safekey.app.auth.ChangeMasterPasswordActivity;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.generator.GeneratorActivity;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.storage.VaultOperations;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.securityui.SetupDecoyVaultActivity;
import com.safekey.app.securityui.SetupPanicModeActivity;
import com.safekey.app.securityui.SetupTotpActivity;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.vault.VaultActivity;

public class SettingsActivity extends ProtectedActivity {

    private static final String LEGACY_VAULT_NAME_PREFS = "safekey_vault_display";
    private static final String DEFAULT_VAULT_NAME = "Local Vault";
    private static final int MAX_VAULT_NAME_LENGTH = 64;

    private long vaultNameRequestGeneration;
    private String loadedVaultName;
    private boolean vaultNameLoaded;
    private AlertDialog renameDialog;
    private AlertDialog biometricDialog;
    private boolean biometricConfigured;
    private boolean biometricBusy;
    private long biometricUiGeneration;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);

        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        insetsController.setAppearanceLightStatusBars(false);
        insetsController.setAppearanceLightNavigationBars(false);

        setContentView(R.layout.activity_settings);

        // Remove the abandoned plaintext storage. The encrypted SQLCipher
        // vault_profile table is now the sole source of display names.
        deleteSharedPreferences(LEGACY_VAULT_NAME_PREFS);

        if (!refreshProtectedSettings()) {
            return;
        }
        refreshVaultDisplayName();

        findViewById(R.id.buttonSettingsEditName)
                .setOnClickListener(view -> showEditVaultNameDialog());

        SwitchCompat biometricSwitch = findViewById(R.id.switchSettingsBiometric);
        biometricSwitch.setOnClickListener(view -> {
            // A tap requests a change; it does not establish that the change succeeded.
            biometricSwitch.setChecked(biometricConfigured);
            if (!isAuthenticatedRealVault() || biometricBusy) {
                refreshBiometricSwitch();
                return;
            }
            if (biometricConfigured) {
                showDisableBiometricDialog();
            } else {
                showEnableBiometricDialog();
            }
        });

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(R.id.rootSettings),
                (view, windowInsets) -> {
                    Insets systemBars = windowInsets.getInsets(
                            WindowInsetsCompat.Type.systemBars());
                    view.setPadding(systemBars.left, systemBars.top,
                            systemBars.right, systemBars.bottom);
                    return windowInsets;
                });

        findViewById(R.id.rowSettingsDecoy).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            SafeKeyApplication app = (SafeKeyApplication) getApplication();
            if (SafeKeySession.getState() != SessionState.UNLOCKED
                    || app.getActiveVault() != SafeKeyApplication.ActiveVault.REAL) {
                return;
            }
            startActivity(new Intent(this, SetupDecoyVaultActivity.class));
        });

        findViewById(R.id.rowSettingsPanic).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            SafeKeyApplication app = (SafeKeyApplication) getApplication();
            if (SafeKeySession.getState() != SessionState.UNLOCKED
                    || app.getActiveVault() != SafeKeyApplication.ActiveVault.REAL) {
                return;
            }
            startActivity(new Intent(this, SetupPanicModeActivity.class));
        });

        // T39: Open the protected setup UI only from an unlocked REAL vault.
        // Enrollment remains unavailable until its authorized backend is integrated.
        findViewById(R.id.rowSettingsTotp).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity() || !isAuthenticatedRealVault()) {
                return;
            }
            startActivity(new Intent(this, SetupTotpActivity.class));
        });

        findViewById(R.id.rowSettingsChangePassword).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            SafeKeyApplication app = (SafeKeyApplication) getApplication();
            if (app.getActiveVault() != SafeKeyApplication.ActiveVault.REAL) {
                return;
            }
            startActivity(new Intent(this, ChangeMasterPasswordActivity.class));
        });

        findViewById(R.id.rowSettingsLockVault).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            invalidateVaultNameRequests();
            SafeKeySession.lock();
            Intent intent = new Intent(this, SignInActivity.class);
            intent.putExtra(SignInActivity.REQUIRE_MASTER_PASSWORD, true);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        });

        findViewById(R.id.navHome).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            Intent intent = new Intent(this, HomeActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
        });

        findViewById(R.id.navVault).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            Intent intent = new Intent(this, VaultActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
        });

        findViewById(R.id.navGenerator).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            Intent intent = new Intent(this, GeneratorActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
        });

        findViewById(R.id.navAlerts).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            Intent intent = new Intent(this, AlertsActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
        });

        findViewById(R.id.navSettings).setOnClickListener(view -> {
            SafeKeySession.recordActivity();
        });

        findViewById(R.id.rowSettingsAbout).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            new AlertDialog.Builder(this)
                    .setTitle(R.string.settings_about)
                    .setMessage(R.string.settings_about_message)
                    .setPositiveButton(R.string.settings_about_dialog_close,
                            (dialog, which) -> dialog.dismiss())
                    .show();
        });
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        if (!isFinishing() && refreshProtectedSettings()) {
            refreshVaultDisplayName();
        }
    }

    @Override
    protected void onRuntimeStop() {
        dismissRenameDialog();
        dismissBiometricDialog();
        biometricUiGeneration++;
        biometricBusy = false;
        invalidateVaultNameRequests();
        super.onRuntimeStop();
    }

    private boolean refreshProtectedSettings() {
        SafeKeyApplication application = (SafeKeyApplication) getApplication();
        SafeKeyApplication.ActiveVault activeVault = application.getActiveVault();
        boolean unlocked = SafeKeySession.getState() == SessionState.UNLOCKED;

        if (!unlocked || activeVault == SafeKeyApplication.ActiveVault.NONE) {
            invalidateVaultNameRequests();
            Intent signIn = new Intent(this, SignInActivity.class);
            signIn.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(signIn);
            finish();
            return false;
        }

        boolean real = activeVault == SafeKeyApplication.ActiveVault.REAL;
        int realOnlyVisibility = real ? View.VISIBLE : View.GONE;
        findViewById(R.id.textSettingsEmergencySection).setVisibility(realOnlyVisibility);
        findViewById(R.id.cardSettingsEmergency).setVisibility(realOnlyVisibility);
        findViewById(R.id.rowSettingsChangePassword).setVisibility(realOnlyVisibility);
        findViewById(R.id.dividerSettingsAccount).setVisibility(realOnlyVisibility);

        TextView decoyStatus = findViewById(R.id.textSettingsDecoyStatus);
        if (real) {
            try {
                boolean configured = application.getDecoyVaultCoordinator().hasDecoyVault();
                decoyStatus.setText(configured
                        ? R.string.settings_status_on
                        : R.string.settings_status_not_configured);
            } catch (RuntimeException error) {
                decoyStatus.setText(R.string.settings_status_unavailable);
            }
        } else {
            decoyStatus.setText(R.string.settings_status_unavailable);
        }

        refreshBiometricSwitch();
        return true;
    }

    private boolean isAuthenticatedRealVault() {
        SafeKeyApplication application = (SafeKeyApplication) getApplication();
        return !isFinishing() && !isDestroyed()
                && SafeKeySession.getState() == SessionState.UNLOCKED
                && application.getActiveVault() == SafeKeyApplication.ActiveVault.REAL;
    }

    private void refreshBiometricSwitch() {
        SwitchCompat biometricSwitch = findViewById(R.id.switchSettingsBiometric);
        if (!isAuthenticatedRealVault()) {
            biometricConfigured = false;
            biometricSwitch.setChecked(false);
            biometricSwitch.setEnabled(false);
            return;
        }
        try {
            SecureVaultCoordinator coordinator = ((SafeKeyApplication) getApplication())
                    .getSecureVaultCoordinator();
            biometricConfigured = coordinator.isBiometricUnlockConfigured(this);
            boolean available = "AVAILABLE".equals(coordinator.getBiometricAvailability(this).name());
            biometricSwitch.setChecked(biometricConfigured);
            // Disabling must remain possible even if biometrics are no longer available.
            biometricSwitch.setEnabled(!biometricBusy && (biometricConfigured || available));
        } catch (Exception error) {
            biometricSwitch.setEnabled(false);
            biometricSwitch.setChecked(false);
        }
    }

    private boolean isCurrentBiometricOperation(long request, long authentication) {
        return request == biometricUiGeneration && isAuthenticatedRealVault()
                && SafeKeySession.getManager().getAuthenticationGeneration() == authentication;
    }

    private void dismissBiometricDialog() {
        AlertDialog dialog = biometricDialog;
        biometricDialog = null;
        if (dialog != null) {
            // Clear the input synchronously before the window is dismissed.
            // AlertDialog dismissal listeners may run on a later UI message.
            EditText input = dialog.findViewById(R.id.editSettingsBiometricPassword);
            if (input != null && input.getText() != null) {
                input.getText().clear();
            }
            dialog.dismiss();
        }
    }

    private void showEnableBiometricDialog() {
        if (!SafeKeySession.recordActivity() || !isAuthenticatedRealVault()) {
            return;
        }
        dismissBiometricDialog();
        EditText passwordInput = new EditText(this);
        passwordInput.setId(R.id.editSettingsBiometricPassword);
        passwordInput.setSingleLine(true);
        passwordInput.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        passwordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
        passwordInput.setHint(R.string.t38_biometric_password_hint);

        int horizontal = getResources().getDimensionPixelSize(
                R.dimen.t38_rename_dialog_horizontal_padding);
        int vertical = getResources().getDimensionPixelSize(
                R.dimen.t38_rename_dialog_vertical_padding);
        FrameLayout container = new FrameLayout(this);
        container.setPadding(horizontal, vertical, horizontal, vertical);
        container.addView(passwordInput);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.t38_biometric_password_title)
                .setView(container)
                .setNegativeButton(R.string.t38_biometric_cancel, null)
                .setPositiveButton(R.string.t38_biometric_continue, null)
                .create();
        biometricDialog = dialog;
        dialog.setOnDismissListener(ignored -> {
            Editable editable = passwordInput.getText();
            if (editable != null) {
                editable.clear();
            }
            if (biometricDialog == dialog) {
                biometricDialog = null;
            }
            refreshBiometricSwitch();
        });
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    if (!SafeKeySession.recordActivity() || !isAuthenticatedRealVault()) {
                        dialog.dismiss();
                        return;
                    }
                    Editable editable = passwordInput.getText();
                    int length = editable == null ? 0 : editable.length();
                    if (length == 0) {
                        passwordInput.setError(getString(R.string.t38_biometric_password_required));
                        return;
                    }
                    char[] password = new char[length];
                    try {
                        for (int i = 0; i < length; i++) {
                            password[i] = editable.charAt(i);
                        }
                        // The coordinator makes its own password copy before returning.
                        long authentication = SafeKeySession.getManager()
                                .getAuthenticationGeneration();
                        long request = ++biometricUiGeneration;
                        biometricBusy = true;
                        dialog.dismiss();
                        refreshBiometricSwitch();
                        ((SafeKeyApplication) getApplication()).getSecureVaultCoordinator()
                                .enableBiometricUnlockForRealSession(this, password,
                                        getString(R.string.biometric_enable_title),
                                        getString(R.string.biometric_enable_message),
                                        new SecureVaultCoordinator.BiometricSetupCallback() {
                                            @Override
                                            public void onEnabled() {
                                                finishBiometricOperation(request, authentication, true);
                                            }

                                            @Override
                                            public void onError(String message) {
                                                finishBiometricOperation(request, authentication, false);
                                            }

                                            @Override
                                            public void onFailed() {
                                                // A failed scan can be retried by the system prompt.
                                            }
                                        });
                    } catch (RuntimeException error) {
                        biometricBusy = false;
                        refreshBiometricSwitch();
                        Toast.makeText(this, R.string.t38_biometric_enable_error,
                                Toast.LENGTH_LONG).show();
                    } finally {
                        Arrays.fill(password, '\0');
                        if (editable != null) {
                            editable.clear();
                        }
                    }
                }));
        dialog.show();
    }

    private void showDisableBiometricDialog() {
        if (!SafeKeySession.recordActivity() || !isAuthenticatedRealVault()) {
            return;
        }
        dismissBiometricDialog();
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.t38_biometric_disable_title)
                .setMessage(R.string.t38_biometric_disable_message)
                .setNegativeButton(R.string.t38_biometric_cancel, null)
                .setPositiveButton(R.string.t38_biometric_disable, (ignored, which) -> {
                    if (!SafeKeySession.recordActivity() || !isAuthenticatedRealVault()) {
                        return;
                    }
                    long authentication = SafeKeySession.getManager()
                            .getAuthenticationGeneration();
                    long request = ++biometricUiGeneration;
                    biometricBusy = true;
                    refreshBiometricSwitch();
                    try {
                        ((SafeKeyApplication) getApplication()).getSecureVaultCoordinator()
                                .disableBiometricUnlockForRealSession(this, new VaultDataService.SimpleCallback() {
                                    @Override
                                    public void onSuccess() {
                                        finishBiometricOperation(request, authentication, true);
                                    }

                                    @Override
                                    public void onError(Exception error) {
                                        finishBiometricOperation(request, authentication, false);
                                    }
                                });
                    } catch (RuntimeException error) {
                        finishBiometricOperation(request, authentication, false);
                    }
                })
                .create();
        biometricDialog = dialog;
        dialog.setOnDismissListener(ignored -> {
            if (biometricDialog == dialog) {
                biometricDialog = null;
            }
            refreshBiometricSwitch();
        });
        dialog.show();
    }

    private void finishBiometricOperation(long request, long authentication,
                                          boolean successful) {
        runOnUiThread(() -> {
            if (!isCurrentBiometricOperation(request, authentication)) {
                return;
            }
            biometricBusy = false;
            refreshBiometricSwitch();
            if (!successful) {
                Toast.makeText(this, R.string.t38_biometric_operation_error,
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    private void dismissRenameDialog() {
        AlertDialog dialog = renameDialog;
        renameDialog = null;
        if (dialog != null) {
            dialog.dismiss();
        }
    }

    private void invalidateVaultNameRequests() {
        vaultNameRequestGeneration++;
        vaultNameLoaded = false;
        loadedVaultName = null;
    }

    private boolean isCurrentVaultRequest(
            long requestGeneration,
            long authenticationGeneration,
            SafeKeyApplication.ActiveVault expectedVault,
            VaultOperations expectedOperations) {
        if (isFinishing() || isDestroyed()
                || requestGeneration != vaultNameRequestGeneration
                || SafeKeySession.getState() != SessionState.UNLOCKED
                || SafeKeySession.getManager().getAuthenticationGeneration()
                != authenticationGeneration) {
            return false;
        }
        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        if (expectedVault == SafeKeyApplication.ActiveVault.NONE
                || app.getActiveVault() != expectedVault) {
            return false;
        }
        try {
            return app.getActiveVaultOperations() == expectedOperations;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private void refreshVaultDisplayName() {
        final long requestGeneration = ++vaultNameRequestGeneration;
        vaultNameLoaded = false;
        loadedVaultName = null;
        TextView label = findViewById(R.id.textSettingsVaultName);
        label.setText(DEFAULT_VAULT_NAME);
        findViewById(R.id.buttonSettingsEditName).setEnabled(false);

        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        final SafeKeyApplication.ActiveVault expectedVault = app.getActiveVault();
        final long authenticationGeneration =
                SafeKeySession.getManager().getAuthenticationGeneration();
        final VaultOperations operations;
        try {
            operations = app.getActiveVaultOperations();
        } catch (RuntimeException exception) {
            return;
        }

        operations.getVaultDisplayName(new VaultDataService.ResultCallback<String>() {
            @Override
            public void onSuccess(String displayName) {
                if (!isCurrentVaultRequest(requestGeneration,
                        authenticationGeneration, expectedVault, operations)) {
                    return;
                }
                loadedVaultName = displayName;
                vaultNameLoaded = true;
                label.setText(displayName);
                findViewById(R.id.buttonSettingsEditName).setEnabled(true);
            }

            @Override
            public void onError(Exception exception) {
                if (!isCurrentVaultRequest(requestGeneration,
                        authenticationGeneration, expectedVault, operations)) {
                    return;
                }
                label.setText(R.string.settings_status_unavailable);
                findViewById(R.id.buttonSettingsEditName).setEnabled(false);
            }
        });
    }

    private void showEditVaultNameDialog() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        if (!SafeKeySession.recordActivity()
                || SafeKeySession.getState() != SessionState.UNLOCKED
                || !vaultNameLoaded
                || app.getActiveVault() == SafeKeyApplication.ActiveVault.NONE) {
            return;
        }

        final SafeKeyApplication.ActiveVault expectedVault = app.getActiveVault();
        final long authenticationGeneration =
                SafeKeySession.getManager().getAuthenticationGeneration();
        final VaultOperations operations;
        try {
            operations = app.getActiveVaultOperations();
        } catch (RuntimeException exception) {
            return;
        }
        final long requestGeneration = vaultNameRequestGeneration;
        if (!isCurrentVaultRequest(requestGeneration,
                authenticationGeneration, expectedVault, operations)) {
            return;
        }

        dismissRenameDialog();

        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS);
        input.setFilters(new android.text.InputFilter[]{
                new android.text.InputFilter.LengthFilter(MAX_VAULT_NAME_LENGTH)
        });
        input.setText(loadedVaultName);
        input.setSelection(input.length());

        int padding = getResources().getDimensionPixelSize(
                R.dimen.t38_rename_dialog_horizontal_padding);
        int verticalPadding = getResources().getDimensionPixelSize(
                R.dimen.t38_rename_dialog_vertical_padding);
        FrameLayout container = new FrameLayout(this);
        container.setPadding(padding, verticalPadding, padding, verticalPadding);
        container.addView(input);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.t38_rename_dialog_title)
                .setView(container)
                .setNegativeButton(R.string.t38_rename_cancel, null)
                // Override below to keep the dialog open on validation/save errors.
                .setPositiveButton(R.string.t38_rename_save, null)
                .create();

        renameDialog = dialog;
        dialog.setOnDismissListener(ignored -> {
            if (renameDialog == dialog) {
                renameDialog = null;
            }
        });

        dialog.setOnShowListener(ignored -> {
            Button save = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            save.setOnClickListener(view -> {
                if (!SafeKeySession.recordActivity()
                        || !isCurrentVaultRequest(requestGeneration,
                                authenticationGeneration, expectedVault, operations)) {
                    dialog.dismiss();
                    return;
                }

                String name = input.getText().toString().trim();
                if (name.isEmpty()) {
                    input.setError(getString(R.string.t38_rename_empty_error));
                    return;
                }
                if (name.length() > MAX_VAULT_NAME_LENGTH) {
                    input.setError(getString(R.string.t38_rename_too_long_error));
                    return;
                }

                save.setEnabled(false);
                input.setEnabled(false);
                try {
                    operations.updateVaultDisplayName(name,
                            new VaultDataService.ResultCallback<Integer>() {
                                @Override
                                public void onSuccess(Integer updatedRows) {
                                    if (!isCurrentVaultRequest(requestGeneration,
                                            authenticationGeneration, expectedVault,
                                            operations) || !dialog.isShowing()) {
                                        return;
                                    }
                                    if (updatedRows == null || updatedRows != 1) {
                                        onError(new IllegalStateException(
                                                "Vault name was not updated."));
                                        return;
                                    }
                                    dialog.dismiss();
                                    refreshVaultDisplayName();
                                }

                                @Override
                                public void onError(Exception exception) {
                                    if (!dialog.isShowing()
                                            || !isCurrentVaultRequest(requestGeneration,
                                                    authenticationGeneration,
                                                    expectedVault, operations)) {
                                        dialog.dismiss();
                                        return;
                                    }
                                    input.setEnabled(true);
                                    save.setEnabled(true);
                                    input.setError(getString(R.string.t38_rename_save_error));
                                }
                            });
                } catch (RuntimeException exception) {
                    if (dialog.isShowing()) {
                        input.setEnabled(true);
                        save.setEnabled(true);
                        input.setError(getString(R.string.t38_rename_save_error));
                    }
                }
            });
        });
        dialog.show();
    }
}

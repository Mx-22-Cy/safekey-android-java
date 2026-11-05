package com.safekey.app.settings;

import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
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
import com.safekey.app.securityui.SetupDecoyVaultActivity;
import com.safekey.app.securityui.SetupPanicModeActivity;
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

        SwitchCompat biometricSwitch = findViewById(R.id.switchSettingsBiometric);
        biometricSwitch.setEnabled(false);
        if (!real) {
            biometricSwitch.setChecked(false);
        } else {
            try {
                biometricSwitch.setChecked(application.getSecureVaultCoordinator()
                        .isBiometricUnlockConfigured(this));
            } catch (Exception error) {
                biometricSwitch.setChecked(false);
            }
        }
        return true;
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

        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS);
        input.setFilters(new android.text.InputFilter[]{
                new android.text.InputFilter.LengthFilter(MAX_VAULT_NAME_LENGTH)
        });
        input.setText(loadedVaultName);
        input.setSelection(input.length());

        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        int verticalPadding = (int) (8 * getResources().getDisplayMetrics().density);
        FrameLayout container = new FrameLayout(this);
        container.setPadding(padding, verticalPadding, padding, verticalPadding);
        container.addView(input);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Edit Vault Name")
                .setView(container)
                .setNegativeButton("Cancel", null)
                // Override below to keep the dialog open on validation/save errors.
                .setPositiveButton("Save", null)
                .create();

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
                    input.setError("Vault name cannot be empty.");
                    return;
                }
                if (name.length() > MAX_VAULT_NAME_LENGTH) {
                    input.setError("Vault name cannot exceed 64 characters.");
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
                                    input.setError("Could not save the vault name. Try again.");
                                }
                            });
                } catch (RuntimeException exception) {
                    if (dialog.isShowing()) {
                        input.setEnabled(true);
                        save.setEnabled(true);
                        input.setError("Could not save the vault name. Try again.");
                    }
                }
            });
        });
        dialog.show();
    }
}

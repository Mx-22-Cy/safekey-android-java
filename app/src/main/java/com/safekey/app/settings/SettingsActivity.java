package com.safekey.app.settings;

import android.os.Bundle;
import android.view.WindowManager;
import android.content.Intent;
import android.view.View;
import android.widget.TextView;
import android.content.SharedPreferences;
import android.widget.EditText;
import android.text.InputType;

import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.appcompat.widget.SwitchCompat;
import androidx.appcompat.app.AlertDialog;

import com.safekey.app.R;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.auth.ChangeMasterPasswordActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.vault.VaultActivity;
import com.safekey.app.generator.GeneratorActivity;
import com.safekey.app.alerts.AlertsActivity;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.securityui.SetupDecoyVaultActivity;
import com.safekey.app.securityui.SetupPanicModeActivity;

public class SettingsActivity extends ProtectedActivity {

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        if (!isFinishing() && refreshProtectedSettings()) {
            refreshVaultDisplayName();
        }
    }

    /**
     * Keep REAL-only controls hidden unless a live, authenticated REAL vault
     * is selected. Re-run when returning to Settings after another screen.
     */
    private boolean refreshProtectedSettings() {
        SafeKeyApplication application = (SafeKeyApplication) getApplication();
        SafeKeyApplication.ActiveVault activeVault = application.getActiveVault();
        boolean unlocked = SafeKeySession.getState()
                == com.safekey.app.session.logic.SessionState.UNLOCKED;

        if (!unlocked || activeVault == SafeKeyApplication.ActiveVault.NONE) {
            Intent signIn = new Intent(this, SignInActivity.class);
            signIn.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(signIn);
            finish();
            return false;
        }

        boolean real = activeVault == SafeKeyApplication.ActiveVault.REAL;
        int realOnlyVisibility = real ? View.VISIBLE : View.GONE;
        findViewById(R.id.textSettingsEmergencySection)
                .setVisibility(realOnlyVisibility);
        findViewById(R.id.cardSettingsEmergency)
                .setVisibility(realOnlyVisibility);
        findViewById(R.id.rowSettingsChangePassword)
                .setVisibility(realOnlyVisibility);
        findViewById(R.id.dividerSettingsAccount)
                .setVisibility(realOnlyVisibility);

        TextView decoyStatus = findViewById(R.id.textSettingsDecoyStatus);
        if (real) {
            try {
                boolean configured = application.getDecoyVaultCoordinator()
                        .hasDecoyVault();
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

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);

        // Prevent screenshots and screen recording on the Settings screen.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);

        // Match SafeKey's existing edge-to-edge screen configuration.
        WindowCompat.enableEdgeToEdge(getWindow());
        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.setAppearanceLightStatusBars(false);
        insetsController.setAppearanceLightNavigationBars(false);

        setContentView(R.layout.activity_settings);

        if (!refreshProtectedSettings()) {
            return;
        }

        refreshVaultDisplayName();

        findViewById(R.id.buttonSettingsEditName)
                .setOnClickListener(view -> showEditVaultNameDialog());

        // Keep Settings content clear of system bars.
        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(R.id.rootSettings),
                (view, windowInsets) -> {

                    Insets systemBars = windowInsets.getInsets(
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

        findViewById(R.id.rowSettingsDecoy).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            SafeKeyApplication app = (SafeKeyApplication) getApplication();

            if (SafeKeySession.getState()
                    != com.safekey.app.session.logic.SessionState.UNLOCKED
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

            if (SafeKeySession.getState()
                    != com.safekey.app.session.logic.SessionState.UNLOCKED
                    || app.getActiveVault() != SafeKeyApplication.ActiveVault.REAL) {
                return;
            }

            startActivity(new Intent(this, SetupPanicModeActivity.class));
        });

        findViewById(R.id.rowSettingsChangePassword).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            SafeKeyApplication currentVaultApplication =
                    (SafeKeyApplication) getApplication();

            if (currentVaultApplication.getActiveVault()
                    != SafeKeyApplication.ActiveVault.REAL) {
                return;
            }

            startActivity(new Intent(
                    SettingsActivity.this,
                    ChangeMasterPasswordActivity.class
            ));
        });

        findViewById(R.id.rowSettingsLockVault).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            SafeKeySession.lock();

            Intent intent = new Intent(
                    SettingsActivity.this,
                    SignInActivity.class
            );

            intent.putExtra(
                    SignInActivity.REQUIRE_MASTER_PASSWORD,
                    true
            );

            intent.addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK
                            | Intent.FLAG_ACTIVITY_CLEAR_TASK
            );

            startActivity(intent);
            finish();
        });

        findViewById(R.id.navHome).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Intent intent = new Intent(
                    SettingsActivity.this,
                    HomeActivity.class
            );

            intent.addFlags(
                    Intent.FLAG_ACTIVITY_CLEAR_TOP
                            | Intent.FLAG_ACTIVITY_SINGLE_TOP
            );

            startActivity(intent);
            finish();
        });

        findViewById(R.id.navVault).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Intent intent = new Intent(
                    SettingsActivity.this,
                    VaultActivity.class
            );

            intent.addFlags(
                    Intent.FLAG_ACTIVITY_CLEAR_TOP
                            | Intent.FLAG_ACTIVITY_SINGLE_TOP
            );

            startActivity(intent);
            finish();
        });

        findViewById(R.id.navGenerator).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Intent intent = new Intent(
                    SettingsActivity.this,
                    GeneratorActivity.class
            );

            intent.addFlags(
                    Intent.FLAG_ACTIVITY_CLEAR_TOP
                            | Intent.FLAG_ACTIVITY_SINGLE_TOP
            );

            startActivity(intent);
            finish();
        });

        findViewById(R.id.navAlerts).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Intent intent = new Intent(
                    SettingsActivity.this,
                    AlertsActivity.class
            );

            intent.addFlags(
                    Intent.FLAG_ACTIVITY_CLEAR_TOP
                            | Intent.FLAG_ACTIVITY_SINGLE_TOP
            );

            startActivity(intent);
            finish();
        });

        findViewById(R.id.navSettings).setOnClickListener(view -> {
            SafeKeySession.recordActivity();

            // Already on Settings; remain on this screen.
        });

        findViewById(R.id.rowSettingsAbout).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            new AlertDialog.Builder(SettingsActivity.this)
                    .setTitle(R.string.settings_about)
                    .setMessage(R.string.settings_about_message)
                    .setPositiveButton(
                            R.string.settings_about_dialog_close,
                            (dialog, which) -> dialog.dismiss()
                    )
                    .show();
        });

    }

    private static final String VAULT_NAME_PREFS = "safekey_vault_display";
    private static final String REAL_VAULT_NAME = "real_vault_name";
    private static final String DECOY_VAULT_NAME = "decoy_vault_name";

    private String getVaultNameKey() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();

        return app.getActiveVault() == SafeKeyApplication.ActiveVault.DECOY
                ? DECOY_VAULT_NAME
                : REAL_VAULT_NAME;
    }

    private void refreshVaultDisplayName() {
        SharedPreferences preferences =
                getSharedPreferences(VAULT_NAME_PREFS, MODE_PRIVATE);

        String name = preferences.getString(
                getVaultNameKey(),
                getString(R.string.settings_local_vault)
        );

        ((TextView) findViewById(R.id.textSettingsVaultName)).setText(name);
    }

    private void showEditVaultNameDialog() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();

        if (!SafeKeySession.recordActivity()
                || SafeKeySession.getState()
                != com.safekey.app.session.logic.SessionState.UNLOCKED
                || app.getActiveVault() == SafeKeyApplication.ActiveVault.NONE) {
            return;
        }

        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_CAP_WORDS);
        input.setFilters(new android.text.InputFilter[]{
                new android.text.InputFilter.LengthFilter(40)
        });

        SharedPreferences preferences =
                getSharedPreferences(VAULT_NAME_PREFS, MODE_PRIVATE);

        String key = getVaultNameKey();
        input.setText(preferences.getString(
                key,
                getString(R.string.settings_local_vault)
        ));

        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        int verticalPadding = (int) (8 * getResources().getDisplayMetrics().density);

        android.widget.FrameLayout container = new android.widget.FrameLayout(this);
        container.setPadding(padding, verticalPadding, padding, verticalPadding);
        container.addView(input);

        new AlertDialog.Builder(this)
                .setTitle("Edit Vault Name")
                .setView(container)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save", (dialog, which) -> {
                    if (!SafeKeySession.recordActivity()
                            || app.getActiveVault()
                            == SafeKeyApplication.ActiveVault.NONE
                            || !key.equals(getVaultNameKey())) {
                        return;
                    }

                    String name = input.getText().toString().trim();

                    if (name.isEmpty()) {
                        return;
                    }

                    preferences.edit().putString(key, name).apply();
                    refreshVaultDisplayName();
                })
                .show();
    }
}

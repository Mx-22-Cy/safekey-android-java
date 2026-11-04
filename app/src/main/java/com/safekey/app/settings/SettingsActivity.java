package com.safekey.app.settings;

import android.os.Bundle;
import android.view.WindowManager;
import android.content.Intent;
import android.view.View;
import android.widget.TextView;

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

public class SettingsActivity extends ProtectedActivity {

    @Override
    protected void onResume() {
        super.onResume();
        if (!isFinishing()) {
            refreshProtectedSettings();
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
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

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
}

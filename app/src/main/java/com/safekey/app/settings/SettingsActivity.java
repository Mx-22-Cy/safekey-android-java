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

        SafeKeyApplication currentApplication =
                (SafeKeyApplication) getApplication();

        boolean isRealVault =
                currentApplication.getActiveVault()
                        == SafeKeyApplication.ActiveVault.REAL;

        int emergencyVisibility =
                isRealVault ? View.VISIBLE : View.GONE;

        findViewById(R.id.textSettingsEmergencySection)
                .setVisibility(emergencyVisibility);

        findViewById(R.id.cardSettingsEmergency)
                .setVisibility(emergencyVisibility);

        findViewById(R.id.rowSettingsChangePassword)
                .setVisibility(isRealVault ? View.VISIBLE : View.GONE);

        findViewById(R.id.dividerSettingsAccount)
                .setVisibility(isRealVault ? View.VISIBLE : View.GONE);

        if (isRealVault) {
            TextView decoyStatus =
                    findViewById(R.id.textSettingsDecoyStatus);

            try {
                boolean configured =
                        currentApplication.getDecoyVaultCoordinator()
                                .hasDecoyVault();

                decoyStatus.setText(configured
                        ? R.string.settings_status_on
                        : R.string.settings_status_not_configured);

            } catch (Exception exception) {
                decoyStatus.setText(R.string.settings_status_unavailable);
            }
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

        SwitchCompat biometricSwitch =
                findViewById(R.id.switchSettingsBiometric);

        biometricSwitch.setEnabled(false);

        try {
            SecureVaultCoordinator coordinator =
                    ((SafeKeyApplication) getApplication())
                            .getSecureVaultCoordinator();

            boolean isRealBiometricVault =
                    ((SafeKeyApplication) getApplication()).getActiveVault()
                            == SafeKeyApplication.ActiveVault.REAL;

            if (isRealBiometricVault) {
                boolean configured =
                        coordinator.isBiometricUnlockConfigured(this);

                biometricSwitch.setChecked(configured);
            } else {
                biometricSwitch.setChecked(false);
            }

        } catch (Exception exception) {
            // Do not show an enabled state if the configuration cannot be read.
            biometricSwitch.setChecked(false);
        }
    }
}

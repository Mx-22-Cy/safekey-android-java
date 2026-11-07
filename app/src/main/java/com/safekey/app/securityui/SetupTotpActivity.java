package com.safekey.app.securityui;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

/**
 * T39 setup presentation. Secret material must only come from an authenticated
 * REAL-vault enrollment coordinator, never Intent extras or demonstration data.
 */
public final class SetupTotpActivity extends ProtectedActivity {
    private View manualKeyGroup;
    private Button manualKeyToggle;
    private Button copyKeyButton;
    private Button continueButton;
    private TextView manualKeyText;
    private boolean manualKeyAvailable;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        setContentView(R.layout.activity_setup_totp);

        View root = findViewById(R.id.rootSetupTotp);
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(root);

        manualKeyGroup = findViewById(R.id.groupTotpManualKey);
        manualKeyToggle = findViewById(R.id.buttonToggleTotpKey);
        copyKeyButton = findViewById(R.id.buttonCopyTotpKey);
        continueButton = findViewById(R.id.buttonContinueTotpSetup);
        manualKeyText = findViewById(R.id.textTotpManualKey);

        findViewById(R.id.buttonTotpBack).setOnClickListener(view -> {
            hideManualKey();
            finish();
        });
        findViewById(R.id.buttonCancelTotpSetup).setOnClickListener(view -> {
            hideManualKey();
            finish();
        });

        manualKeyToggle.setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity() || !requireRealVault()
                    || !manualKeyAvailable) {
                hideManualKey();
                return;
            }
            if (manualKeyGroup.getVisibility() == View.VISIBLE) {
                hideManualKey();
            } else {
                manualKeyGroup.setVisibility(View.VISIBLE);
                manualKeyToggle.setText(R.string.t39_hide_key);
                manualKeyToggle.setContentDescription(getString(R.string.t39_hide_key));
            }
        });

        // Keep all secret-dependent actions disabled until a session-bound
        // coordinator owns the pending enrollment and supplies its lifetime.
        manualKeyAvailable = false;
        hideManualKey();
        manualKeyToggle.setEnabled(false);
        copyKeyButton.setEnabled(false);
        copyKeyButton.setText(R.string.t39_copy_key);
        continueButton.setEnabled(false);
        continueButton.setText(R.string.t39_continue);
        findViewById(R.id.imageTotpQrCode).setVisibility(View.GONE);
        ((TextView) findViewById(R.id.textTotpQrPlaceholder))
                .setText(R.string.t39_not_enabled);
        ((TextView) findViewById(R.id.textTotpCountdown))
                .setText(R.string.t39_time_limit);

        requireRealVault();
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        requireRealVault();
    }

    @Override
    protected void onRuntimeStop() {
        hideManualKey();
        super.onRuntimeStop();
    }

    private void hideManualKey() {
        if (manualKeyGroup != null) {
            manualKeyGroup.setVisibility(View.GONE);
        }
        if (manualKeyToggle != null) {
            manualKeyToggle.setText(R.string.t39_show_key);
            manualKeyToggle.setContentDescription(getString(R.string.t39_show_key));
        }
        if (manualKeyText != null) {
            manualKeyText.setText(R.string.t39_manual_key_hidden);
        }
    }

    private boolean requireRealVault() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        if (SafeKeySession.getState() == SessionState.UNLOCKED
                && app.getActiveVault() == SafeKeyApplication.ActiveVault.REAL
                && !isFinishing() && !isDestroyed()) {
            return true;
        }
        hideManualKey();
        if (SafeKeySession.getState() != SessionState.UNLOCKED
                && !isFinishing() && !isDestroyed()) {
            Intent intent = new Intent(this, SignInActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
        }
        finish();
        return false;
    }
}

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
 * T39 presentation shell. Enrollment is intentionally unavailable until an
 * authenticated, REAL-vault TOTP coordinator is integrated by the security owner.
 * Never populate the QR/key from a sample or from an Intent extra.
 */
public final class SetupTotpActivity extends ProtectedActivity {

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

        findViewById(R.id.buttonTotpBack).setOnClickListener(view -> finish());
        findViewById(R.id.buttonCancelTotpSetup).setOnClickListener(view -> finish());

        // Safe UI-only shell: no credentials, QR or enrollment token are available.
        findViewById(R.id.imageTotpQrCode).setVisibility(View.GONE);
        findViewById(R.id.groupTotpManualKey).setVisibility(View.GONE);
        findViewById(R.id.buttonToggleTotpKey).setEnabled(false);
        findViewById(R.id.buttonCopyTotpKey).setEnabled(false);
        findViewById(R.id.buttonContinueTotpSetup).setEnabled(false);
        ((TextView) findViewById(R.id.textTotpQrPlaceholder))
                .setText(R.string.t39_not_enabled);

        requireRealVault();
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        requireRealVault();
    }

    private boolean requireRealVault() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        if (SafeKeySession.getState() == SessionState.UNLOCKED
                && app.getActiveVault() == SafeKeyApplication.ActiveVault.REAL
                && !isFinishing() && !isDestroyed()) {
            return true;
        }
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

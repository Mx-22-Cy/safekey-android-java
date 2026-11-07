package com.safekey.app.securityui;

import android.content.Intent;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.Button;

import androidx.appcompat.widget.AppCompatEditText;
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
 * T39 verification presentation shell. Confirmation stays disabled until the
 * security coordinator can supply and validate a session-owned pending setup.
 */
public final class VerifyTotpActivity extends ProtectedActivity {
    private AppCompatEditText codeInput;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        setContentView(R.layout.activity_verify_totp);

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(R.id.rootVerifyTotp), (view, insets) -> {
                    Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
                    view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
                    return insets;
                });
        ViewCompat.requestApplyInsets(findViewById(R.id.rootVerifyTotp));

        codeInput = findViewById(R.id.editVerifyTotpCode);
        Button enable = findViewById(R.id.buttonEnableTotpProtection);
        enable.setEnabled(false);
        findViewById(R.id.buttonVerifyTotpTopBack).setOnClickListener(view -> finish());
        findViewById(R.id.buttonVerifyTotpBack).setOnClickListener(view -> finish());
        requireRealVault();
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        requireRealVault();
    }

    @Override
    protected void onRuntimeStop() {
        clearCode();
        super.onRuntimeStop();
    }

    @Override
    protected void onRuntimeDestroy() {
        clearCode();
        super.onRuntimeDestroy();
    }

    private void clearCode() {
        if (codeInput != null && codeInput.getText() != null) {
            codeInput.getText().clear();
        }
    }

    private boolean requireRealVault() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        if (SafeKeySession.getState() == SessionState.UNLOCKED
                && app.getActiveVault() == SafeKeyApplication.ActiveVault.REAL
                && !isFinishing() && !isDestroyed()) {
            return true;
        }
        clearCode();
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

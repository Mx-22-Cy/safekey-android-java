package com.safekey.app.securityui;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;

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
 * T39 verification presentation. The security coordinator must validate the
 * code against a session-owned pending enrollment before enabling protection.
 */
public final class VerifyTotpActivity extends ProtectedActivity {
    private AppCompatEditText codeInput;
    private TextView errorText;
    private Button enableButton;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        setContentView(R.layout.activity_verify_totp);

        View root = findViewById(R.id.rootVerifyTotp);
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(root);

        codeInput = findViewById(R.id.editVerifyTotpCode);
        errorText = findViewById(R.id.textVerifyTotpError);
        enableButton = findViewById(R.id.buttonEnableTotpProtection);
        enableButton.setEnabled(false);
        errorText.setVisibility(View.GONE);
        ((TextView) findViewById(R.id.textVerifyTotpCountdown))
                .setText(R.string.t39_time_limit);

        // Validate only presentation/format. A six-digit input does NOT imply
        // a correct TOTP code or authorize an enrollment change.
        codeInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) { }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                errorText.setVisibility(View.GONE);
                enableButton.setEnabled(false);
            }

            @Override
            public void afterTextChanged(Editable s) { }
        });

        findViewById(R.id.buttonVerifyTotpTopBack).setOnClickListener(view -> {
            clearCode();
            finish();
        });
        findViewById(R.id.buttonVerifyTotpBack).setOnClickListener(view -> {
            clearCode();
            finish();
        });
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

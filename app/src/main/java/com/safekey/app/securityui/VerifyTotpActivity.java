package com.safekey.app.securityui;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.security.totp.TotpEnrollmentCoordinator;
import com.safekey.app.security.totp.TotpEnrollmentService;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.Arrays;
import java.util.Locale;

/** Verifies the SAME pending enrollment created in SetupTotpActivity. */
public final class VerifyTotpActivity extends ProtectedActivity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable ticker = new Runnable() {
        @Override public void run() {
            if (!visible || !requireRealVault()) { return; }
            if (!TotpConfirmationState.isConfirming()) { refreshCountdown(); }
            if (visible && setup != null && setup.isReady()) { main.postDelayed(this, 1000L); }
        }
    };
    private AppCompatEditText codeInput;
    private TextView errorText;
    private TextView countdown;
    private Button enableButton;
    private TotpEnrollmentCoordinator.Setup setup;
    private boolean visible;
    private boolean busy;
    private final TotpConfirmationState.Listener confirmationListener = this::onRetainedConfirmation;
    // Preserve the backend's terminal outcome instead of mislabeling it as a timeout.
    private int terminalMessage;

    @Override protected void onRuntimeCreate(Bundle state) {
        super.onRuntimeCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        setContentView(R.layout.activity_verify_totp);
        View root = findViewById(R.id.rootVerifyTotp);
        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(root);

        codeInput = findViewById(R.id.editVerifyTotpCode);
        errorText = findViewById(R.id.textVerifyTotpError);
        countdown = findViewById(R.id.textVerifyTotpCountdown);
        enableButton = findViewById(R.id.buttonEnableTotpProtection);
        enableButton.setEnabled(false);
        errorText.setVisibility(View.GONE);
        codeInput.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                errorText.setVisibility(View.GONE);
                updateButton();
            }
            @Override public void afterTextChanged(Editable s) { }
        });
        findViewById(R.id.buttonVerifyTotpTopBack).setOnClickListener(v -> goBack());
        findViewById(R.id.buttonVerifyTotpBack).setOnClickListener(v -> goBack());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() { goBack(); }
        });
        enableButton.setOnClickListener(v -> verifyCode());
        requireRealVault();
    }

    @Override protected void onRuntimeResume() {
        super.onRuntimeResume();
        visible = true;
        if (!requireRealVault()) { return; }
        setup = ((SafeKeyApplication) getApplication()).getTotpEnrollmentCoordinator().getPendingSetup();
        // Observe the application-scoped operation BEFORE interpreting a missing setup.
        // Successful confirmation closes the backend setup, so null is expected then.
        boolean outcomeWaiting = TotpConfirmationState.hasResult();
        TotpConfirmationState.observe(confirmationListener);
        if (outcomeWaiting) { return; }
        busy = TotpConfirmationState.isConfirming();
        if (busy) {
            enableButton.setEnabled(false);
            countdown.setText(R.string.t39_time_limit);
            return;
        }
        if (!isReady()) {
            endUnavailable();
            return;
        }
        updateButton();
        refreshCountdown();
        main.removeCallbacks(ticker);
        main.postDelayed(ticker, 1000L);
    }

    @Override protected void onRuntimeStop() {
        visible = false;
        TotpConfirmationState.stopObserving(confirmationListener);
        // The backend request continues and its result is retained across onStop.
        main.removeCallbacks(ticker);
        clearCode();
        enableButton.setEnabled(false);
        super.onRuntimeStop();
    }

    @Override protected void onRuntimeDestroy() {
        TotpConfirmationState.stopObserving(confirmationListener);
        clearCode();
        main.removeCallbacks(ticker);
        super.onRuntimeDestroy();
    }

    private boolean isReady() {
        if (terminalMessage != 0 || !visible || !requireRealVault() || setup == null
                || !setup.isSessionValid() || !setup.isReady()) { return false; }
        try { return setup.getRemainingMillis() > 0L; }
        catch (RuntimeException error) { return false; }
    }

    private void updateButton() {
        Editable value = codeInput.getText();
        enableButton.setEnabled(!busy && isReady() && value != null
                && value.length() == 6 && onlyDigits(value));
    }

    private static boolean onlyDigits(CharSequence code) {
        for (int i = 0; i < code.length(); i++) {
            if (code.charAt(i) < '0' || code.charAt(i) > '9') { return false; }
        }
        return true;
    }

    private void verifyCode() {
        if (busy || TotpConfirmationState.isConfirming() || !isReady()) { return; }
        Editable value = codeInput.getText();
        if (value == null || value.length() != 6 || !onlyDigits(value)) {
            showError(R.string.t39_invalid_format);
            return;
        }
        char[] code = new char[6];
        for (int i = 0; i < code.length; i++) { code[i] = value.charAt(i); }
        busy = true;
        enableButton.setEnabled(false);
        clearCode();
        try {
            // No Activity callback is captured: the result lives until a resumed
            // verifier consumes it, even if Android recreates this Activity.
            TotpConfirmationState.submit(setup, code);
        } catch (RuntimeException error) {
            busy = false;
            showError(R.string.t39_verification_failed);
            updateButton();
        } finally { Arrays.fill(code, '\0'); }
    }

    private void onRetainedConfirmation(TotpEnrollmentService.Confirmation result,
                                        int remaining, boolean failed) {
        if (!visible || isFinishing() || !requireRealVault()) { return; }
        busy = false;
        // Prevent showing a retained result under another REAL-vault session.
        if (!TotpConfirmationState.isSessionCurrent()) {
            TotpConfirmationState.discard();
            endEnrollment(R.string.t39_cancelled);
            return;
        }
        TotpConfirmationState.consume();
        if (failed || result == null) {
            showError(R.string.t39_verification_failed);
            updateButton();
            return;
        }
        switch (result) {
            case ENABLED:
                main.removeCallbacks(ticker);
                showSuccess();
                return;
            case INVALID_CODE:
                setup = ((SafeKeyApplication) getApplication())
                        .getTotpEnrollmentCoordinator().getPendingSetup();
                showError(getResources().getQuantityString(
                        R.plurals.t39_invalid_with_attempts, remaining, remaining));
                updateButton();
                return;
            case ATTEMPT_LIMIT_REACHED: endEnrollment(R.string.t39_attempt_limit); break;
            case EXPIRED: endEnrollment(R.string.t39_expired); break;
            case ALREADY_CONFIGURED: endEnrollment(R.string.t39_already_enabled); break;
            case CANCELLED: endEnrollment(R.string.t39_cancelled); break;
        }
    }

    private void showSuccess() {
        clearCode();
        enableButton.setEnabled(false);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.t39_success_title)
                .setMessage(R.string.t39_success_description)
                .setCancelable(false)
                .setPositiveButton(R.string.t39_done, (ignored, which) -> exitToSettings())
                .create();
        dialog.show();
        if (dialog.getWindow() != null) {
            dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    private void exitToSettings() {
        // Remove both enrollment screens from history after success.
        Intent intent = new Intent(this, com.safekey.app.settings.SettingsActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        startActivity(intent);
        finish();
    }

    private void refreshCountdown() {
        if (!isReady()) {
            endUnavailable();
            return;
        }
        try {
            long millis = setup.getRemainingMillis();
            if (millis <= 0L) {
                endEnrollment(R.string.t39_expired);
                return;
            }
            long seconds = (millis + 999L) / 1000L;
            String clock = String.format(Locale.US, "%d:%02d", seconds / 60L, seconds % 60L);
            countdown.setText(getString(R.string.t39_time_remaining, clock));
        } catch (RuntimeException error) {
            endUnavailable();
        }
    }

    private void endUnavailable() {
        if (terminalMessage != 0) {
            endEnrollment(terminalMessage);
            return;
        }
        // An unavailable setup may have been cancelled or invalidated, not timed out.
        // Distinguish a genuine timeout where the backend still exposes its clock.
        int reason = R.string.t39_cancelled;
        if (setup != null) {
            try {
                if (setup.isSessionValid() && setup.getRemainingMillis() <= 0L) {
                    reason = R.string.t39_expired;
                }
            } catch (RuntimeException ignored) {
                // Keep the conservative unavailable/cancelled result.
            }
        }
        endEnrollment(reason);
    }

    private void endEnrollment(int messageRes) {
        terminalMessage = messageRes;
        main.removeCallbacks(ticker);
        busy = false;
        enableButton.setEnabled(false);
        countdown.setText(R.string.t39_time_limit);
        clearCode();
        showError(messageRes);
    }

    private void showError(int id) { showError(getString(id)); }
    private void showError(String value) { errorText.setText(value); errorText.setVisibility(View.VISIBLE); }
    private void clearCode() {
        if (codeInput != null && codeInput.getText() != null) { codeInput.getText().clear(); }
    }
    private void goBack() {
        // Do not navigate away mid-confirmation and misreport an enabled vault.
        if (TotpConfirmationState.isConfirming()) { return; }
        clearCode();
        finish();
    }

    private boolean requireRealVault() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        if (SafeKeySession.getState() == SessionState.UNLOCKED
                && app.getActiveVault() == SafeKeyApplication.ActiveVault.REAL
                && !isFinishing() && !isDestroyed()) { return true; }
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

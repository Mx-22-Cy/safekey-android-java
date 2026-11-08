package com.safekey.app.securityui;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.security.totp.TotpEnrollmentCoordinator;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;

/** T39: the coordinator, not an Activity or Intent, owns the TOTP secret. */
public final class SetupTotpActivity extends ProtectedActivity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable ticker = new Runnable() {
        @Override public void run() {
            if (!visible || !requireRealVault()) { return; }
            // Preparation is asynchronous and may outlive an Activity instance.
            // Poll the coordinator while the screen is visible, even before it is ready.
            reconcileSetup();
        }
    };

    private TotpEnrollmentCoordinator.Setup setup;
    private AlertDialog passwordDialog;
    private View manualKeyGroup;
    private Button manualKeyToggle;
    private Button copyKeyButton;
    private Button continueButton;
    private TextView manualKeyText;
    private TextView errorText;
    private TextView qrPlaceholder;
    private TextView countdown;
    private ImageView qrImage;
    private Bitmap qrBitmap;
    private boolean visible;
    private boolean busy;
    private boolean passwordPromptShown;
    private int operationGeneration;
    private static final long CLIPBOARD_CLEAR_DELAY_MILLIS = 90_000L;
    private static final Handler CLIPBOARD_HANDLER = new Handler(Looper.getMainLooper());

    @Override protected void onRuntimeCreate(Bundle state) {
        super.onRuntimeCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        setContentView(R.layout.activity_setup_totp);
        View root = findViewById(R.id.rootSetupTotp);
        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(root);

        manualKeyGroup = findViewById(R.id.groupTotpManualKey);
        manualKeyToggle = findViewById(R.id.buttonToggleTotpKey);
        copyKeyButton = findViewById(R.id.buttonCopyTotpKey);
        continueButton = findViewById(R.id.buttonContinueTotpSetup);
        manualKeyText = findViewById(R.id.textTotpManualKey);
        errorText = findViewById(R.id.textTotpSetupError);
        qrPlaceholder = findViewById(R.id.textTotpQrPlaceholder);
        countdown = findViewById(R.id.textTotpCountdown);
        qrImage = findViewById(R.id.imageTotpQrCode);

        findViewById(R.id.buttonTotpBack).setOnClickListener(v -> cancelAndExit());
        findViewById(R.id.buttonCancelTotpSetup).setOnClickListener(v -> cancelAndExit());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() { cancelAndExit(); }
        });

        manualKeyToggle.setOnClickListener(v -> {
            if (!isReady()) { conceal(); return; }
            if (manualKeyGroup.getVisibility() == View.VISIBLE) {
                hideManualKey();
            } else {
                char[] key = null;
                try {
                    key = setup.copyBase32Secret();
                    manualKeyText.setText(new String(key));
                    manualKeyGroup.setVisibility(View.VISIBLE);
                    manualKeyToggle.setText(R.string.t39_hide_key);
                    manualKeyToggle.setContentDescription(getString(R.string.t39_hide_key));
                } catch (RuntimeException error) { showError(R.string.t39_expired); conceal(); }
                finally { if (key != null) { Arrays.fill(key, '\0'); } }
            }
        });
        copyKeyButton.setOnClickListener(v -> copyKey());
        continueButton.setOnClickListener(v -> {
            if (!isReady()) { return; }
            conceal();
            startActivity(new Intent(this, VerifyTotpActivity.class));
        });

        conceal();
        requireRealVault();
    }

    @Override protected void onRuntimeResume() {
        super.onRuntimeResume();
        visible = true;
        if (!requireRealVault()) { return; }
        reconcileSetup();
    }

    private void reconcileSetup() {
        if (!visible || !requireRealVault()) { return; }
        main.removeCallbacks(ticker);
        TotpEnrollmentCoordinator.Setup pending = coordinator().getPendingSetup();
        setup = pending;
        if (pending != null) {
            // Reattachment after recreation must not restart enrollment or generate a new seed.
            if (pending.isReady() && pending.isSessionValid()) {
                busy = false;
                if (qrBitmap == null) { renderReady(); }
                else {
                    refreshCountdown();
                    main.postDelayed(ticker, 1000L);
                }
            } else if (pending.isActive() && pending.isSessionValid()) {
                busy = true;
                conceal();
                showError(R.string.t39_preparing);
                main.postDelayed(ticker, 1000L);
            } else {
                busy = false;
                conceal();
                showError(R.string.t39_expired);
            }
        } else if (busy) {
            // Preparation completed with an error while the old Activity owned its callback.
            busy = false;
            passwordPromptShown = false;
            showPasswordDialogIfNeeded();
        } else {
            showPasswordDialogIfNeeded();
        }
    }

    private void showPasswordDialogIfNeeded() {
        if (visible && !busy && !passwordPromptShown && passwordDialog == null) {
            passwordPromptShown = true;
            showPasswordDialog();
        }
    }

    @Override protected void onRuntimeStop() {
        visible = false;
        main.removeCallbacks(ticker);
        dismissPasswordDialog();
        // A system-initiated dismissal is not a user cancellation.
        // Allow the white password confirmation dialog to reopen on resume.
        if (!busy) { passwordPromptShown = false; }
        conceal();
        super.onRuntimeStop();
    }

    @Override protected void onRuntimeDestroy() {
        visible = false;
        operationGeneration++;
        main.removeCallbacks(ticker);
        dismissPasswordDialog();
        conceal();
        super.onRuntimeDestroy();
    }

    private TotpEnrollmentCoordinator coordinator() {
        return ((SafeKeyApplication) getApplication()).getTotpEnrollmentCoordinator();
    }

    private void showPasswordDialog() {
        if (!visible || !requireRealVault() || isFinishing()) { return; }
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        input.setTransformationMethod(PasswordTransformationMethod.getInstance());
        input.setHint(R.string.t39_master_password_hint);
        input.setSaveEnabled(false);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        input.setFilterTouchesWhenObscured(true);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        FrameLayout wrapper = new FrameLayout(this);
        wrapper.setPadding(padding, padding / 2, padding, padding / 2);
        wrapper.addView(input);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.t39_master_password_title)
                .setMessage(R.string.t39_master_password_message)
                .setView(wrapper)
                .setNegativeButton(R.string.t39_cancel, null)
                .setPositiveButton(R.string.t39_continue, null)
                .create();
        passwordDialog = dialog;
        dialog.setOnDismissListener(unused -> {
            Editable text = input.getText();
            if (text != null) { text.clear(); }
            if (passwordDialog == dialog) { passwordDialog = null; }
        });
        dialog.setOnShowListener(unused -> {
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v -> {
                dialog.dismiss();
                cancelAndExit();
            });
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                if (!visible || !requireRealVault() || busy) { return; }
                Editable text = input.getText();
                if (text == null || text.length() == 0) {
                    input.setError(getString(R.string.t39_master_password_required));
                    return;
                }
                char[] password = new char[text.length()];
                for (int i = 0; i < password.length; i++) { password[i] = text.charAt(i); }
                try {
                    busy = true;
                    int operation = ++operationGeneration;
                    setup = coordinator().begin(password, new TotpEnrollmentCoordinator.SetupCallback() {
                        @Override public void onReady(TotpEnrollmentCoordinator.Setup ready) {
                            if (operation != operationGeneration) { return; }
                            busy = false;
                            setup = ready;
                            if (visible && !isFinishing() && requireRealVault()) { reconcileSetup(); }
                        }
                        @Override public void onError(Exception error) {
                            if (operation != operationGeneration) { return; }
                            busy = false;
                            setup = null;
                            if (visible && !isFinishing() && requireRealVault()) {
                                showError(R.string.t39_master_password_failed);
                                passwordPromptShown = true;
                                showPasswordDialog();
                            }
                        }
                    });
                    dialog.dismiss();
                    showError(R.string.t39_preparing);
                } catch (RuntimeException error) {
                    busy = false;
                    showError(R.string.t39_setup_failed);
                } finally {
                    Arrays.fill(password, '\0');
                    if (text != null) { text.clear(); }
                }
            });
        });
        dialog.show();
        if (dialog.getWindow() != null) {
            dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    private void dismissPasswordDialog() {
        AlertDialog dialog = passwordDialog;
        passwordDialog = null;
        if (dialog != null) { dialog.dismiss(); }
    }

    private boolean isReady() {
        if (!visible || !requireRealVault()
                || setup == null || !setup.isSessionValid() || !setup.isReady()) { return false; }
        try { return setup.getRemainingMillis() > 0L; }
        catch (RuntimeException error) { return false; }
    }

    private void renderReady() {
        if (!isReady()) { conceal(); showError(R.string.t39_expired); return; }
        try {
            // Never retain the sensitive URI in an Activity field or Intent.
            Bitmap rendered = TotpQrCodeRenderer.render(setup.getAuthenticatorUri(), 576);
            clearQr();
            qrBitmap = rendered;
            qrImage.setImageBitmap(rendered);
            qrImage.setVisibility(View.VISIBLE);
            qrPlaceholder.setVisibility(View.GONE);
            errorText.setVisibility(View.GONE);
            manualKeyToggle.setEnabled(true);
            copyKeyButton.setEnabled(true);
            continueButton.setEnabled(true);
            refreshCountdown();
            main.removeCallbacks(ticker);
            main.postDelayed(ticker, 1000L);
        } catch (Exception error) {
            conceal();
            showError(R.string.t39_setup_failed);
        }
    }

    private void refreshCountdown() {
        if (!isReady()) {
            conceal();
            showError(R.string.t39_expired);
            return;
        }
        try {
            long seconds = (setup.getRemainingMillis() + 999L) / 1000L;
            String clock = String.format(Locale.US, "%d:%02d", seconds / 60L, seconds % 60L);
            countdown.setText(getString(R.string.t39_time_remaining, clock));
        } catch (RuntimeException error) {
            conceal();
            showError(R.string.t39_expired);
        }
    }

    private void copyKey() {
        if (!isReady()) { return; }
        char[] key = null;
        try {
            key = setup.copyBase32Secret();
            String ownClipLabel = "SafeKey-TOTP-" + UUID.randomUUID();
            ClipData clip = ClipData.newPlainText(ownClipLabel, new String(key));
            if (Build.VERSION.SDK_INT >= 33) {
                android.os.PersistableBundle extras = new android.os.PersistableBundle();
                extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
                clip.getDescription().setExtras(extras);
            }
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(clip);
                // Do not retain the seed in the scheduled cleanup callback.
                CLIPBOARD_HANDLER.postDelayed(() -> {
                    try {
                        if (!clipboard.hasPrimaryClip()) { return; }
                        android.content.ClipDescription description = clipboard.getPrimaryClipDescription();
                        if (description == null || !ownClipLabel.contentEquals(description.getLabel())) {
                            return; // The user or another app replaced the clipboard.
                        }
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            clipboard.clearPrimaryClip();
                        } else {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""));
                        }
                    } catch (RuntimeException ignored) {
                        // Clipboard ownership can change while the app is backgrounded.
                    }
                }, CLIPBOARD_CLEAR_DELAY_MILLIS);
                Toast.makeText(this, R.string.t39_key_copied, Toast.LENGTH_SHORT).show();
            }
        } catch (RuntimeException error) { showError(R.string.t39_expired); }
        finally { if (key != null) { Arrays.fill(key, '\0'); } }
    }

    private void conceal() {
        hideManualKey();
        clearQr();
        if (manualKeyToggle != null) { manualKeyToggle.setEnabled(false); }
        if (copyKeyButton != null) { copyKeyButton.setEnabled(false); copyKeyButton.setText(R.string.t39_copy_key); }
        if (continueButton != null) { continueButton.setEnabled(false); continueButton.setText(R.string.t39_continue); }
        if (qrPlaceholder != null) { qrPlaceholder.setVisibility(View.VISIBLE); }
    }

    private void clearQr() {
        if (qrImage != null) { qrImage.setImageDrawable(null); qrImage.setVisibility(View.GONE); }
        if (qrBitmap != null) { qrBitmap.recycle(); qrBitmap = null; }
    }

    private void hideManualKey() {
        if (manualKeyGroup != null) { manualKeyGroup.setVisibility(View.GONE); }
        if (manualKeyToggle != null) {
            manualKeyToggle.setText(R.string.t39_show_key);
            manualKeyToggle.setContentDescription(getString(R.string.t39_show_key));
        }
        if (manualKeyText != null) { manualKeyText.setText(R.string.t39_manual_key_hidden); }
    }

    private void showError(int message) {
        if (errorText != null) { errorText.setText(message); errorText.setVisibility(View.VISIBLE); }
    }

    private void cancelAndExit() {
        operationGeneration++;
        busy = false;
        dismissPasswordDialog();
        try { coordinator().cancelPending(); } catch (RuntimeException ignored) { }
        conceal();
        finish();
    }

    private boolean requireRealVault() {
        SafeKeyApplication app = (SafeKeyApplication) getApplication();
        if (SafeKeySession.getState() == SessionState.UNLOCKED
                && app.getActiveVault() == SafeKeyApplication.ActiveVault.REAL
                && !isFinishing() && !isDestroyed()) { return true; }
        conceal();
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

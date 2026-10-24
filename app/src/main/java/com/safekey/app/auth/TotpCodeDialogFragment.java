package com.safekey.app.auth;

import android.app.Dialog;
import android.content.DialogInterface;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.Editable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;

import com.safekey.app.R;
import com.safekey.app.security.totp.TotpVerificationService;

import java.util.Arrays;

/** Holds only transient code-entry UI; the Activity owns authentication. */
public final class TotpCodeDialogFragment extends DialogFragment {

    public static final String TAG = "safekey_totp_signin";

    public interface Listener {
        boolean hasPendingTotpChallenge();
        void onTotpCodeSubmitted(char[] code);
        void onTotpCancelled();
    }

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable retryTick = this::updateRetry;
    private EditText codeInput;
    private TextView message;
    private Button verifyButton;
    private long retryUntilMillis;
    private boolean checking;
    private boolean silentClose;
    private boolean cancellationSent;

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        View content = LayoutInflater.from(requireContext())
                .inflate(R.layout.dialog_totp_code, null);

        codeInput = content.findViewById(R.id.editTotpCode);
        message = content.findViewById(R.id.textTotpCodeMessage);
        verifyButton = content.findViewById(R.id.buttonTotpVerify);
        Button cancelButton = content.findViewById(R.id.buttonTotpCancel);

        codeInput.setSaveEnabled(false);
        verifyButton.setOnClickListener(view -> submit());
        cancelButton.setOnClickListener(view -> dismiss());

        codeInput.setOnEditorActionListener((view, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                submit();
                return true;
            }
            return false;
        });

        return new AlertDialog.Builder(requireContext())
                .setView(content)
                .create();
    }

    @Override
    public void onStart() {
        super.onStart();

        Dialog dialog = getDialog();
        if (dialog == null) {
            return;
        }

        dialog.setCanceledOnTouchOutside(false);

        Window window = dialog.getWindow();
        if (window != null) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE
                    | WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));

            WindowManager.LayoutParams attributes = window.getAttributes();
            attributes.dimAmount = 0.72f;
            window.setAttributes(attributes);
            window.setSoftInputMode(
                    WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE);
        }

        if (codeInput != null) {
            codeInput.requestFocus();
        }
    }

    @Override
    public void onResume() {
        super.onResume();

        Listener listener = listener();
        if (listener == null || !listener.hasPendingTotpChallenge()) {
            dismissSilently();
        }
    }

    public void showResult(TotpVerificationService.Result result) {
        if (codeInput == null || message == null) {
            return;
        }

        if (result.getStatus() == TotpVerificationService.Status.VERIFIED) {
            setChecking(true);
            message.setText(R.string.totp_signin_opening);
        } else if (result.getStatus()
                == TotpVerificationService.Status.RETRY_LATER) {
            retryUntilMillis =
                    SystemClock.elapsedRealtime() + result.getRetryAfterMillis();
            setChecking(false);
            updateRetry();
        } else {
            setChecking(false);
            message.setText(R.string.totp_signin_invalid_code);
            codeInput.requestFocus();
        }
    }

    public void dismissSilently() {
        silentClose = true;
        clearInput();
        handler.removeCallbacks(retryTick);

        if (isAdded()) {
            dismissAllowingStateLoss();
        }
    }

    @Override
    public void onCancel(@NonNull DialogInterface dialog) {
        notifyCancellation();
        super.onCancel(dialog);
    }

    @Override
    public void onDismiss(@NonNull DialogInterface dialog) {
        notifyCancellation();
        super.onDismiss(dialog);
    }

    @Override
    public void onDestroyView() {
        handler.removeCallbacks(retryTick);
        clearInput();
        codeInput = null;
        message = null;
        verifyButton = null;
        super.onDestroyView();
    }

    private void submit() {
        if (codeInput == null || checking
                || retryUntilMillis > SystemClock.elapsedRealtime()) {
            return;
        }

        Listener listener = listener();
        if (listener == null || !listener.hasPendingTotpChallenge()) {
            dismissSilently();
            return;
        }

        Editable editable = codeInput.getText();
        if (editable == null || editable.length() != 6) {
            message.setText(R.string.totp_signin_invalid_format);
            return;
        }

        char[] code = new char[6];
        editable.getChars(0, 6, code, 0);
        clearInput();
        setChecking(true);
        message.setText(null);

        try {
            listener.onTotpCodeSubmitted(code);
        } finally {
            Arrays.fill(code, '\0');
        }
    }

    private void setChecking(boolean value) {
        checking = value;

        if (codeInput != null) {
            codeInput.setEnabled(
                    !value && retryUntilMillis <= SystemClock.elapsedRealtime());
        }

        if (verifyButton != null) {
            verifyButton.setEnabled(
                    !value && retryUntilMillis <= SystemClock.elapsedRealtime());
        }
    }

    private void updateRetry() {
        handler.removeCallbacks(retryTick);

        if (codeInput == null || message == null) {
            return;
        }

        long remaining = retryUntilMillis - SystemClock.elapsedRealtime();

        if (remaining <= 0L) {
            retryUntilMillis = 0L;
            setChecking(false);
            message.setText(null);
            return;
        }

        codeInput.setEnabled(false);
        verifyButton.setEnabled(false);

        int seconds = (int) ((remaining + 999L) / 1_000L);
        message.setText(getResources().getQuantityString(
                R.plurals.totp_signin_retry_wait, seconds, seconds));
        handler.postDelayed(retryTick, Math.min(1_000L, remaining));
    }

    private Listener listener() {
        return getActivity() instanceof Listener
                ? (Listener) getActivity()
                : null;
    }

    private void notifyCancellation() {
        clearInput();

        if (!silentClose && !cancellationSent) {
            cancellationSent = true;
            Listener listener = listener();

            if (listener != null) {
                listener.onTotpCancelled();
            }
        }
    }

    private void clearInput() {
        if (codeInput != null) {
            codeInput.setText("");
        }
    }
}

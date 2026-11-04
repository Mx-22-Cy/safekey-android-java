package com.safekey.app;

import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.auth.SignUpActivity;
import com.safekey.app.security.panic.PanicStartupGate;

/** A cold-start screen only; it cannot request or authorize a new wipe. */
public final class PanicStartupActivity extends AppCompatActivity {
    private AutoCloseable observer;
    private TextView message;
    private ProgressBar progress;
    private Button close;
    private Button retry;
    private boolean active;
    private boolean navigating;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(null);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        int padding = Math.round(24 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);
        progress = new ProgressBar(this);
        layout.addView(progress);
        message = new TextView(this);
        message.setGravity(Gravity.CENTER);
        message.setText(R.string.startup_preparing);
        layout.addView(message);
        retry = new Button(this);
        retry.setText(R.string.startup_retry);
        retry.setVisibility(View.GONE);
        retry.setOnClickListener(view -> {
            detachObserver();
            application().retryStartupRecovery();
            observeStartup();
            render();
        });
        layout.addView(retry);
        close = new Button(this);
        close.setText(R.string.startup_close);
        close.setVisibility(View.GONE);
        close.setOnClickListener(view -> finishAndRemoveTask());
        layout.addView(close);
        setContentView(layout);
    }

    @Override protected void onStart() {
        super.onStart();
        active = true;
        observeStartup();
        render();
    }

    @Override protected void onStop() {
        active = false;
        detachObserver();
        super.onStop();
    }

    private void observeStartup() {
        observer = application().getStartupGate().observe(() -> runOnUiThread(this::render));
    }

    private void detachObserver() {
        if (observer != null) {
            try { observer.close(); }
            catch (Exception ignored) { /* Local observer removal has no storage side effects. */ }
            observer = null;
        }
    }

    private SafeKeyApplication application() { return (SafeKeyApplication) getApplication(); }

    private void render() {
        if (!active || navigating || isFinishing() || isDestroyed()) { return; }
        PanicStartupGate.State state = application().getStartupGate().getState();
        if (state == PanicStartupGate.State.READY && application().isStartupRuntimeAvailable()) {
            Intent intent = new Intent(this, SignUpActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            navigating = true;
            try {
                startActivity(intent);
                application().completeStartupNavigation();
                finish();
            } catch (RuntimeException error) {
                navigating = false;
                showFailure();
            }
        } else if (state == PanicStartupGate.State.FAILED || state == PanicStartupGate.State.READY) {
            showFailure();
        } else {
            progress.setVisibility(View.VISIBLE);
            message.setText(R.string.startup_preparing);
            retry.setVisibility(View.GONE);
            close.setVisibility(View.GONE);
        }
    }

    private void showFailure() {
        progress.setVisibility(View.GONE);
        boolean canRetry = application().canRetryStartupRecovery();
        message.setText(canRetry ? R.string.startup_unavailable : R.string.startup_restart_required);
        retry.setVisibility(canRetry ? View.VISIBLE : View.GONE);
        close.setVisibility(View.VISIBLE);
    }
}

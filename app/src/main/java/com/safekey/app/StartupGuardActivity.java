package com.safekey.app;

import android.content.Intent;
import android.os.Bundle;
import android.view.WindowManager;

import androidx.appcompat.app.AppCompatActivity;

/** Prevent a restored screen from initializing against a recovering runtime. */
public abstract class StartupGuardActivity extends AppCompatActivity {
    private boolean runtimeScreenCreated;

    @Override protected final void onCreate(Bundle state) {
        SafeKeyApplication application = (SafeKeyApplication) getApplication();
        if (!application.canCreateRuntimeScreen()) {
            // Fulfil Android's lifecycle contract without restoring the old UI.
            super.onCreate(null);
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            Intent intent = new Intent(this, PanicStartupActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
            return;
        }
        runtimeScreenCreated = true;
        onRuntimeCreate(state);
    }

    protected void onRuntimeCreate(Bundle state) { super.onCreate(state); }

    @Override protected final void onStart() {
        if (runtimeScreenCreated) { onRuntimeStart(); } else { super.onStart(); }
    }
    protected void onRuntimeStart() { super.onStart(); }

    @Override protected final void onRestart() {
        if (runtimeScreenCreated) { onRuntimeRestart(); } else { super.onRestart(); }
    }
    protected void onRuntimeRestart() { super.onRestart(); }

    @Override protected final void onResume() {
        if (runtimeScreenCreated) { onRuntimeResume(); } else { super.onResume(); }
    }
    protected void onRuntimeResume() { super.onResume(); }

    @Override protected final void onPostResume() {
        if (runtimeScreenCreated) { onRuntimePostResume(); } else { super.onPostResume(); }
    }
    protected void onRuntimePostResume() { super.onPostResume(); }

    @Override protected final void onPause() {
        if (runtimeScreenCreated) { onRuntimePause(); } else { super.onPause(); }
    }
    protected void onRuntimePause() { super.onPause(); }

    @Override protected final void onStop() {
        if (runtimeScreenCreated) { onRuntimeStop(); } else { super.onStop(); }
    }
    protected void onRuntimeStop() { super.onStop(); }

    @Override protected final void onDestroy() {
        if (runtimeScreenCreated) { onRuntimeDestroy(); } else { super.onDestroy(); }
    }
    protected void onRuntimeDestroy() { super.onDestroy(); }

    @Override protected final void onPostCreate(Bundle state) {
        if (runtimeScreenCreated) { onRuntimePostCreate(state); } else { super.onPostCreate(null); }
    }
    protected void onRuntimePostCreate(Bundle state) { super.onPostCreate(state); }

    @Override protected final void onSaveInstanceState(Bundle state) {
        if (runtimeScreenCreated) { onRuntimeSaveInstanceState(state); }
        else { super.onSaveInstanceState(state); }
    }
    protected void onRuntimeSaveInstanceState(Bundle state) { super.onSaveInstanceState(state); }

    @Override protected final void onRestoreInstanceState(Bundle state) {
        if (runtimeScreenCreated) { onRuntimeRestoreInstanceState(state); }
        else { super.onRestoreInstanceState(new Bundle()); }
    }
    protected void onRuntimeRestoreInstanceState(Bundle state) { super.onRestoreInstanceState(state); }

    @Override protected final void onNewIntent(Intent intent) {
        if (runtimeScreenCreated) { onRuntimeNewIntent(intent); } else { super.onNewIntent(intent); }
    }
    protected void onRuntimeNewIntent(Intent intent) { super.onNewIntent(intent); }

    @Override public final void onUserInteraction() {
        if (runtimeScreenCreated) { onRuntimeUserInteraction(); } else { super.onUserInteraction(); }
    }
    protected void onRuntimeUserInteraction() { super.onUserInteraction(); }
}

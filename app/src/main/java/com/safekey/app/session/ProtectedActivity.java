package com.safekey.app.session;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.WindowManager;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.auth.SignInActivity;

public abstract class ProtectedActivity
        extends com.safekey.app.StartupGuardActivity {

    @Override
    protected void onRuntimeCreate(Bundle state) {
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        super.onRuntimeCreate(state);
    }

    private final Handler inactivityHandler =
            new Handler(
                    Looper.getMainLooper()
            );

    private final Runnable inactivityTimeoutCheck =
            this::checkInactivityTimeout;

    private boolean redirectingToSignIn;
    private SafeKeySession.TimeoutRegistration timeoutRegistration;

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();

        stopObservingTimeoutChanges();
        timeoutRegistration = SafeKeySession.observeTimeoutChanges(
                this::checkInactivityTimeout);
        checkInactivityTimeout();
    }

    @Override
    protected void onRuntimePause() {
        stopObservingTimeoutChanges();
        inactivityHandler.removeCallbacks(
                inactivityTimeoutCheck
        );

        super.onRuntimePause();
    }

    @Override
    protected void onRuntimeDestroy() {
        stopObservingTimeoutChanges();
        inactivityHandler.removeCallbacks(
                inactivityTimeoutCheck
        );

        super.onRuntimeDestroy();
    }

    private void stopObservingTimeoutChanges() {
        if (timeoutRegistration != null) {
            timeoutRegistration.close();
            timeoutRegistration = null;
        }
    }

    @Override
    public void onRuntimeUserInteraction() {
        super.onRuntimeUserInteraction();

        if (!SafeKeySession.recordActivity()) {
            redirectToSignIn();

            return;
        }

        scheduleNextTimeoutCheck();
    }

    private void checkInactivityTimeout() {
        long remainingMillis =
                SafeKeySession
                        .getManager()
                        .getRemainingInactivityMillis();

        if (remainingMillis <= 0L) {
            redirectToSignIn();

            return;
        }

        scheduleNextTimeoutCheck();
    }

    private void scheduleNextTimeoutCheck() {
        inactivityHandler.removeCallbacks(
                inactivityTimeoutCheck
        );

        long remainingMillis =
                SafeKeySession
                        .getManager()
                        .getRemainingInactivityMillis();

        if (remainingMillis <= 0L) {
            redirectToSignIn();

            return;
        }

        inactivityHandler.postDelayed(
                inactivityTimeoutCheck,
                remainingMillis
        );
    }

    private void redirectToSignIn() {
        inactivityHandler.removeCallbacks(
                inactivityTimeoutCheck
        );

        if (redirectingToSignIn
                || isFinishing()) {

            return;
        }

        redirectingToSignIn =
                true;

        Intent intent =
                new Intent(
                        ProtectedActivity.this,
                        SignInActivity.class
                );

        intent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK
                        | Intent.FLAG_ACTIVITY_CLEAR_TASK
        );

        startActivity(
                intent
        );

        finish();
    }
}

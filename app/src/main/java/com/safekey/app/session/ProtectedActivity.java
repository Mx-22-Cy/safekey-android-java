package com.safekey.app.session;

import android.content.Intent;
import android.os.Handler;
import android.os.Looper;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.auth.SignInActivity;

public abstract class ProtectedActivity
        extends AppCompatActivity {

    private final Handler inactivityHandler =
            new Handler(
                    Looper.getMainLooper()
            );

    private final Runnable inactivityTimeoutCheck =
            this::checkInactivityTimeout;

    private boolean redirectingToSignIn;

    @Override
    protected void onResume() {
        super.onResume();

        checkInactivityTimeout();
    }

    @Override
    protected void onPause() {
        inactivityHandler.removeCallbacks(
                inactivityTimeoutCheck
        );

        super.onPause();
    }

    @Override
    protected void onDestroy() {
        inactivityHandler.removeCallbacks(
                inactivityTimeoutCheck
        );

        super.onDestroy();
    }

    @Override
    public void onUserInteraction() {
        super.onUserInteraction();

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

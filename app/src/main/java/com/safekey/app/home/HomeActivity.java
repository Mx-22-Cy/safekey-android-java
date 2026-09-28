package com.safekey.app.home;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.vault.VaultActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionDestination;
import com.safekey.app.session.logic.SessionNavigation;

public class HomeActivity extends AppCompatActivity {

    private static final int PREVIEW_SECURITY_SCORE = 82;

    private SecurityScoreView securityScoreView;

    private TextView textAtRiskCount;
    private TextView textBreachCount;
    private TextView textCredentialCount;
    private TextView textFavoriteCount;
    private TextView textSecureNoteCount;

    @Override
    protected void onCreate(
            Bundle savedInstanceState
    ) {

        super.onCreate(savedInstanceState);

        WindowCompat.enableEdgeToEdge(
                getWindow()
        );

        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.setAppearanceLightStatusBars(
                false
        );

        insetsController.setAppearanceLightNavigationBars(
                false
        );

        setContentView(
                R.layout.activity_home
        );

        View rootHome =
                findViewById(
                        R.id.rootHome
                );

        ViewCompat.setOnApplyWindowInsetsListener(
                rootHome,
                (view, windowInsets) -> {

                    Insets systemBars =
                            windowInsets.getInsets(
                                    WindowInsetsCompat.Type.systemBars()
                            );

                    view.setPadding(
                            systemBars.left,
                            systemBars.top,
                            systemBars.right,
                            systemBars.bottom
                    );

                    return windowInsets;
                }
        );

        ViewCompat.requestApplyInsets(
                rootHome
        );

        securityScoreView =
                findViewById(
                        R.id.securityScoreView
                );

        textAtRiskCount =
                findViewById(
                        R.id.textAtRiskCount
                );

        textBreachCount =
                findViewById(
                        R.id.textBreachCount
                );

        textCredentialCount =
                findViewById(
                        R.id.textCredentialCount
                );

        textFavoriteCount =
                findViewById(
                        R.id.textFavoriteCount
                );

        textSecureNoteCount =
                findViewById(
                        R.id.textSecureNoteCount
                );

        Button buttonOpenVault =
                findViewById(
                        R.id.buttonOpenVault
                );

        Button buttonAddCredential =
                findViewById(
                        R.id.buttonAddCredential
                );

        View navHome =
                findViewById(
                        R.id.navHome
                );

        View navVault =
                findViewById(
                        R.id.navVault
                );

        View navAlerts =
                findViewById(
                        R.id.navAlerts
                );

        View navSettings =
                findViewById(
                        R.id.navSettings
                );

        showPreviewData();

        navHome.setOnClickListener(
                view ->
                        requireUnlockedSession()
        );

        navVault.setOnClickListener(
                view ->
                        navigateToVault()
        );

        navAlerts.setOnClickListener(
                view ->
                        showProtectedPlaceholder(
                                R.string.home_alerts_navigation_pending
                        )
        );

        navSettings.setOnClickListener(
                view ->
                        showProtectedPlaceholder(
                                R.string.home_settings_navigation_pending
                        )
        );

        buttonOpenVault.setOnClickListener(
                view ->
                        navigateToVault()
        );

        buttonAddCredential.setOnClickListener(
                view ->
                        showProtectedPlaceholder(
                                R.string.home_credential_creation_pending
                        )
        );
    }

    @Override
    protected void onResume() {

        super.onResume();

        /*
         * Maryam's SessionNavigation defines:
         *
         * UNLOCKED -> HOME
         * LOCKED   -> LOCK_SCREEN
         *
         * SignInActivity currently represents the lock-screen
         * destination in the Android UI.
         *
         * The real authentication/security integration is not
         * connected yet, so production code intentionally does
         * not call unlockAfterAuthentication() from the current
         * placeholder Sign In actions.
         */
        if (!isSessionUnlocked()) {
            navigateToSignIn();
        }
    }

    @Override
    public void onUserInteraction() {

        super.onUserInteraction();

        /*
         * recordActivity() performs the inactivity-timeout check.
         * If it returns false, the session is locked or has expired,
         * so Home must no longer remain visible.
         */
        if (!SafeKeySession.recordActivity()) {
            navigateToSignIn();
        }
    }

    private boolean isSessionUnlocked() {

        SessionDestination destination =
                SessionNavigation.destinationFor(
                        SafeKeySession.getState()
                );

        return destination
                == SessionDestination.HOME;
    }

    private boolean requireUnlockedSession() {

        /*
         * Use recordActivity() as the final session decision.
         *
         * It checks timeout state and returns false if the
         * session is already locked or expires during the check.
         */
        if (!SafeKeySession.recordActivity()) {

            navigateToSignIn();

            return false;
        }

        return true;
    }

    private void showProtectedPlaceholder(
            int messageResource
    ) {

        if (!requireUnlockedSession()) {
            return;
        }

        Toast.makeText(
                this,
                messageResource,
                Toast.LENGTH_SHORT
        ).show();
    }

    private void navigateToVault() {

        if (!requireUnlockedSession()) {
            return;
        }

        Intent intent =
                new Intent(
                        HomeActivity.this,
                        VaultActivity.class
                );

        startActivity(
                intent
        );
    }

    private void navigateToSignIn() {

        if (isFinishing()) {
            return;
        }

        Toast.makeText(
                this,
                R.string.home_session_locked,
                Toast.LENGTH_SHORT
        ).show();

        Intent intent =
                new Intent(
                        HomeActivity.this,
                        SignInActivity.class
                );

        intent.addFlags(
                Intent.FLAG_ACTIVITY_CLEAR_TOP
        );

        startActivity(
                intent
        );

        finish();
    }

    private void showPreviewData() {

        /*
         * UI PREVIEW DATA ONLY.
         *
         * These values are intentionally not read
         * from the real encrypted vault yet.
         */

        securityScoreView.setScore(
                PREVIEW_SECURITY_SCORE
        );

        textAtRiskCount.setText(
                R.string.home_preview_at_risk_count
        );

        textBreachCount.setText(
                R.string.home_preview_breach_count
        );

        textCredentialCount.setText(
                R.string.home_preview_credential_count
        );

        textFavoriteCount.setText(
                R.string.home_preview_favorite_count
        );

        textSecureNoteCount.setText(
                R.string.home_preview_secure_note_count
        );

        /*
         * TODO(Security integration):
         *
         * Replace the preview Security Score,
         * at-risk count and breach-alert count
         * with values produced by the approved
         * security layer.
         *
         * Breach checking must use the project's
         * privacy-preserving HIBP k-anonymity design.
         *
         * Never send plaintext passwords
         * to an external breach service.
         *
         * TODO(Data/UI integration):
         *
         * Replace credential, favorite and note
         * preview counts with values obtained through
         * VaultDataService after secure vault unlock.
         */
    }
}
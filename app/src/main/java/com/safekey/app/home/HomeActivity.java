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

        /*
         * Home is already the selected destination.
         * Record the interaction if the vault session
         * is still valid.
         */
        navHome.setOnClickListener(
                view ->
                        requireUnlockedSession()
        );

        /*
         * Vault UI is not implemented yet.
         * We still enforce the active session before
         * allowing the protected navigation action.
         */
        navVault.setOnClickListener(
                view ->
                        showProtectedPlaceholder(
                                R.string.home_vault_navigation_pending
                        )
        );

        /*
         * Alerts UI is not implemented yet.
         */
        navAlerts.setOnClickListener(
                view ->
                        showProtectedPlaceholder(
                                R.string.home_alerts_navigation_pending
                        )
        );

        /*
         * Settings UI is not implemented yet.
         */
        navSettings.setOnClickListener(
                view ->
                        showProtectedPlaceholder(
                                R.string.home_settings_navigation_pending
                        )
        );

        /*
         * Open Vault follows the same protected
         * navigation rule as the Vault tab.
         */
        buttonOpenVault.setOnClickListener(
                view ->
                        showProtectedPlaceholder(
                                R.string.home_vault_navigation_pending
                        )
        );

        /*
         * Credential creation is protected by the
         * current vault session. The actual credential
         * screen will be connected when that UI exists.
         */
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
         * SignInActivity currently represents the
         * lock-screen destination in the Android UI.
         */
        if (!isSessionUnlocked()) {

            navigateToSignIn();
        }
    }

    @Override
    public void onUserInteraction() {

        super.onUserInteraction();

        /*
         * Touch/key interaction refreshes Maryam's
         * inactivity timer only while the session is
         * still unlocked.
         */
        SafeKeySession.recordActivity();
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

        if (!isSessionUnlocked()) {

            navigateToSignIn();

            return false;
        }

        return SafeKeySession.recordActivity();
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
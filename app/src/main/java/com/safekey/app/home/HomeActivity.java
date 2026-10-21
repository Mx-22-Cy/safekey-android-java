package com.safekey.app.home;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.safekey.app.session.ProtectedActivity;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.vault.VaultActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.generator.GeneratorActivity;

public class HomeActivity extends ProtectedActivity {

    private static final int PREVIEW_SECURITY_SCORE = 82;

    private SecurityScoreView securityScoreView;

    private TextView textAtRiskCount;
    private TextView textBreachCount;
    private TextView textCredentialCount;
    private TextView textFavoriteCount;
    private TextView textSecureNoteCount;

    private boolean countsActive;
    private long countRequestGeneration;

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

        View navGenerator =
                findViewById(
                        R.id.navGenerator
                );

        View navAlerts =
                findViewById(
                        R.id.navAlerts
                );

        View navSettings =
                findViewById(
                        R.id.navSettings
                );

        showPreviewSecurityData();
        showVaultCountsUnavailable();

        navHome.setOnClickListener(
                view -> {
                    if (requireUnlockedSession()) {
                        refreshVaultCounts();
                    }
                }
        );

        navVault.setOnClickListener(
                view ->
                        navigateToVault()
        );

        navGenerator.setOnClickListener(
                view -> {

                    if (!requireUnlockedSession()) {
                        return;
                    }

                    Intent intent =
                            new Intent(
                                    HomeActivity.this,
                                    GeneratorActivity.class
                            );

                    startActivity(
                            intent
                    );
                }
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

        if (isFinishing() || isDestroyed()) {
            return;
        }

        countsActive = true;
        refreshVaultCounts();
    }

    @Override
    protected void onPause() {
        countsActive = false;
        countRequestGeneration++;
        showVaultCountsUnavailable();

        super.onPause();
    }

    @Override
    protected void onDestroy() {
        countsActive = false;
        countRequestGeneration++;

        super.onDestroy();
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

    private void showPreviewSecurityData() {

        /*
         * Security-panel preview values remain until the
         * security dashboard integration is complete.
         * Credential, favorite, and note totals are loaded separately.
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
         */
    }

    private void refreshVaultCounts() {
        final long requestGeneration = ++countRequestGeneration;

        showVaultCountsUnavailable();

        if (!canApplyVaultCounts(requestGeneration)) {
            return;
        }

        try {
            SecureVaultCoordinator coordinator =
                    ((SafeKeyApplication) getApplication())
                            .getSecureVaultCoordinator();

            coordinator.getVaultCounts(
                    new VaultDataService.ResultCallback<VaultCounts>() {
                        @Override
                        public void onSuccess(VaultCounts counts) {
                            if (!canApplyVaultCounts(requestGeneration)) {
                                return;
                            }

                            textCredentialCount.setText(
                                    getString(
                                            R.string.home_vault_count_value,
                                            counts.getCredentialCount()
                                    )
                            );

                            textFavoriteCount.setText(
                                    getString(
                                            R.string.home_vault_count_value,
                                            counts.getFavoriteCount()
                                    )
                            );

                            textSecureNoteCount.setText(
                                    getString(
                                            R.string.home_vault_count_value,
                                            counts.getSecureNoteCount()
                                    )
                            );
                        }

                        @Override
                        public void onError(Exception exception) {
                            showVaultCountsError(requestGeneration);
                        }
                    }
            );
        } catch (RuntimeException exception) {
            showVaultCountsError(requestGeneration);
        }
    }

    private boolean canApplyVaultCounts(long requestGeneration) {
        return countsActive
                && requestGeneration == countRequestGeneration
                && !isFinishing()
                && !isDestroyed()
                && SafeKeySession.getManager()
                .getRemainingInactivityMillis() > 0L;
    }

    private void showVaultCountsUnavailable() {
        textCredentialCount.setText(R.string.home_vault_count_unavailable);
        textFavoriteCount.setText(R.string.home_vault_count_unavailable);
        textSecureNoteCount.setText(R.string.home_vault_count_unavailable);
    }

    private void showVaultCountsError(long requestGeneration) {
        if (!canApplyVaultCounts(requestGeneration)) {
            return;
        }

        showVaultCountsUnavailable();

        Toast.makeText(
                this,
                R.string.home_vault_counts_error,
                Toast.LENGTH_SHORT
        ).show();
    }
}

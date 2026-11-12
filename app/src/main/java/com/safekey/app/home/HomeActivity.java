package com.safekey.app.home;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
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
import com.safekey.app.security.results.AndroidCredentialSecurity;
import com.safekey.app.security.results.CredentialSecurityController;
import com.safekey.app.security.results.CredentialSecuritySummary;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.model.VaultCounts;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.auth.MasterPasswordHealth;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.vault.VaultActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.generator.GeneratorActivity;
import com.safekey.app.alerts.AlertsActivity;
import com.safekey.app.settings.SettingsActivity;

public class HomeActivity extends ProtectedActivity {

    private CredentialSecurityController securityController;
    private TextView textSecurityStatus;
    private TextView textSecurityCoverage;
    private TextView textSecurityReview;
    private View securityBanner;

    private final Runnable masterPasswordHealthChanged = this::refreshMasterPasswordHealth;
    private MasterPasswordHealth masterPasswordHealth;
    private View layoutMasterPasswordHealth;
    private TextView textMasterPasswordHealthTitle;
    private TextView textMasterPasswordHealth;
    private Button buttonCheckMasterPassword;

    private SecurityScoreView securityScoreView;

    private TextView textAtRiskCount;
    private TextView textBreachCount;
    private TextView textCredentialCount;
    private TextView textFavoriteCount;
    private TextView textSecureNoteCount;

    private boolean countsActive;
    private long countRequestGeneration;

    @Override
    protected void onRuntimeCreate(
            Bundle savedInstanceState
    ) {

        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);

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

        masterPasswordHealth = ((SafeKeyApplication) getApplication()).getMasterPasswordHealth();
        layoutMasterPasswordHealth = findViewById(R.id.layoutMasterPasswordHealth);
        textMasterPasswordHealthTitle = findViewById(R.id.textMasterPasswordHealthTitle);
        textMasterPasswordHealth = findViewById(R.id.textMasterPasswordHealth);
        buttonCheckMasterPassword = findViewById(R.id.buttonCheckMasterPassword);
        buttonCheckMasterPassword.setOnClickListener(view -> {
            if (!requireUnlockedSession()) { return; }
            SafeKeySession.lock();
            Intent intent = new Intent(this, SignInActivity.class);
            intent.putExtra(SignInActivity.REQUIRE_MASTER_PASSWORD, true);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        });

        securityController = AndroidCredentialSecurity.create(
                ((SafeKeyApplication) getApplication()).getSecureVaultCoordinator(), false);
        textSecurityStatus = findViewById(R.id.textHomeSecurityStatus);
        textSecurityCoverage = findViewById(R.id.textHomeSecurityCoverage);
        textSecurityReview = findViewById(R.id.textHomeSecurityReview);
        securityBanner = findViewById(R.id.layoutHomeSecurityBanner);
        findViewById(R.id.textReview).setOnClickListener(
                view -> findViewById(R.id.navAlerts).performClick());
        showSecurityUnavailable(R.string.security_loading);
        showVaultCountsUnavailable();

        navHome.setOnClickListener(
                view -> {
                    if (requireUnlockedSession()) {
                        refreshVaultCounts();
                        refreshSecurityResults();
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
                view -> {

                    if (!requireUnlockedSession()) {
                        return;
                    }

                    Intent intent =
                            new Intent(
                                    HomeActivity.this,
                                    AlertsActivity.class
                            );

                    startActivity(intent);
                }
        );

        navSettings.setOnClickListener(view -> {
            if (!requireUnlockedSession()) {
                return;
            }

            Intent intent = new Intent(
                    HomeActivity.this,
                    SettingsActivity.class
            );

            startActivity(intent);
            finish();
        });

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
    protected void onRuntimeResume() {
        super.onRuntimeResume();

        if (isFinishing() || isDestroyed()) {
            return;
        }

        countsActive = true;
        masterPasswordHealth.addListener(masterPasswordHealthChanged);
        refreshMasterPasswordHealth();
        refreshVaultCounts();
        refreshSecurityResults();
    }

    @Override
    protected void onRuntimePause() {
        securityController.stop();
        showSecurityUnavailable(R.string.security_not_checked);
        countsActive = false;
        masterPasswordHealth.removeListener(masterPasswordHealthChanged);
        textMasterPasswordHealth.setText(null);
        countRequestGeneration++;
        showVaultCountsUnavailable();

        super.onRuntimePause();
    }

    @Override
    protected void onRuntimeDestroy() {
        if (securityController != null) { securityController.close(); }
        countsActive = false;
        countRequestGeneration++;

        super.onRuntimeDestroy();
    }

    private void refreshMasterPasswordHealth() {
        if (!countsActive || isFinishing() || isDestroyed()
                || SafeKeySession.getManager().getRemainingInactivityMillis() <= 0L) { return; }
        MasterPasswordCheckStatus status = masterPasswordHealth.getStatus();
        boolean pending = status == MasterPasswordCheckStatus.PENDING;
        boolean checked = status == MasterPasswordCheckStatus.CHECKED;
        layoutMasterPasswordHealth.setVisibility(checked ? View.GONE : View.VISIBLE);
        textMasterPasswordHealth.setText(checked ? null
                : getString(pending ? R.string.t30_master_password_pending_description
                            : R.string.master_password_breached_notice));
        textMasterPasswordHealthTitle.setText(pending
                ? R.string.master_password_pending_title
                : R.string.master_password_breached_title);
        buttonCheckMasterPassword.setVisibility(pending ? View.VISIBLE : View.GONE);
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

    private void refreshSecurityResults() {
        showSecurityUnavailable(R.string.security_loading);
        try {
            securityController.load(new CredentialSecurityController.Listener() {
                @Override public void onResults(CredentialSecuritySummary summary) {
                    if (!countsActive || isFinishing() || isDestroyed()) { return; }
                    textAtRiskCount.setText(getString(R.string.home_vault_count_value, summary.getAtRiskCount()));
                    textBreachCount.setText(getString(R.string.home_vault_count_value, summary.getBreachCount()));
                    if (summary.hasScore()) {
                        securityScoreView.setScore(summary.getScore());
                        textSecurityStatus.setText(summary.getAtRiskCount() == 0
                                ? R.string.security_no_known_issues : R.string.security_needs_attention);
                    } else {
                        int label = summary.getAvailability() == CredentialSecuritySummary.Availability.EMPTY
                                ? R.string.security_no_credentials
                                : summary.getAvailability() == CredentialSecuritySummary.Availability.UNAVAILABLE
                                  ? R.string.security_unavailable : R.string.security_not_checked;
                        securityScoreView.setUnavailable(getString(label));
                        textSecurityStatus.setText(label);
                    }
                    textSecurityStatus.setTextColor(getColor(summary.hasScore()
                            && summary.getAtRiskCount() == 0 ? R.color.auth_accent
                            : R.color.auth_text_primary));
                    String coverage = getString(R.string.security_saved_basis);
                    if (summary.getIncompleteCount() > 0) {
                        coverage += "\n" + getResources().getQuantityString(R.plurals.security_incomplete_count,
                                summary.getIncompleteCount(), summary.getIncompleteCount());
                    }
                    textSecurityCoverage.setText(coverage);
                    if (summary.getTotalCount() == 0) {
                        textSecurityReview.setText(R.string.security_review_empty);
                    } else if (summary.getAtRiskCount() > 0) {
                        textSecurityReview.setText(getResources().getQuantityString(R.plurals.security_risk_count,
                                summary.getAtRiskCount(), summary.getAtRiskCount()));
                    } else if (summary.getIncompleteCount() > 0) {
                        textSecurityReview.setText(getResources().getQuantityString(R.plurals.security_incomplete_count,
                                summary.getIncompleteCount(), summary.getIncompleteCount()));
                    } else {
                        textSecurityReview.setText(R.string.security_review_clean);
                    }
                    securityBanner.setBackgroundResource(summary.getAtRiskCount() > 0
                            ? R.drawable.dashboard_alert_banner_bg : R.drawable.dashboard_card_bg);
                }
                @Override public void onError(Exception error) {
                    if (countsActive && !isFinishing() && !isDestroyed()) {
                        showSecurityUnavailable(R.string.security_unavailable);
                    }
                }
            }, false);
        } catch (RuntimeException error) {
            showSecurityUnavailable(R.string.security_unavailable);
        }
    }

    private void showSecurityUnavailable(int label) {
        securityScoreView.setUnavailable(getString(label));
        textAtRiskCount.setText("\u2014");
        textBreachCount.setText("\u2014");
        textSecurityStatus.setText(label);
        textSecurityStatus.setTextColor(getColor(R.color.auth_text_primary));
        textSecurityCoverage.setText(R.string.security_score_method);
        textSecurityReview.setText(label);
        securityBanner.setBackgroundResource(R.drawable.dashboard_card_bg);
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

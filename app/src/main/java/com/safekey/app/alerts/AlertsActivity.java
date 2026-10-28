package com.safekey.app.alerts;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.generator.GeneratorActivity;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.security.results.AndroidCredentialSecurity;
import com.safekey.app.security.results.CredentialSecurityController;
import com.safekey.app.security.results.CredentialSecurityItem;
import com.safekey.app.security.results.CredentialSecuritySummary;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.vault.CredentialDetailsActivity;
import com.safekey.app.vault.VaultActivity;

public class AlertsActivity extends ProtectedActivity {
    private enum AlertFilter { ALL, BREACHED, ATTENTION, PASSED }
    private AlertFilter selectedFilter = AlertFilter.ALL;
    private CredentialSecurityController controller;
    private CredentialSecuritySummary summary;
    private boolean activityStarted;
    private boolean loading;
    private boolean failed;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        WindowCompat.enableEdgeToEdge(getWindow());
        WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView())
                .setAppearanceLightStatusBars(false);
        WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView())
                .setAppearanceLightNavigationBars(false);
        setContentView(R.layout.activity_alerts);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.rootAlerts), (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(findViewById(R.id.rootAlerts));
        controller = AndroidCredentialSecurity.create(((SafeKeyApplication) getApplication())
                .getSecureVaultCoordinator(), true);
        setupNavigation();
        int[] ids = {R.id.filterAlertsAll, R.id.filterAlertsBreached,
                R.id.filterAlertsAttention, R.id.filterAlertsPassed};
        for (int i = 0; i < ids.length; i++) {
            final AlertFilter filter = AlertFilter.values()[i];
            findViewById(ids[i]).setOnClickListener(view -> {
                if (activityStarted && SafeKeySession.recordActivity()) {
                    selectedFilter = filter;
                    refreshAlertsDashboard();
                }
            });
        }
        findViewById(R.id.buttonAlertsRetryAll).setOnClickListener(view -> {
            if (activityStarted && !loading && !failed && SafeKeySession.recordActivity()) {
                controller.checkAll();
            }
        });
    }

    @Override protected void onRuntimeStart() {
        super.onRuntimeStart();
        activityStarted = true;
        if (SafeKeySession.getState() == SessionState.UNLOCKED) { loadCredentials(); }
    }

    private void loadCredentials() {
        loading = true;
        failed = false;
        summary = null;
        refreshAlertsDashboard();
        try {
            controller.load(new CredentialSecurityController.Listener() {
                @Override public void onResults(CredentialSecuritySummary result) {
                    if (!canDisplay()) { return; }
                    loading = false;
                    failed = false;
                    summary = result;
                    refreshAlertsDashboard();
                }
                @Override public void onError(Exception error) {
                    if (!canDisplay()) { return; }
                    loading = false;
                    failed = true;
                    summary = null;
                    refreshAlertsDashboard();
                }
            }, true);
        } catch (RuntimeException error) {
            loading = false;
            failed = true;
            refreshAlertsDashboard();
        }
    }

    private boolean canDisplay() {
        return activityStarted && !isFinishing() && !isDestroyed()
                && SafeKeySession.getState() == SessionState.UNLOCKED;
    }

    private void refreshAlertsDashboard() {
        LinearLayout breached = findViewById(R.id.layoutAlertsBreachedCards);
        LinearLayout attention = findViewById(R.id.layoutAlertsAttentionCards);
        LinearLayout passed = findViewById(R.id.layoutAlertsPassedCards);
        breached.removeAllViews();
        attention.removeAllViews();
        passed.removeAllViews();
        findViewById(R.id.layoutAlertsBreachedSection).setVisibility(View.GONE);
        findViewById(R.id.layoutAlertsAttentionSection).setVisibility(View.GONE);
        findViewById(R.id.layoutAlertsPassedSection).setVisibility(View.GONE);
        TextView empty = findViewById(R.id.textAlertsEmptyState);
        TextView totals = findViewById(R.id.textAlertsSecuritySummary);
        empty.setOnClickListener(null);
        empty.setClickable(false);
        findViewById(R.id.buttonAlertsRetryAll).setEnabled(canDisplay() && !loading && !failed
                && summary != null && summary.getTotalCount() > 0);
        updateAlertFilterStyling();
        if (!canDisplay()) {
            empty.setText(null);
            empty.setVisibility(View.GONE);
            totals.setText(null);
            return;
        }
        if (loading || failed || summary == null) {
            empty.setText(failed ? R.string.alerts_load_error : R.string.alerts_loading);
            empty.setVisibility(View.VISIBLE);
            totals.setText(failed ? R.string.security_unavailable : R.string.security_loading);
            if (failed) {
                empty.setOnClickListener(view -> {
                    if (canDisplay() && SafeKeySession.recordActivity()) { loadCredentials(); }
                });
            }
            return;
        }
        totals.setText(getString(R.string.security_alert_summary,
                getResources().getQuantityString(R.plurals.security_risk_count,
                        summary.getAtRiskCount(), summary.getAtRiskCount()),
                getResources().getQuantityString(R.plurals.security_incomplete_count,
                        summary.getIncompleteCount(), summary.getIncompleteCount()),
                getString(R.string.security_saved_basis)));
        for (CredentialSecurityItem item : summary.getItems()) {
            LinearLayout parent = item.getGroup() == CredentialSecurityItem.Group.BREACHED ? breached
                    : item.getGroup() == CredentialSecurityItem.Group.ATTENTION ? attention : passed;
            addCard(parent, item);
        }
        findViewById(R.id.layoutAlertsBreachedSection).setVisibility(breached.getChildCount() > 0
                && (selectedFilter == AlertFilter.ALL || selectedFilter == AlertFilter.BREACHED)
                ? View.VISIBLE : View.GONE);
        findViewById(R.id.layoutAlertsAttentionSection).setVisibility(attention.getChildCount() > 0
                && (selectedFilter == AlertFilter.ALL || selectedFilter == AlertFilter.ATTENTION)
                ? View.VISIBLE : View.GONE);
        findViewById(R.id.layoutAlertsPassedSection).setVisibility(passed.getChildCount() > 0
                && (selectedFilter == AlertFilter.ALL || selectedFilter == AlertFilter.PASSED)
                ? View.VISIBLE : View.GONE);
        boolean noCards = selectedFilter == AlertFilter.ALL ? summary.getTotalCount() == 0
                : selectedFilter == AlertFilter.BREACHED ? breached.getChildCount() == 0
                : selectedFilter == AlertFilter.ATTENTION ? attention.getChildCount() == 0
                : passed.getChildCount() == 0;
        empty.setVisibility(noCards ? View.VISIBLE : View.GONE);
        empty.setText(selectedFilter == AlertFilter.ALL ? R.string.alerts_empty_all
                : selectedFilter == AlertFilter.BREACHED ? R.string.alerts_empty_breached
                : selectedFilter == AlertFilter.ATTENTION ? R.string.alerts_empty_attention
                : R.string.alerts_empty_passed);
    }

    private void addCard(LinearLayout parent, CredentialSecurityItem item) {
        View card = LayoutInflater.from(this).inflate(R.layout.item_alert_credential, parent, false);
        ((TextView) card.findViewById(R.id.textAlertCredentialName)).setText(item.getTitle());
        int background = item.getGroup() == CredentialSecurityItem.Group.BREACHED
                ? R.drawable.alerts_breached_card_bg
                : item.getGroup() == CredentialSecurityItem.Group.ATTENTION
                ? R.drawable.alerts_attention_card_bg : R.drawable.alerts_passed_card_bg;
        card.setBackgroundResource(background);
        TextView status = card.findViewById(R.id.textAlertCredentialStatus);
        switch (item.getBreachStatus()) {
            case BREACHED: status.setText(R.string.alerts_status_breached); break;
            case NOT_FOUND: status.setText(R.string.alerts_status_passed); break;
            case ERROR: status.setText(R.string.alerts_status_error); break;
            default: status.setText(R.string.alerts_status_not_checked);
        }
        TextView occurrences = card.findViewById(R.id.textAlertOccurrences);
        if (item.getOccurrences() > 0L && item.isBreached()) {
            long count = item.getOccurrences();
            occurrences.setText(getResources().getQuantityString(R.plurals.alerts_occurrences,
                    count == 1L ? 1 : 2, count));
            occurrences.setVisibility(View.VISIBLE);
        }
        String detail;
        if (item.isMissingPassword()) { detail = getString(R.string.security_missing_password); }
        else if (item.getStrengthScore() < 0) { detail = getString(R.string.security_strength_unavailable); }
        else {
            int[] strengthLabels = {R.string.security_strength_0, R.string.security_strength_1,
                    R.string.security_strength_2, R.string.security_strength_3, R.string.security_strength_4};
            detail = getString(R.string.security_strength_format,
                    getString(strengthLabels[item.getStrengthScore()]));
        }
        if (item.isReused()) { detail += "\n" + getString(R.string.security_reused); }
        if (item.isChecking()) { detail += "\n" + getString(R.string.security_checking); }
        if (item.isRefreshFailed()) { detail += "\n" + getString(R.string.security_refresh_failed); }
        ((TextView) card.findViewById(R.id.textAlertCredentialRiskDetails)).setText(detail);
        card.setOnClickListener(view -> {
            if (!canDisplay() || !SafeKeySession.recordActivity()) { return; }
            Intent intent = new Intent(this, CredentialDetailsActivity.class);
            intent.putExtra(CredentialDetailsActivity.EXTRA_ID, item.getId());
            startActivity(intent);
        });
        if (parent.getChildCount() > 0) {
            LinearLayout.LayoutParams params = (LinearLayout.LayoutParams) card.getLayoutParams();
            params.topMargin = getResources().getDimensionPixelSize(R.dimen.alerts_card_spacing);
            card.setLayoutParams(params);
        }
        parent.addView(card);
    }

    private void updateAlertFilterStyling() {
        int[] ids = {R.id.filterAlertsAll, R.id.filterAlertsBreached,
                R.id.filterAlertsAttention, R.id.filterAlertsPassed};
        for (int i = 0; i < ids.length; i++) {
            TextView chip = findViewById(ids[i]);
            boolean selected = selectedFilter == AlertFilter.values()[i];
            chip.setBackgroundResource(selected ? R.drawable.vault_chip_active_bg
                    : R.drawable.vault_chip_inactive_bg);
            chip.setTextColor(getColor(selected ? R.color.vault_chip_text_dark : R.color.vault_text_secondary));
            chip.setSelected(selected);
        }
    }

    @Override protected void onRuntimeStop() {
        activityStarted = false;
        controller.stop();
        summary = null;
        refreshAlertsDashboard();
        super.onRuntimeStop();
    }

    @Override protected void onRuntimeDestroy() {
        if (controller != null) { controller.close(); }
        super.onRuntimeDestroy();
    }

    private void setupNavigation() {

        View navHome = findViewById(R.id.navHome);

        navHome.setOnClickListener(view -> {

            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Intent intent =
                    new Intent(
                            AlertsActivity.this,
                            HomeActivity.class
                    );

            startActivity(intent);
            finish();
        });


        View navVault = findViewById(R.id.navVault);

        navVault.setOnClickListener(view -> {

            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Intent intent =
                    new Intent(
                            AlertsActivity.this,
                            VaultActivity.class
                    );

            startActivity(intent);
            finish();
        });


        View navGenerator = findViewById(R.id.navGenerator);

        navGenerator.setOnClickListener(view -> {

            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Intent intent =
                    new Intent(
                            AlertsActivity.this,
                            GeneratorActivity.class
                    );

            startActivity(intent);
            finish();
        });

        View navAlerts = findViewById(R.id.navAlerts);

        navAlerts.setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }

            // Already on Security Alerts; remain on this screen.
        });

        View navSettings = findViewById(R.id.navSettings);

        navSettings.setOnClickListener(view -> {

            if (!SafeKeySession.recordActivity()) {
                return;
            }

            Toast.makeText(
                    AlertsActivity.this,
                    R.string.home_settings_navigation_pending,
                    Toast.LENGTH_SHORT
            ).show();
        });
    }
}

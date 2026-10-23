package com.safekey.app.alerts;

import android.os.Bundle;
import android.content.Intent;
import android.view.View;
import android.widget.Toast;
import android.view.LayoutInflater;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.safekey.app.R;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.vault.VaultActivity;
import com.safekey.app.generator.GeneratorActivity;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.vault.CredentialDetailsActivity;
import com.safekey.app.breach.HibpRangeClient;
import com.safekey.app.breach.PasswordBreachCoordinator;
import com.safekey.app.breach.PasswordBreachResult;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

public class AlertsActivity extends ProtectedActivity {
    private SecureVaultCoordinator secureVaultCoordinator;
    private HibpRangeClient hibpRangeClient;
    private PasswordBreachCoordinator passwordBreachCoordinator;
    private final Map<Long, PasswordBreachCoordinator.Request> activeBreachRequests =
            new HashMap<>();
    private final Map<Long, PasswordBreachResult> breachResults =
            new HashMap<>();
    private final List<Credential> loadedCredentials =
            new ArrayList<>();

    private enum AlertFilter {
        ALL,
        BREACHED,
        ATTENTION,
        PASSED
    }
    private AlertFilter selectedFilter = AlertFilter.ALL;
    private boolean activityStarted = false;
    private boolean credentialsLoading = false;
    private boolean credentialsLoadFailed = false;
    private int credentialLoadGeneration = 0;
    private long nextBreachCheckId = 0;
    private final Map<Long, Long> latestBreachCheckIds =
            new HashMap<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        secureVaultCoordinator =
                ((SafeKeyApplication) getApplication())
                        .getSecureVaultCoordinator();

        hibpRangeClient = new HibpRangeClient();

        passwordBreachCoordinator =
                new PasswordBreachCoordinator(hibpRangeClient);

        WindowCompat.enableEdgeToEdge(getWindow());

        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.setAppearanceLightStatusBars(false);
        insetsController.setAppearanceLightNavigationBars(false);

        setContentView(R.layout.activity_alerts);

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(R.id.rootAlerts),
                (view, windowInsets) -> {

                    Insets systemBars = windowInsets.getInsets(
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

        setupNavigation();
        setupAlertFilters();
        findViewById(R.id.buttonAlertsRetryAll).setOnClickListener(
                view -> retryAttentionCredentials()
        );
    }

    @Override
    protected void onStart() {
        super.onStart();

        activityStarted = true;

        if (SafeKeySession.getState() == SessionState.UNLOCKED) {
            loadCredentials();
        }
    }

    private void loadCredentials() {

        credentialsLoading = true;
        credentialsLoadFailed = false;

        TextView loadingMessage =
                findViewById(R.id.textAlertsEmptyState);

        loadingMessage.setOnClickListener(null);
        loadingMessage.setClickable(false);

        loadingMessage.setText(R.string.alerts_loading);
        loadingMessage.setVisibility(View.VISIBLE);

        findViewById(R.id.layoutAlertsBreachedSection)
                .setVisibility(View.GONE);

        findViewById(R.id.layoutAlertsAttentionSection)
                .setVisibility(View.GONE);

        findViewById(R.id.layoutAlertsPassedSection)
                .setVisibility(View.GONE);

        final int thisLoadGeneration = ++credentialLoadGeneration;
        secureVaultCoordinator.getCredentials(
                new VaultDataService.ResultCallback<List<Credential>>() {

                    @Override
                    public void onSuccess(List<Credential> credentials) {

                        if (!activityStarted
                                || thisLoadGeneration != credentialLoadGeneration
                                || isFinishing()
                                || isDestroyed()
                                || SafeKeySession.getState() != SessionState.UNLOCKED) {
                            return;
                        }

                        credentialsLoading = false;
                        credentialsLoadFailed = false;
                        loadedCredentials.clear();
                        loadedCredentials.addAll(credentials);
                        breachResults.clear();

                        for (Credential credential : credentials) {
                            breachResults.put(
                                    credential.getId(),
                                    PasswordBreachResult.notChecked()
                            );
                        }

                        refreshAlertsDashboard();

                        for (Credential credential : credentials) {
                            checkCredentialPassword(credential);
                        }
                    }

                    @Override
                    public void onError(Exception exception) {

                        if (!activityStarted
                                || thisLoadGeneration != credentialLoadGeneration
                                || isFinishing()
                                || isDestroyed()
                                || SafeKeySession.getState() != SessionState.UNLOCKED) {
                            return;
                        }

                        credentialsLoading = false;
                        credentialsLoadFailed = true;
                        TextView errorMessage =
                                findViewById(R.id.textAlertsEmptyState);

                        errorMessage.setText(R.string.alerts_load_error);
                        errorMessage.setVisibility(View.VISIBLE);

                        errorMessage.setOnClickListener(view -> {
                            if (activityStarted
                                    && SafeKeySession.getState() == SessionState.UNLOCKED
                                    && SafeKeySession.recordActivity()) {
                                loadCredentials();
                            }
                        });

                        findViewById(R.id.layoutAlertsBreachedSection)
                                .setVisibility(View.GONE);

                        findViewById(R.id.layoutAlertsAttentionSection)
                                .setVisibility(View.GONE);

                        findViewById(R.id.layoutAlertsPassedSection)
                                .setVisibility(View.GONE);
                    }
                }
        );
    }

    private void refreshAlertsDashboard() {

        if (!activityStarted
                || credentialsLoading
                || credentialsLoadFailed
                || isFinishing()
                || isDestroyed()
                || SafeKeySession.getState() != SessionState.UNLOCKED) {
            return;
        }

        LinearLayout breachedCards =
                findViewById(R.id.layoutAlertsBreachedCards);

        LinearLayout attentionCards =
                findViewById(R.id.layoutAlertsAttentionCards);

        LinearLayout passedCards =
                findViewById(R.id.layoutAlertsPassedCards);

        View breachedSection =
                findViewById(R.id.layoutAlertsBreachedSection);

        View attentionSection =
                findViewById(R.id.layoutAlertsAttentionSection);

        View passedSection =
                findViewById(R.id.layoutAlertsPassedSection);

        breachedSection.setVisibility(
                selectedFilter == AlertFilter.ALL
                        || selectedFilter == AlertFilter.BREACHED
                        ? View.VISIBLE : View.GONE
        );

        attentionSection.setVisibility(
                selectedFilter == AlertFilter.ALL
                        || selectedFilter == AlertFilter.ATTENTION
                        ? View.VISIBLE : View.GONE
        );

        passedSection.setVisibility(
                selectedFilter == AlertFilter.ALL
                        || selectedFilter == AlertFilter.PASSED
                        ? View.VISIBLE : View.GONE
        );

        updateAlertFilterStyling();
        breachedCards.removeAllViews();
        attentionCards.removeAllViews();
        passedCards.removeAllViews();

        for (Credential credential : loadedCredentials) {

            PasswordBreachResult result =
                    breachResults.get(credential.getId());

            PasswordBreachResult.Status status =
                    result == null
                            ? PasswordBreachResult.Status.NOT_CHECKED
                            : result.getStatus();

            LinearLayout targetContainer;

            switch (status) {
                case BREACHED:
                    targetContainer = breachedCards;
                    break;

                case NOT_FOUND:
                    targetContainer = passedCards;
                    break;

                case NOT_CHECKED:
                case ERROR:
                default:
                    targetContainer = attentionCards;
                    break;
            }

            View card = LayoutInflater.from(this).inflate(
                    R.layout.item_alert_credential,
                    targetContainer,
                    false
            );

            TextView name =
                    card.findViewById(R.id.textAlertCredentialName);

            TextView statusText =
                    card.findViewById(R.id.textAlertCredentialStatus);

            TextView occurrences =
                    card.findViewById(R.id.textAlertOccurrences);

            switch (status) {
                case BREACHED:
                    card.setBackgroundResource(
                            R.drawable.alerts_breached_card_bg
                    );
                    break;

                case NOT_FOUND:
                    card.setBackgroundResource(
                            R.drawable.alerts_passed_card_bg
                    );
                    break;

                case NOT_CHECKED:
                case ERROR:
                default:
                    card.setBackgroundResource(
                            R.drawable.alerts_attention_card_bg
                    );
                    break;
            }

            name.setText(credential.getTitle());

            switch (status) {
                case BREACHED:
                    statusText.setText(R.string.alerts_status_breached);

                    if (result != null && result.getOccurrenceCount() > 0) {
                        long count = result.getOccurrenceCount();

                        occurrences.setText(
                                getResources().getQuantityString(
                                        R.plurals.alerts_occurrences,
                                        count == 1L ? 1 : 2,
                                        count
                                )
                        );
                        occurrences.setVisibility(View.VISIBLE);
                    }
                    break;

                case NOT_FOUND:
                    statusText.setText(R.string.alerts_status_passed);
                    break;

                case ERROR:
                    if (result != null
                            && result.getErrorReason()
                            == PasswordBreachResult.ErrorReason.OFFLINE) {
                        statusText.setText(R.string.alerts_status_offline);
                    } else {
                        statusText.setText(R.string.alerts_status_error);
                    }
                    break;

                case NOT_CHECKED:
                default:
                    statusText.setText(R.string.alerts_status_not_checked);
                    break;
            }

            final long credentialId = credential.getId();

            card.setOnClickListener(view -> {

                if (SafeKeySession.getState() != SessionState.UNLOCKED
                        || !SafeKeySession.recordActivity()) {
                    return;
                }

                Intent intent = new Intent(
                        AlertsActivity.this,
                        CredentialDetailsActivity.class
                );

                intent.putExtra(
                        CredentialDetailsActivity.EXTRA_ID,
                        credentialId
                );

                startActivity(intent);
            });

            if (targetContainer.getChildCount() > 0) {
                LinearLayout.LayoutParams params =
                        (LinearLayout.LayoutParams) card.getLayoutParams();

                params.topMargin = getResources().getDimensionPixelSize(
                        R.dimen.alerts_card_spacing
                );

                card.setLayoutParams(params);
            }

            targetContainer.addView(card);
        }

        breachedSection.setVisibility(
                (selectedFilter == AlertFilter.ALL
                        || selectedFilter == AlertFilter.BREACHED)
                        && breachedCards.getChildCount() > 0
                        ? View.VISIBLE : View.GONE
        );

        attentionSection.setVisibility(
                (selectedFilter == AlertFilter.ALL
                        || selectedFilter == AlertFilter.ATTENTION)
                        && attentionCards.getChildCount() > 0
                        ? View.VISIBLE : View.GONE
        );

        passedSection.setVisibility(
                (selectedFilter == AlertFilter.ALL
                        || selectedFilter == AlertFilter.PASSED)
                        && passedCards.getChildCount() > 0
                        ? View.VISIBLE : View.GONE
        );

        TextView emptyState =
                findViewById(R.id.textAlertsEmptyState);

        emptyState.setOnClickListener(null);
        emptyState.setClickable(false);

        boolean noVisibleCredentials;

        switch (selectedFilter) {
            case BREACHED:
                noVisibleCredentials = breachedCards.getChildCount() == 0;
                emptyState.setText(R.string.alerts_empty_breached);
                break;

            case ATTENTION:
                noVisibleCredentials = attentionCards.getChildCount() == 0;
                emptyState.setText(R.string.alerts_empty_attention);
                break;

            case PASSED:
                noVisibleCredentials = passedCards.getChildCount() == 0;
                emptyState.setText(R.string.alerts_empty_passed);
                break;

            case ALL:
            default:
                noVisibleCredentials = loadedCredentials.isEmpty();
                emptyState.setText(R.string.alerts_empty_all);
                break;
        }

        emptyState.setVisibility(
                noVisibleCredentials ? View.VISIBLE : View.GONE
        );
    }

    private void checkCredentialPassword(Credential credential) {

        if (!activityStarted
                || SafeKeySession.getState() != SessionState.UNLOCKED) {
            return;
        }

        final long credentialId = credential.getId();
        final String password = credential.getPassword();
        final int checkGeneration = credentialLoadGeneration;
        final long checkId = ++nextBreachCheckId;
        latestBreachCheckIds.put(credentialId, checkId);

        PasswordBreachCoordinator.Request previousRequest =
                activeBreachRequests.remove(credentialId);

        if (previousRequest != null) {
            previousRequest.close();
        }

        if (password == null || password.isEmpty()) {
            breachResults.put(
                    credentialId,
                    PasswordBreachResult.notChecked()
            );

            latestBreachCheckIds.remove(credentialId);
            return;
        }

        char[] passwordChars = password.toCharArray();

        PasswordBreachCoordinator.Request request =
                passwordBreachCoordinator.check(
                        passwordChars,

                        result -> {
                            if (!activityStarted
                                    || checkGeneration != credentialLoadGeneration
                                    || !Long.valueOf(checkId).equals(
                                            latestBreachCheckIds.get(credentialId))
                                    || isFinishing()
                                    || isDestroyed()
                                    || SafeKeySession.getState() != SessionState.UNLOCKED) {
                                return;
                            }

                            breachResults.put(
                                    credentialId,
                                    result
                            );

                            activeBreachRequests.remove(credentialId);
                            latestBreachCheckIds.remove(credentialId);

                            refreshAlertsDashboard();
                        }
                );

        activeBreachRequests.put(credentialId, request);
    }

    private void cancelActiveBreachRequests() {

        for (PasswordBreachCoordinator.Request request
                : activeBreachRequests.values()) {

            if (request != null) {
                request.close();
            }
        }

        activeBreachRequests.clear();
    }

    @Override
    protected void onStop() {
        activityStarted = false;
        credentialsLoading = false;
        credentialsLoadFailed = false;
        credentialLoadGeneration++;
        cancelActiveBreachRequests();
        latestBreachCheckIds.clear();

        loadedCredentials.clear();
        breachResults.clear();

        int[] cardContainerIds = {
                R.id.layoutAlertsBreachedCards,
                R.id.layoutAlertsAttentionCards,
                R.id.layoutAlertsPassedCards
        };

        for (int containerId : cardContainerIds) {
            LinearLayout container = findViewById(containerId);

            if (container != null) {
                container.removeAllViews();
            }
        }

        TextView emptyState =
                findViewById(R.id.textAlertsEmptyState);

        if (emptyState != null) {
            emptyState.setOnClickListener(null);
            emptyState.setClickable(false);
            emptyState.setVisibility(View.GONE);
        }

        super.onStop();
    }

    @Override
    protected void onDestroy() {

        cancelActiveBreachRequests();

        if (passwordBreachCoordinator != null) {
            passwordBreachCoordinator.shutdown();
        }

        if (hibpRangeClient != null) {
            hibpRangeClient.shutdown();
        }

        super.onDestroy();
    }

    private void updateAlertFilterStyling() {

        int[] filterIds = {
                R.id.filterAlertsAll,
                R.id.filterAlertsBreached,
                R.id.filterAlertsAttention,
                R.id.filterAlertsPassed
        };

        AlertFilter[] filters = AlertFilter.values();

        for (int i = 0; i < filterIds.length; i++) {

            TextView chip = findViewById(filterIds[i]);

            boolean isSelected = selectedFilter == filters[i];

            chip.setBackgroundResource(
                    isSelected
                            ? R.drawable.vault_chip_active_bg
                            : R.drawable.vault_chip_inactive_bg
            );

            chip.setTextColor(
                    getColor(
                            isSelected
                                    ? R.color.vault_chip_text_dark
                                    : R.color.vault_text_secondary
                    )
            );

            chip.setSelected(isSelected);
        }
    }

    private void retryAttentionCredentials() {

        if (!activityStarted
                || SafeKeySession.getState() != SessionState.UNLOCKED
                || !SafeKeySession.recordActivity()) {
            return;
        }

        for (Credential credential : loadedCredentials) {

            long credentialId = credential.getId();

            // Do not duplicate a check already in progress.
            if (activeBreachRequests.containsKey(credentialId)) {
                continue;
            }

            PasswordBreachResult result =
                    breachResults.get(credentialId);

            if (result == null
                    || result.getStatus() == PasswordBreachResult.Status.NOT_CHECKED
                    || result.getStatus() == PasswordBreachResult.Status.ERROR) {

                if (credential.getPassword() == null
                        || credential.getPassword().isEmpty()) {
                    continue;
                }

                breachResults.put(
                        credentialId,
                        PasswordBreachResult.notChecked()
                );

                checkCredentialPassword(credential);
            }
        }

        refreshAlertsDashboard();
    }

    private void setupAlertFilters() {

        findViewById(R.id.filterAlertsAll).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            selectedFilter = AlertFilter.ALL;
            refreshAlertsDashboard();
        });

        findViewById(R.id.filterAlertsBreached).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            selectedFilter = AlertFilter.BREACHED;
            refreshAlertsDashboard();
        });

        findViewById(R.id.filterAlertsAttention).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            selectedFilter = AlertFilter.ATTENTION;
            refreshAlertsDashboard();
        });

        findViewById(R.id.filterAlertsPassed).setOnClickListener(view -> {
            if (!SafeKeySession.recordActivity()) {
                return;
            }
            selectedFilter = AlertFilter.PASSED;
            refreshAlertsDashboard();
        });
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

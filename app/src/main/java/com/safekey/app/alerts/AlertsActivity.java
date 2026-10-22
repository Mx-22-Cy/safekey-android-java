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
    private boolean activityStarted = false;
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

                        loadedCredentials.clear();
                        loadedCredentials.addAll(credentials);
                        breachResults.clear();

                        for (Credential credential : credentials) {
                            breachResults.put(
                                    credential.getId(),
                                    PasswordBreachResult.notChecked()
                            );
                        }

                        showUncheckedCredentials(credentials);

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

                        // We will display the loading error state later.
                    }
                }
        );
    }


    private void showUncheckedCredentials(List<Credential> credentials) {

        LinearLayout attentionCards =
                findViewById(R.id.layoutAlertsAttentionCards);

        attentionCards.removeAllViews();

        for (Credential credential : credentials) {

            final long credentialId = credential.getId();

            View card = LayoutInflater.from(this).inflate(
                    R.layout.item_alert_credential,
                    attentionCards,
                    false
            );

            TextView name =
                    card.findViewById(R.id.textAlertCredentialName);

            TextView status =
                    card.findViewById(R.id.textAlertCredentialStatus);

            name.setText(credential.getTitle());
            status.setText(R.string.alerts_status_not_checked);

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

            attentionCards.addView(card);
        }
    }

    private void refreshAlertsDashboard() {

        if (!activityStarted
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
                        occurrences.setText(
                                getString(
                                        R.string.alerts_occurrences,
                                        result.getOccurrenceCount()
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

            targetContainer.addView(card);
        }
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
        credentialLoadGeneration++;
        cancelActiveBreachRequests();
        latestBreachCheckIds.clear();

        loadedCredentials.clear();
        breachResults.clear();

        LinearLayout attentionCards =
                findViewById(R.id.layoutAlertsAttentionCards);

        if (attentionCards != null) {
            attentionCards.removeAllViews();
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

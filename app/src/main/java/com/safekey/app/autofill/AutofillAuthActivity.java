package com.safekey.app.autofill;

import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.Bundle;
import android.service.autofill.Dataset;
import android.service.autofill.FillResponse;
import android.view.WindowManager;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.RemoteViews;
import android.widget.ScrollView;
import android.widget.TextView;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.StartupGuardActivity;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.List;

public final class AutofillAuthActivity extends StartupGuardActivity {

    private AutofillVaultSession vaultSession;
    private AutofillRequestMetadata metadata;
    private LinearLayout content;
    private boolean completed;

    // Identifies the authentication session that opened this activity.
    private long authenticationGeneration = -1L;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);

        // Prevent screenshots and screen recordings of credential selection.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);

        SafeKeyApplication app =
                (SafeKeyApplication) getApplication();

        // The vault must already be unlocked.
        if (!app.isStartupRuntimeAvailable()
                || SafeKeySession.getState() != SessionState.UNLOCKED) {
            denyAutofill();
            return;
        }

        // Capture the current authentication generation.
        authenticationGeneration =
                SafeKeySession.getManager().getAuthenticationGeneration();

        if (authenticationGeneration < 0 || !sessionValid()) {
            denyAutofill();
            return;
        }

        // Obtain the Autofill structure supplied by Android.
        AssistStructure structure = getIntent().getParcelableExtra(
                AutofillManager.EXTRA_ASSIST_STRUCTURE
        );

        metadata = AutofillRequestMetadata.extract(structure);

        if (metadata == null) {
            denyAutofill();
            return;
        }

        // Reject missing, expired, reused, or mismatched requests.
        String requestToken = getIntent().getStringExtra(
                SafeKeyAutofillService.EXTRA_REQUEST_TOKEN
        );

        if (!AutofillRequestTracker.consume(requestToken, metadata)) {
            denyAutofill();
            return;
        }

        // Capture the active real or decoy vault without switching vaults.
        vaultSession = AutofillVaultSession.capture(this);

        if (vaultSession == null || !vaultSession.isCurrent()) {
            denyAutofill();
            return;
        }

        ScrollView scroll = new ScrollView(this);

        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(40, 40, 40, 40);

        scroll.addView(content);
        setContentView(scroll);

        showMessage("Verifying application and website...");

        // Verify Digital Asset Links outside the Android main thread.
        new Thread(() -> {

            boolean verified =
                    AutofillAssociationVerifier.isAssociated(
                            getApplicationContext(),
                            metadata
                    );

            runOnUiThread(() -> {

                if (isFinishing() || isDestroyed() || completed) {
                    return;
                }

                // Reject if association verification failed
                // or the original vault session is no longer valid.
                if (!verified
                        || !sessionValid()
                        || !vaultSession.isCurrent()) {

                    showMessage(
                            "SafeKey cannot verify this app and website."
                    );
                    return;
                }

                loadMatchingCredentials();
            });

        }, "SafeKey-Autofill-Verification").start();
    }

    private void loadMatchingCredentials() {

        if (!sessionValid() || !vaultSession.isCurrent()) {
            denyAutofill();
            return;
        }

        showMessage("Loading matching credentials...");

        vaultSession.getCredentials(
                new VaultDataService.ResultCallback<List<Credential>>() {

                    @Override
                    public void onSuccess(List<Credential> credentials) {

                        runOnUiThread(() -> {

                            if (isFinishing() || isDestroyed() || completed) {
                                return;
                            }

                            if (!sessionValid()
                                    || !vaultSession.isCurrent()) {

                                denyAutofill();
                                return;
                            }

                            List<Credential> matches =
                                    AutofillCredentialMatcher.findMatches(
                                            credentials,
                                            metadata.getClaimedWebHost()
                                    );

                            showCredentialChoices(matches);
                        });
                    }

                    @Override
                    public void onError(Exception error) {

                        runOnUiThread(() -> {

                            if (!isFinishing()
                                    && !isDestroyed()
                                    && !completed) {

                                showMessage(
                                        "Matching credentials unavailable."
                                );
                            }
                        });
                    }
                }
        );
    }

    private void showCredentialChoices(List<Credential> matches) {

        content.removeAllViews();

        if (matches.isEmpty()) {
            showMessage("No matching credentials found.");
            return;
        }

        TextView title = new TextView(this);
        title.setText("Choose a SafeKey credential");
        title.setTextSize(20);
        content.addView(title);

        for (Credential credential : matches) {

            Button button = new Button(this);

            // Display the username only.
            // Never display or log the password.
            button.setText(credential.getUsername());

            button.setOnClickListener(view ->
                    fillSelectedCredential(credential)
            );

            content.addView(button);
        }
    }

    private void fillSelectedCredential(Credential credential) {

        // Recheck authentication and the original vault session.
        if (completed
                || !sessionValid()
                || vaultSession == null
                || !vaultSession.isCurrent()
                || metadata == null
                || credential == null) {

            denyAutofill();
            return;
        }

        AutofillLoginFields.Fields fields = metadata.getFields();

        if (fields == null
                || fields.getUsernameId() == null
                || fields.getPasswordId() == null
                || !AutofillWebsiteMatcher.matches(
                credential.getWebsite(),
                metadata.getClaimedWebHost()
        )) {

            denyAutofill();
            return;
        }

        try {

            RemoteViews presentation = new RemoteViews(
                    getPackageName(),
                    android.R.layout.simple_list_item_1
            );

            presentation.setTextViewText(
                    android.R.id.text1,
                    "SafeKey"
            );

            // Build a dataset containing only the selected credential.
            Dataset dataset = new Dataset.Builder()
                    .setValue(
                            fields.getUsernameId(),
                            AutofillValue.forText(
                                    credential.getUsername()
                            ),
                            presentation
                    )
                    .setValue(
                            fields.getPasswordId(),
                            AutofillValue.forText(
                                    credential.getPassword()
                            ),
                            presentation
                    )
                    .build();

            FillResponse response = new FillResponse.Builder()
                    .addDataset(dataset)
                    .build();

            // Final validation before handing credentials to Android.
            if (!sessionValid() || !vaultSession.isCurrent()) {
                denyAutofill();
                return;
            }

            completed = true;

            Intent result = new Intent();

            result.putExtra(
                    AutofillManager.EXTRA_AUTHENTICATION_RESULT,
                    response
            );

            setResult(RESULT_OK, result);
            finish();

        } catch (RuntimeException exception) {

            // Fail closed if anything unexpected occurs.
            denyAutofill();
        }
    }

    /**
     * Confirms that:
     * 1. SafeKey's runtime is available.
     * 2. The vault is unlocked.
     * 3. The authentication generation has not changed.
     */
    private boolean sessionValid() {

        SafeKeyApplication app =
                (SafeKeyApplication) getApplication();

        return app.isStartupRuntimeAvailable()
                && SafeKeySession.getState() == SessionState.UNLOCKED
                && authenticationGeneration >= 0
                && SafeKeySession.getManager()
                .getAuthenticationGeneration()
                == authenticationGeneration;
    }

    private void showMessage(String message) {

        content.removeAllViews();

        TextView text = new TextView(this);
        text.setText(message);
        text.setTextSize(18);

        content.addView(text);
    }

    private void denyAutofill() {

        if (completed) {
            return;
        }

        completed = true;

        setResult(RESULT_CANCELED);
        finish();
    }
}

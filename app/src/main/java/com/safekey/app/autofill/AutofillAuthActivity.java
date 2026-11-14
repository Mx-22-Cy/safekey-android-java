package com.safekey.app.autofill;

import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
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
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Handles authenticated credential selection for Android Autofill.
 *
 * SECURITY:
 * - Requires an unlocked SafeKey vault.
 * - Requires a valid one-time Autofill request token.
 * - Preserves the original real or decoy vault session.
 * - Verifies HTTPS website requests before loading choices.
 * - Verifies native-app credentials using the installed
 *   application identity and Digital Asset Links.
 * - Rechecks native authorization before returning a dataset.
 * - Rechecks session validity before credential delivery.
 * - Never displays passwords in the selection interface.
 */
public final class AutofillAuthActivity
        extends StartupGuardActivity {

    private static final int REQUEST_UNLOCK_FOR_AUTOFILL = 451;
    private static final long MAX_AUTHENTICATION_FLOW_MILLIS = 5 * 60_000L;

    private final Handler validityHandler = new Handler(Looper.getMainLooper());
    private final Runnable validityCheck = this::checkFlowValidity;

    private AutofillVaultSession vaultSession;
    private AutofillRequestMetadata metadata;
    private LinearLayout content;

    private boolean completed;
    private boolean selectionInProgress;
    private boolean websiteAssociationVerified;
    private boolean awaitingSignIn;
    private long requestClaimedAtMillis = -1L;

    private List<Credential> verifiedChoices =
            Collections.emptyList();

    private long authenticationGeneration = -1L;

    @Override
    protected void onRuntimeCreate(Bundle savedInstanceState) {
        super.onRuntimeCreate(savedInstanceState);

        getWindow().addFlags(
                WindowManager.LayoutParams.FLAG_SECURE
        );

        // A recreated authentication screen must not reuse a consumed token.
        if (savedInstanceState != null || getIntent() == null) {
            denyAutofill();
            return;
        }

        SafeKeyApplication app =
                (SafeKeyApplication) getApplication();

        if (!app.isStartupRuntimeAvailable()) {
            denyAutofill();
            return;
        }

        AssistStructure structure =
                getIntent().getParcelableExtra(
                        AutofillManager.EXTRA_ASSIST_STRUCTURE
                );

        metadata = AutofillRequestMetadata.extract(structure);
        if (metadata == null) {
            denyAutofill();
            return;
        }

        String requestToken =
                getIntent().getStringExtra(
                        SafeKeyAutofillService.EXTRA_REQUEST_TOKEN
                );

        boolean vaultWasLocked =
                SafeKeySession.getState() == SessionState.LOCKED;

        // Each entry point consumes its original one-time token exactly once.
        // The locked path permits authentication, not access to credentials.
        boolean requestAccepted = vaultWasLocked
                ? AutofillRequestTracker.takeForAuthentication(
                requestToken, metadata)
                : AutofillRequestTracker.consume(requestToken, metadata);

        if (!requestAccepted) {
            denyAutofill();
            return;
        }

        requestClaimedAtMillis = SystemClock.elapsedRealtime();

        ScrollView scroll = new ScrollView(this);

        content = new LinearLayout(this);
        content.setOrientation(
                LinearLayout.VERTICAL
        );
        content.setPadding(40, 40, 40, 40);

        scroll.addView(content);
        setContentView(scroll);
        scheduleValidityCheck();

        if (vaultWasLocked) {
            awaitingSignIn = true;
            showMessage("Unlock SafeKey to continue Autofill.");

            try {
                Intent signIn = new Intent(this, SignInActivity.class);
                signIn.putExtra(
                        SignInActivity.EXTRA_RETURN_TO_AUTOFILL, true);
                startActivityForResult(
                        signIn, REQUEST_UNLOCK_FOR_AUTOFILL);
            } catch (RuntimeException failure) {
                awaitingSignIn = false;
                denyAutofill();
            }
            return;
        }

        if (!captureAuthenticatedVaultSession()) {
            denyAutofill();
            return;
        }
        startVerifiedCredentialFlow();
    }

    /** Internal Sign-In is a valid transition; ordinary backgrounding is not. */
    @Override
    protected void onRuntimeStop() {
        if (mustCancelOnStop(completed, awaitingSignIn)) {
            denyAutofill();
        }
        super.onRuntimeStop();
    }

    @Override
    protected void onRuntimeResume() {
        super.onRuntimeResume();
        if (completed) {
            return;
        }
        if (!requestFresh()
                || (!awaitingSignIn && vaultSession != null
                && (!sessionValid() || !vaultSession.isCurrent()))) {
            denyAutofill();
            return;
        }
        scheduleValidityCheck();
    }

    @Override
    protected void onRuntimeUserInteraction() {
        super.onRuntimeUserInteraction();
        if (!completed && !awaitingSignIn && vaultSession != null) {
            if (!sessionValid() || !vaultSession.isCurrent()
                    || !SafeKeySession.recordActivity()) {
                denyAutofill();
                return;
            }
            scheduleValidityCheck();
        }
    }

    @Override
    protected void onRuntimeDestroy() {
        validityHandler.removeCallbacks(validityCheck);
        if (!completed) {
            denyAutofill();
        }
        verifiedChoices = Collections.emptyList();
        vaultSession = null;
        metadata = null;
        super.onRuntimeDestroy();
    }

    static boolean mustCancelOnStop(boolean isCompleted, boolean isAwaitingSignIn) {
        return !isCompleted && !isAwaitingSignIn;
    }

    private void checkFlowValidity() {
        if (completed) {
            return;
        }
        if (!requestFresh() || (!awaitingSignIn && vaultSession != null
                && (!sessionValid() || !vaultSession.isCurrent()))) {
            denyAutofill();
        } else {
            scheduleValidityCheck();
        }
    }

    private void scheduleValidityCheck() {
        validityHandler.removeCallbacks(validityCheck);
        if (completed || requestClaimedAtMillis < 0L) {
            return;
        }
        long age = SystemClock.elapsedRealtime() - requestClaimedAtMillis;
        long delay = MAX_AUTHENTICATION_FLOW_MILLIS - age;
        if (delay <= 0L) {
            denyAutofill();
            return;
        }
        if (!awaitingSignIn && vaultSession != null) {
            long inactivity = SafeKeySession.getManager().getRemainingInactivityMillis();
            if (inactivity <= 0L) {
                denyAutofill();
                return;
            }
            delay = Math.min(delay, inactivity);
        }
        validityHandler.postDelayed(validityCheck, delay);
    }

    @Override
    protected void onActivityResult(
            int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode != REQUEST_UNLOCK_FOR_AUTOFILL) {
            return;
        }

        if (completed || !awaitingSignIn || resultCode != RESULT_OK
                || !requestFresh()) {
            denyAutofill();
            return;
        }

        awaitingSignIn = false;

        // SignInActivity performs master-password/biometric + TOTP,
        // claims the unlock session, and activates the real vault.
        // Recheck everything here. A result alone is NOT authorization.
        if (!captureAuthenticatedVaultSession()) {
            denyAutofill();
            return;
        }

        startVerifiedCredentialFlow();
    }

    private boolean requestFresh() {
        if (requestClaimedAtMillis < 0) {
            return false;
        }

        long elapsed = SystemClock.elapsedRealtime()
                - requestClaimedAtMillis;
        return elapsed >= 0
                && elapsed < MAX_AUTHENTICATION_FLOW_MILLIS;
    }

    private boolean captureAuthenticatedVaultSession() {
        if (!requestFresh()
                || SafeKeySession.getState() != SessionState.UNLOCKED) {
            return false;
        }

        authenticationGeneration = SafeKeySession.getManager()
                .getAuthenticationGeneration();
        if (!sessionValid()) {
            return false;
        }

        vaultSession = AutofillVaultSession.capture(this);
        boolean valid = vaultSession != null && vaultSession.isCurrent();
        if (valid) {
            scheduleValidityCheck();
        }
        return valid;
    }

    private void startVerifiedCredentialFlow() {
        if (completed || awaitingSignIn || !sessionValid()
                || metadata == null || vaultSession == null
                || !vaultSession.isCurrent()) {
            denyAutofill();
            return;
        }

        /*
         * Native requests do not claim a website origin.
         *
         * Each matching credential must be authorized
         * separately using the installed application
         * and its associated website.
         */
        if (metadata.isNativeApp()) {

            showMessage(
                    "Checking native application authorization..."
            );

            loadMatchingCredentials();
            return;
        }

        /*
         * Website requests require a valid HTTPS origin
         * and the existing Digital Asset Links verification.
         */
        if (metadata.getClaimedWebOrigin() == null) {
            denyAutofill();
            return;
        }

        showMessage(
                "Verifying application and website..."
        );

        final AutofillRequestMetadata request = metadata;

        new Thread(() -> {

            boolean verified =
                    AutofillAssociationVerifier.isAssociated(
                            getApplicationContext(),
                            request
                    );

            runOnUiThread(() -> {

                if (isFinishing()
                        || isDestroyed()
                        || completed) {
                    return;
                }

                if (!verified
                        || metadata != request
                        || !sessionValid()
                        || !vaultSession.isCurrent()) {

                    showMessage(
                            "SafeKey cannot verify this app and website."
                    );
                    return;
                }

                websiteAssociationVerified = true;

                loadMatchingCredentials();
            });

        }, "SafeKey-Web-Autofill-Verification").start();
    }

    /**
     * Retrieves credentials only from the original
     * authenticated real or decoy vault.
     */
    private void loadMatchingCredentials() {

        if (completed
                || !sessionValid()
                || vaultSession == null
                || !vaultSession.isCurrent()) {
            denyAutofill();
            return;
        }

        showMessage(
                "Loading matching credentials..."
        );

        vaultSession.getCredentials(
                new VaultDataService.ResultCallback<List<Credential>>() {

                    @Override
                    public void onSuccess(
                            List<Credential> credentials
                    ) {

                        runOnUiThread(() -> {

                            if (isFinishing()
                                    || isDestroyed()
                                    || completed) {
                                return;
                            }

                            if (!sessionValid()
                                    || !vaultSession.isCurrent()) {
                                denyAutofill();
                                return;
                            }

                            if (metadata.isNativeApp()) {

                                startNativeVerification(
                                        credentials
                                );

                                return;
                            }

                            if (!websiteAssociationVerified
                                    || metadata.getClaimedWebOrigin()
                                    == null) {
                                denyAutofill();
                                return;
                            }

                            List<Credential> matches =
                                    AutofillCredentialMatcher
                                            .findMatches(
                                                    credentials,
                                                    metadata
                                                            .getClaimedWebHost()
                                            );

                            showCredentialChoices(
                                    matches
                            );
                        });
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        runOnUiThread(() -> {

                            if (!isFinishing() && !isDestroyed() && !completed) {
                                // Error callbacks must never leave stale choices available.
                                denyAutofill();
                            }
                        });
                    }
                }
        );
    }

    /**
     * Verifies native-app credential associations
     * outside the Android main thread.
     *
     * No unverified credentials are displayed.
     */
    private void startNativeVerification(
            List<Credential> credentials
    ) {

        if (completed
                || metadata == null
                || !metadata.isNativeApp()
                || !sessionValid()
                || !vaultSession.isCurrent()) {
            denyAutofill();
            return;
        }

        showMessage(
                "Verifying application and associated websites..."
        );

        final AutofillRequestMetadata request = metadata;

        new Thread(() -> {

            List<Credential> matches =
                    AutofillAssociationVerifier
                            .findNativeMatches(
                                    getApplicationContext(),
                                    request,
                                    credentials
                            );

            runOnUiThread(() -> {

                if (isFinishing()
                        || isDestroyed()
                        || completed) {
                    return;
                }

                if (metadata != request
                        || !sessionValid()
                        || !vaultSession.isCurrent()) {
                    denyAutofill();
                    return;
                }

                showCredentialChoices(matches);
            });

        }, "SafeKey-Native-Autofill-Verification").start();
    }

    /**
     * Shows only credentials that passed the corresponding
     * website or native-app authorization path.
     */
    private void showCredentialChoices(
            List<Credential> matches
    ) {

        if (completed
                || !sessionValid()
                || !vaultSession.isCurrent()) {
            denyAutofill();
            return;
        }

        verifiedChoices = matches == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(
                new ArrayList<>(matches)
        );

        content.removeAllViews();

        if (verifiedChoices.isEmpty()) {

            showMessage(
                    "No verified matching credentials found."
            );

            return;
        }

        TextView title = new TextView(this);
        title.setText(
                "Choose a SafeKey credential"
        );
        title.setTextSize(20);

        content.addView(title);

        for (Credential credential : verifiedChoices) {

            if (credential == null) {
                continue;
            }

            Button button = new Button(this);

            /*
             * Display only the username.
             * Never expose the stored password in UI text.
             */
            button.setText(
                    credential.getUsername()
            );

            button.setOnClickListener(view ->
                    fillSelectedCredential(credential)
            );

            content.addView(button);
        }
    }

    /**
     * Starts final authorization for the selected credential.
     */
    private void fillSelectedCredential(
            Credential credential
    ) {

        if (completed || selectionInProgress) {
            return;
        }

        if (!sessionValid()
                || vaultSession == null
                || !vaultSession.isCurrent()
                || metadata == null
                || credential == null
                || !verifiedChoices.contains(credential)) {
            denyAutofill();
            return;
        }

        selectionInProgress = true;

        /*
         * A native application is authorized on a per-website
         * basis. Recheck the selected credential just before
         * returning it to the Android Autofill framework.
         *
         * The network check must not run on the UI thread.
         */
        if (metadata.isNativeApp()) {

            showMessage(
                    "Rechecking application authorization..."
            );

            final AutofillRequestMetadata request = metadata;

            new Thread(() -> {

                List<Credential> verified =
                        AutofillAssociationVerifier
                                .findNativeMatches(
                                        getApplicationContext(),
                                        request,
                                        Collections.singletonList(
                                                credential
                                        )
                                );

                boolean authorized =
                        verified.contains(credential);

                runOnUiThread(() -> {

                    if (isFinishing()
                            || isDestroyed()
                            || completed) {
                        return;
                    }

                    if (!authorized
                            || metadata != request
                            || !sessionValid()
                            || !vaultSession.isCurrent()) {
                        denyAutofill();
                        return;
                    }

                    completeSelection(
                            credential,
                            true
                    );
                });

            }, "SafeKey-Native-Autofill-Recheck").start();

            return;
        }

        completeSelection(
                credential,
                false
        );
    }

    /**
     * Creates the final Autofill response only after
     * authorization and session checks have succeeded.
     */
    private void completeSelection(
            Credential selected,
            boolean nativeReverified
    ) {
        if (completed || !selectionInProgress || !sessionValid()
                || vaultSession == null || !vaultSession.isCurrent()
                || selected == null || selected.getId() <= 0L
                || !verifiedChoices.contains(selected)) {
            denyAutofill();
            return;
        }

        // Retrieve the record again from the *captured* vault, not the current
        // application selection. Reject updates made after the choices were shown.
        final AutofillVaultSession originalSession = vaultSession;
        originalSession.getCredential(selected.getId(),
                new VaultDataService.ResultCallback<Credential>() {
                    @Override
                    public void onSuccess(Credential fresh) {
                        runOnUiThread(() -> {
                            if (completed || isFinishing() || isDestroyed()) {
                                return;
                            }
                            if (originalSession != vaultSession
                                    || !sessionValid() || !originalSession.isCurrent()
                                    || fresh == null || fresh.getId() != selected.getId()
                                    || !Objects.equals(fresh.getUsername(), selected.getUsername())
                                    || !Objects.equals(fresh.getWebsite(), selected.getWebsite())
                                    || !Objects.equals(fresh.getPassword(), selected.getPassword())) {
                                denyAutofill();
                                return;
                            }
                            deliverSelectedCredential(selected, fresh, nativeReverified);
                        });
                    }

                    @Override
                    public void onError(Exception error) {
                        runOnUiThread(() -> {
                            if (!completed && !isFinishing() && !isDestroyed()) {
                                denyAutofill();
                            }
                        });
                    }
                });
    }

    private void deliverSelectedCredential(
            Credential selected,
            Credential credential,
            boolean nativeReverified
    ) {

        if (completed
                || !selectionInProgress
                || !sessionValid()
                || vaultSession == null
                || !vaultSession.isCurrent()
                || metadata == null
                || credential == null
                || !verifiedChoices.contains(selected)) {
            denyAutofill();
            return;
        }

        AutofillLoginFields.Fields fields =
                metadata.getFields();

        if (fields == null
                || fields.getUsernameId() == null
                || fields.getPasswordId() == null
                || fields.getUsernameId().equals(
                fields.getPasswordId()
        )
                || credential.getUsername() == null
                || credential.getUsername().trim().isEmpty()
                || credential.getPassword() == null
                || credential.getPassword().isEmpty()) {
            denyAutofill();
            return;
        }

        if (metadata.isNativeApp()) {

            /*
             * Native requests must not claim a web origin.
             * Their credential must have passed the final
             * package/signature/website association check.
             */
            if (!nativeReverified
                    || metadata.getClaimedWebOrigin() != null
                    || metadata.getClaimedWebHost() != null
                    || metadata.getClaimedWebScheme() != null) {
                denyAutofill();
                return;
            }

        } else {

            /*
             * Preserve strict website matching.
             * Native verification cannot authorize a
             * website-mode request.
             */
            if (nativeReverified
                    || !websiteAssociationVerified
                    || metadata.getClaimedWebOrigin() == null
                    || !AutofillWebsiteMatcher.matches(
                    credential.getWebsite(),
                    metadata.getClaimedWebHost()
            )) {
                denyAutofill();
                return;
            }
        }

        try {

            RemoteViews presentation =
                    new RemoteViews(
                            getPackageName(),
                            android.R.layout.simple_list_item_1
                    );

            presentation.setTextViewText(
                    android.R.id.text1,
                    "SafeKey"
            );

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

            FillResponse response =
                    new FillResponse.Builder()
                            .addDataset(dataset)
                            .build();

            /*
             * Final check before returning the dataset.
             * No vault switching or reauthentication
             * may have occurred.
             */
            if (!sessionValid()
                    || !vaultSession.isCurrent()) {
                denyAutofill();
                return;
            }

            completed = true;
            validityHandler.removeCallbacks(validityCheck);

            verifiedChoices = Collections.emptyList();
            selectionInProgress = false;

            Intent result = new Intent();

            result.putExtra(
                    AutofillManager.EXTRA_AUTHENTICATION_RESULT,
                    response
            );

            setResult(RESULT_OK, result);
            finish();

        } catch (RuntimeException exception) {

            denyAutofill();
        }
    }

    /**
     * Confirms that the same authenticated SafeKey
     * session is still available.
     */
    private boolean sessionValid() {

        SafeKeyApplication app =
                (SafeKeyApplication) getApplication();

        return requestFresh()
                && app.isStartupRuntimeAvailable()
                && SafeKeySession.getState()
                == SessionState.UNLOCKED
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
        validityHandler.removeCallbacks(validityCheck);
        awaitingSignIn = false;
        selectionInProgress = false;
        websiteAssociationVerified = false;
        requestClaimedAtMillis = -1L;
        authenticationGeneration = -1L;
        vaultSession = null;
        metadata = null;
        verifiedChoices = Collections.emptyList();

        setResult(RESULT_CANCELED);
        finish();
    }
}

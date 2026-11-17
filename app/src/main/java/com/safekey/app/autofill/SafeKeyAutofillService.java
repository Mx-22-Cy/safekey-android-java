package com.safekey.app.autofill;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;
import android.view.autofill.AutofillId;
import android.widget.RemoteViews;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SafeKey Autofill service.
 *
 * The initial response never contains credentials.
 * All credential access requires authorization.
 */
public final class SafeKeyAutofillService extends AutofillService {

    public static final String EXTRA_REQUEST_TOKEN =
            "com.safekey.app.autofill.REQUEST_TOKEN";


    private static final AtomicInteger NEXT_REQUEST_ID =
            new AtomicInteger(1);

    private void diagnostic(String message) {
        if ((getApplicationInfo().flags
                & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            android.util.Log.d("SafeKeyAutofillDiag", message);
        }
    }

    @Override
    public void onConnected() {
        super.onConnected();
        diagnostic("SERVICE_CONNECTED");
    }

    @Override
    public void onFillRequest(
            FillRequest request,
            CancellationSignal cancellationSignal,
            FillCallback callback
    ) {
        diagnostic("FILL_REQUEST_ENTER");

        if (callback == null) {
            return;
        }

        if (request == null
                || cancellationSignal == null
                || cancellationSignal.isCanceled()) {
            callback.onSuccess(null);
            return;
        }

        List<FillContext> contexts = request.getFillContexts();
        diagnostic("FILL_CONTEXT_COUNT=" + (contexts == null ? -1 : contexts.size()));

        if (contexts == null || contexts.isEmpty()) {
            callback.onSuccess(null);
            return;
        }

        AssistStructure structure =
                contexts.get(contexts.size() - 1).getStructure();

        AutofillRequestMetadata metadata =
                AutofillRequestMetadata.extract(structure);

        boolean cancelledAfterExtraction = cancellationSignal.isCanceled();

        if ((getApplicationInfo().flags
                & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            android.util.Log.d(
                    "SafeKeyAutofillDiag",
                    metadata == null ? "METADATA_NULL" : "METADATA_PRESENT"
            );
            android.util.Log.d(
                    "SafeKeyAutofillDiag",
                    cancelledAfterExtraction ? "REQUEST_CANCELLED" : "REQUEST_ACTIVE"
            );
        }

        if (metadata == null || cancelledAfterExtraction) {
            callback.onSuccess(null);
            return;
        }

        diagnostic("METADATA_ACCEPTED package="
                + metadata.getPackageName()
                + " mode="
                + (metadata.isNativeApp() ? "NATIVE" : "WEB"));
        if (!metadata.isNativeApp()) {
            // Claimed by the browser form, not yet authorized for credentials.
            diagnostic("CLAIMED_WEB_HOST=" + metadata.getClaimedWebHost());
        }

        AutofillLoginFields.Fields fields = metadata.getFields();

        if (fields == null) {
            callback.onSuccess(null);
            return;
        }

        AutofillId usernameId = fields.getUsernameId();
        AutofillId passwordId = fields.getPasswordId();

        if ((usernameId == null && passwordId == null)
                || (usernameId != null && usernameId.equals(passwordId))) {
            callback.onSuccess(null);
            return;
        }

        // Only include fields actually present on this login screen.
        AutofillId[] authenticationIds =
                usernameId != null && passwordId != null
                        ? new AutofillId[]{usernameId, passwordId}
                        : new AutofillId[]{
                                usernameId != null ? usernameId : passwordId
                        };

        diagnostic("FIELDS username="
                + (usernameId != null)
                + " password="
                + (passwordId != null));

        // Register the original request before launching authentication.
        String token = AutofillRequestTracker.registerForAuthentication(metadata);

        if (token == null) {
            diagnostic("TRACKER_REJECTED");
            callback.onSuccess(null);
            return;
        }

        diagnostic("TRACKER_ACCEPTED");

        try {
            Intent authenticationIntent =
                    new Intent(this, AutofillAuthActivity.class);

            // Attach the request token to the authentication intent.
            authenticationIntent.putExtra(
                    EXTRA_REQUEST_TOKEN,
                    token
            );

            int requestId = NEXT_REQUEST_ID.getAndIncrement();

            PendingIntent authenticationPendingIntent =
                    PendingIntent.getActivity(
                            this,
                            requestId,
                            authenticationIntent,
                            PendingIntent.FLAG_ONE_SHOT
                                    | PendingIntent.FLAG_MUTABLE
                    );

            RemoteViews presentation =
                    new RemoteViews(
                            getPackageName(),
                            android.R.layout.simple_list_item_1
                    );

            presentation.setTextViewText(
                    android.R.id.text1,
                    "Unlock SafeKey to Autofill"
            );

            FillResponse response =
                    new FillResponse.Builder()
                            .setAuthentication(
                                    authenticationIds,
                                    authenticationPendingIntent.getIntentSender(),
                                    presentation
                            )
                            .build();

            if (cancellationSignal.isCanceled()) {
                AutofillRequestTracker.cancel(token);
                authenticationPendingIntent.cancel();
                callback.onSuccess(null);
                return;
            }

            // No credentials are included in the initial response.
            diagnostic("AUTH_RESPONSE_SUBMITTED");
            callback.onSuccess(response);

        } catch (RuntimeException exception) {

            diagnostic("RESPONSE_EXCEPTION_"
                    + exception.getClass().getSimpleName());

            // Fail closed and remove the unused token.
            AutofillRequestTracker.cancel(token);

            callback.onSuccess(null);
        }
    }

    @Override
    public void onSaveRequest(
            SaveRequest request,
            SaveCallback callback
    ) {

        // Automatic saving is disabled.
        callback.onSuccess();
    }
}

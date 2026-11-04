package com.safekey.app.autofill;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;
import android.util.Log;
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

    private static final String TAG = "SafeKeyAutofill";

    private static final AtomicInteger NEXT_REQUEST_ID =
            new AtomicInteger(1);

    @Override
    public void onFillRequest(
            FillRequest request,
            CancellationSignal cancellationSignal,
            FillCallback callback
    ) {

        // STEP 41B: Debug-only diagnostic logging.
        // Do not log usernames, passwords, websites, or request tokens.
        // ApplicationInfo.FLAG_DEBUGGABLE avoids the BuildConfig dependency.
        if ((getApplicationInfo().flags
                & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {

            Log.i(
                    TAG,
                    "Autofill fill request received"
            );
        }

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

        if (contexts == null || contexts.isEmpty()) {
            callback.onSuccess(null);
            return;
        }

        AssistStructure structure =
                contexts.get(contexts.size() - 1).getStructure();

        AutofillRequestMetadata metadata =
                AutofillRequestMetadata.extract(structure);

        if (metadata == null || cancellationSignal.isCanceled()) {
            callback.onSuccess(null);
            return;
        }

        AutofillLoginFields.Fields fields = metadata.getFields();

        if (fields == null) {
            callback.onSuccess(null);
            return;
        }

        AutofillId usernameId = fields.getUsernameId();
        AutofillId passwordId = fields.getPasswordId();

        if (usernameId == null || passwordId == null) {
            callback.onSuccess(null);
            return;
        }

        // Register the original request before launching authentication.
        String token = AutofillRequestTracker.register(metadata);

        if (token == null) {
            callback.onSuccess(null);
            return;
        }

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
                                    new AutofillId[]{
                                            usernameId,
                                            passwordId
                                    },
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
            callback.onSuccess(response);

        } catch (RuntimeException exception) {

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

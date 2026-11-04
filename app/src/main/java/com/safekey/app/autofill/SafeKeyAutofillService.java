package com.safekey.app.autofill;

import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.FillCallback;
import android.service.autofill.FillRequest;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;

/**
 * SafeKey Android Autofill service.
 *
 * This first stage registers the service safely.
 * Credential filling will be added only after
 * identity verification and vault-session checks.
 */
public final class SafeKeyAutofillService extends AutofillService {

    @Override
    public void onFillRequest(
            FillRequest request,
            CancellationSignal cancellationSignal,
            FillCallback callback
    ) {
        // Stage 1: Never expose credentials.
        // Secure matching is implemented in the next stage.
        callback.onSuccess(null);
    }

    @Override
    public void onSaveRequest(
            SaveRequest request,
            SaveCallback callback
    ) {
        // Stage 1: No automatic credential saving.
        callback.onSuccess();
    }
}
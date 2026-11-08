package com.safekey.app.autofill;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.view.autofill.AutofillManager;

import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Launches the actual SafeKey Autofill authentication Activity.
 *
 * These tests verify fail-closed results for requests
 * that have no framework-provided AssistStructure.
 *
 * They do not create, unlock, or modify a vault.
 *
 * A successful cancellation does not by itself prove that
 * the runtime-ready authentication path was exercised:
 * StartupGuardActivity can also reject a launch.
 */
@RunWith(AndroidJUnit4.class)
public class AutofillAuthLaunchInstrumentedTest {

    private Intent authenticationIntent() {
        Context context =
                ApplicationProvider.getApplicationContext();

        return new Intent(
                context,
                AutofillAuthActivity.class
        );
    }

    private void assertLaunchDoesNotReturnCredentials(
            Intent intent
    ) {
        try (ActivityScenario<AutofillAuthActivity> scenario =
                     ActivityScenario.launchActivityForResult(
                             intent
                     )) {

            assertNotNull(scenario);

            assertEquals(
                    Activity.RESULT_CANCELED,
                    scenario.getResult().getResultCode()
            );

            Intent resultData =
                    scenario.getResult().getResultData();

            assertTrue(
                    resultData == null
                            || !resultData.hasExtra(
                                    AutofillManager
                                            .EXTRA_AUTHENTICATION_RESULT
                            )
            );
        }
    }

    @Test
    public void launchWithoutFrameworkRequestReturnsNoCredentials() {

        Intent intent = authenticationIntent();

        assertFalse(
                intent.hasExtra(
                        AutofillManager.EXTRA_ASSIST_STRUCTURE
                )
        );

        assertFalse(
                intent.hasExtra(
                        SafeKeyAutofillService.EXTRA_REQUEST_TOKEN
                )
        );

        assertLaunchDoesNotReturnCredentials(intent);
    }

    @Test
    public void launchWithForgedTokenButNoStructureReturnsNoCredentials() {

        Intent intent = authenticationIntent();

        intent.putExtra(
                SafeKeyAutofillService.EXTRA_REQUEST_TOKEN,
                "fabricated-autofill-request-token"
        );

        assertFalse(
                intent.hasExtra(
                        AutofillManager.EXTRA_ASSIST_STRUCTURE
                )
        );

        assertLaunchDoesNotReturnCredentials(intent);
    }
}

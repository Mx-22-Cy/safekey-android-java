package com.safekey.app.autofill;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.view.autofill.AutofillManager;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class AutofillAuthInstrumentedTest {

    @Test
    public void authorizationActivityIsNotExported() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();

        Intent intent = new Intent(
                context,
                AutofillAuthActivity.class
        );

        ActivityInfo info =
                context.getPackageManager().getActivityInfo(
                        intent.getComponent(),
                        0
                );

        assertFalse(info.exported);
    }

    @Test
    public void authenticationIntentTargetsSafeKeyActivity() {
        Context context = ApplicationProvider.getApplicationContext();

        Intent intent = new Intent(
                context,
                AutofillAuthActivity.class
        );

        assertNotNull(intent.getComponent());

        assertTrue(
                context.getPackageName().equals(
                        intent.getComponent().getPackageName()
                )
        );
    }

    @Test
    public void authenticationRequiresFrameworkStructure() {
        Intent intent = new Intent();

        assertFalse(
                intent.hasExtra(
                        AutofillManager.EXTRA_ASSIST_STRUCTURE
                )
        );
    }

    @Test
    public void authenticationRequiresRequestToken() {
        Intent intent = new Intent();

        assertFalse(
                intent.hasExtra(
                        SafeKeyAutofillService.EXTRA_REQUEST_TOKEN
                )
        );
    }
}

package com.safekey.app.autofill;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.view.View;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class AutofillLoginFieldsInstrumentedTest {

    @Test
    public void androidPasswordHintIsRecognized() {
        assertTrue(
                AutofillLoginFields.isPasswordHint(
                        new String[]{View.AUTOFILL_HINT_PASSWORD}
                )
        );
    }

    @Test
    public void htmlCurrentPasswordHintIsRecognized() {
        assertTrue(
                AutofillLoginFields.isPasswordHint(
                        new String[]{"current-password"}
                )
        );
    }

    @Test
    public void currentPasswordHintIsCaseInsensitive() {
        assertTrue(
                AutofillLoginFields.isPasswordHint(
                        new String[]{"CURRENT-PASSWORD"}
                )
        );
    }

    @Test
    public void unrelatedPasswordHintsAreRejected() {
        assertFalse(
                AutofillLoginFields.isPasswordHint(
                        new String[]{"new-password"}
                )
        );

        assertFalse(
                AutofillLoginFields.isPasswordHint(
                        new String[]{"username"}
                )
        );

        assertFalse(
                AutofillLoginFields.isPasswordHint(
                        new String[0]
                )
        );

        assertFalse(
                AutofillLoginFields.isPasswordHint(null)
        );
    }
}

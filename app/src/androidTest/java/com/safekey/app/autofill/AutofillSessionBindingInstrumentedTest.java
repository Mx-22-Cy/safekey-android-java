package com.safekey.app.autofill;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.safekey.app.SafeKeyApplication;

import org.junit.Test;
import org.junit.runner.RunWith;

/** Isolated policy tests. These do not unlock or modify any vault database. */
@RunWith(AndroidJUnit4.class)
public class AutofillSessionBindingInstrumentedTest {

    private static boolean match(
            SafeKeyApplication.ActiveVault expected,
            long generation,
            Object operation,
            SafeKeyApplication.ActiveVault actual,
            long currentGeneration,
            Object currentOperation,
            boolean unlocked) {
        return AutofillVaultSession.matchesBinding(
                expected, generation, operation,
                actual, currentGeneration, currentOperation, unlocked);
    }

    @Test public void realSessionAllowsOnlyOriginalRealOperations() {
        Object operations = new Object();
        assertTrue(match(SafeKeyApplication.ActiveVault.REAL, 3L, operations,
                SafeKeyApplication.ActiveVault.REAL, 3L, operations, true));
    }

    @Test public void decoySessionAllowsOnlyOriginalDecoyOperations() {
        Object operations = new Object();
        assertTrue(match(SafeKeyApplication.ActiveVault.DECOY, 7L, operations,
                SafeKeyApplication.ActiveVault.DECOY, 7L, operations, true));
    }

    @Test public void decoyCannotUseRealSession() {
        Object operations = new Object();
        assertFalse(match(SafeKeyApplication.ActiveVault.REAL, 3L, operations,
                SafeKeyApplication.ActiveVault.DECOY, 3L, operations, true));
    }

    @Test public void realCannotUseDecoySession() {
        Object operations = new Object();
        assertFalse(match(SafeKeyApplication.ActiveVault.DECOY, 3L, operations,
                SafeKeyApplication.ActiveVault.REAL, 3L, operations, true));
    }

    @Test public void sessionSwitchWithSameVaultTypeIsRejected() {
        assertFalse(match(SafeKeyApplication.ActiveVault.REAL, 1L, new Object(),
                SafeKeyApplication.ActiveVault.REAL, 2L, new Object(), true));
    }

    @Test public void sameGenerationWithNewOperationsIsRejected() {
        assertFalse(match(SafeKeyApplication.ActiveVault.DECOY, 8L, new Object(),
                SafeKeyApplication.ActiveVault.DECOY, 8L, new Object(), true));
    }

    @Test public void lockedSessionIsRejected() {
        Object operations = new Object();
        assertFalse(match(SafeKeyApplication.ActiveVault.REAL, 1L, operations,
                SafeKeyApplication.ActiveVault.REAL, 1L, operations, false));
    }

    @Test public void missingVaultIdentityIsRejected() {
        Object operations = new Object();
        assertFalse(match(SafeKeyApplication.ActiveVault.NONE, 1L, operations,
                SafeKeyApplication.ActiveVault.NONE, 1L, operations, true));
    }

    @Test public void missingOperationsAndGenerationAreRejected() {
        assertFalse(match(SafeKeyApplication.ActiveVault.REAL, 1L, null,
                SafeKeyApplication.ActiveVault.REAL, 1L, null, true));
        Object operations = new Object();
        assertFalse(match(SafeKeyApplication.ActiveVault.REAL, -1L, operations,
                SafeKeyApplication.ActiveVault.REAL, -1L, operations, true));
    }

    @Test public void navigationToSignInDoesNotCountAsBackgroundCancel() {
        assertFalse(AutofillAuthActivity.mustCancelOnStop(false, true));
        assertTrue(AutofillAuthActivity.mustCancelOnStop(false, false));
        assertFalse(AutofillAuthActivity.mustCancelOnStop(true, false));
    }
}

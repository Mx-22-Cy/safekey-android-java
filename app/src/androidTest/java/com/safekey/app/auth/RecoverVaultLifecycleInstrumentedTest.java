package com.safekey.app.auth;


import android.widget.EditText;

import com.safekey.app.R;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;


import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Regression tests for PR #41: onResume must not invalidate an in-flight request
 * when the activity was paused but never stopped.
 *
 * These deliberately test lifecycle/token preservation; they do not replace
 * integration tests with the actual password-screening and reset callbacks.
 */
@RunWith(AndroidJUnit4.class)
public final class RecoverVaultLifecycleInstrumentedTest {
    private static final long TOKEN = 314159L;

    @Test
    public void passwordScreeningRemainsCurrentAfterPauseAndResumeWithoutStop() {
        try (ActivityScenario<RecoverVaultActivity> scenario =
                     ActivityScenario.launch(RecoverVaultActivity.class)) {
            scenario.onActivity(activity -> {
                set(activity, "generation", TOKEN);
                set(activity, "busy", true);
                assertTrue("Screening should be current before interruption", current(activity));
            });

            // RESUMED -> STARTED is onPause only, not onStop.
            scenario.moveToState(Lifecycle.State.STARTED);
            scenario.moveToState(Lifecycle.State.RESUMED);

            scenario.onActivity(activity -> {
                assertTrue("Resume cleared the active screening state", (boolean) get(activity, "busy"));
                assertEquals("Resume changed the screening request token", TOKEN,
                        (long) get(activity, "generation"));
                assertTrue("Screening completion would now be rejected", current(activity));
            });
        }
    }

    @Test
    public void resetRemainsCurrentAfterPauseAndResumeWithoutStop() {
        try (ActivityScenario<RecoverVaultActivity> scenario =
                     ActivityScenario.launch(RecoverVaultActivity.class)) {
            scenario.onActivity(activity -> {
                set(activity, "generation", TOKEN);
                set(activity, "busy", true);
                set(activity, "pendingKey", "ABCDEF0123456789ABCDEF0123456789".toCharArray());
                set(activity, "pendingPassword", "DisposableTestPassword!1234".toCharArray());
                assertTrue("Reset should be current before interruption", current(activity));
            });

            scenario.moveToState(Lifecycle.State.STARTED);
            scenario.moveToState(Lifecycle.State.RESUMED);

            scenario.onActivity(activity -> {
                assertTrue("Resume cleared the active reset state", (boolean) get(activity, "busy"));
                assertEquals("Resume changed the reset request token", TOKEN,
                        (long) get(activity, "generation"));
                assertTrue("Reset success callback would now be rejected", current(activity));
                assertEquals(32, ((char[]) get(activity, "pendingKey")).length);
                assertTrue(((char[]) get(activity, "pendingPassword")).length > 0);
            });
        }
    }

    @Test
    public void stopCancelsPendingStateAndInvalidatesOldToken() {
        try (ActivityScenario<RecoverVaultActivity> scenario =
                     ActivityScenario.launch(RecoverVaultActivity.class)) {
            final char[] key = "ABCDEF0123456789ABCDEF0123456789".toCharArray();
            final char[] password = "DisposableTestPassword!1234".toCharArray();
            scenario.onActivity(activity -> {
                set(activity, "generation", TOKEN);
                set(activity, "recoveryUnavailable", false);
                setBusy(activity, true);
                set(activity, "pendingKey", key);
                set(activity, "pendingPassword", password);
                assertTrue(current(activity));
                assertFalse("Busy recovery key should be disabled",
                        activity.findViewById(R.id.editRecoveryKey).isEnabled());
                assertFalse("Busy Back control should be disabled",
                        activity.findViewById(R.id.buttonBackRecovery).isEnabled());
            });

            // RESUMED -> CREATED invokes onStop, which must cancel and clear secrets.
            scenario.moveToState(Lifecycle.State.CREATED);
            scenario.onActivity(activity -> {
                assertFalse("Stopping did not cancel busy state", (boolean) get(activity, "busy"));
                assertFalse("Old request token was not invalidated", current(activity));
                assertTrue("Pending recovery key was retained", get(activity, "pendingKey") == null);
                assertTrue("Pending master password was retained", get(activity, "pendingPassword") == null);
            });
            assertTrue("Recovery key characters were not cleared", allZero(key));
            assertTrue("Master password characters were not cleared", allZero(password));

            // A canceled request must not leave the form disabled on return.
            scenario.moveToState(Lifecycle.State.RESUMED);
            scenario.onActivity(activity -> {
                assertFalse("Canceled request unexpectedly restarted", (boolean) get(activity, "busy"));
                assertFalse("Canceled callback became current again", current(activity));
                int[] controls = {
                        R.id.editRecoveryKey,
                        R.id.editNewRecoveryPassword,
                        R.id.editConfirmRecoveryPassword,
                        R.id.checkShowRecoveryKey,
                        R.id.checkShowRecoveryPasswords,
                        R.id.buttonEyeRecoveryKey,
                        R.id.buttonEyeNewRecoveryPassword,
                        R.id.buttonEyeConfirmRecoveryPassword,
                        R.id.buttonCancelRecovery,
                        R.id.buttonBackRecovery
                };
                for (int id : controls) {
                    assertTrue("Control stayed disabled after resume: " + id,
                            activity.findViewById(id).isEnabled());
                }
                EditText keyField = activity.findViewById(R.id.editRecoveryKey);
                EditText passwordField = activity.findViewById(R.id.editNewRecoveryPassword);
                EditText confirmField = activity.findViewById(R.id.editConfirmRecoveryPassword);
                assertEquals("", keyField.getText().toString());
                assertEquals("", passwordField.getText().toString());
                assertEquals("", confirmField.getText().toString());
                assertFalse("Reset should stay disabled for cleared inputs",
                        activity.findViewById(R.id.buttonResetMasterPassword).isEnabled());

                // Typing again after return must work without restarting Activity.
                keyField.setText("ABCDEF0123456789ABCDEF0123456789");
                passwordField.setText("DisposableTestPassword!1234");
                confirmField.setText("DisposableTestPassword!1234");
                assertEquals(32, keyField.length());
                assertTrue(passwordField.length() > 0);
                assertEquals(passwordField.getText().toString(),
                        confirmField.getText().toString());
                keyField.setText(null);
                passwordField.setText(null);
                confirmField.setText(null);
            });
        }
    }

    @Test
    public void unavailableDuringResetRestoresNavigationButKeepsRecoveryDisabled() {
        try (ActivityScenario<RecoverVaultActivity> scenario =
                     ActivityScenario.launch(RecoverVaultActivity.class)) {
            final char[] key = "ABCDEF0123456789ABCDEF0123456789".toCharArray();
            final char[] password = "DisposableTestPassword!1234".toCharArray();
            scenario.onActivity(activity -> {
                set(activity, "recoveryUnavailable", false);
                set(activity, "generation", TOKEN);
                setBusy(activity, true);
                set(activity, "pendingKey", key);
                set(activity, "pendingPassword", password);
                assertTrue("Reset should be active before backend error", current(activity));
                assertFalse(activity.findViewById(R.id.buttonBackRecovery).isEnabled());
                assertFalse(activity.findViewById(R.id.buttonCancelRecovery).isEnabled());

                setDisabled(activity, "Recovery is unavailable");

                assertTrue("Recovery should be marked unavailable",
                        (boolean) get(activity, "recoveryUnavailable"));
                assertFalse("Canceled request must not remain busy", (boolean) get(activity, "busy"));
                assertFalse("Canceled callback must remain invalid", current(activity));
                assertTrue("Pending key reference retained", get(activity, "pendingKey") == null);
                assertTrue("Pending password reference retained", get(activity, "pendingPassword") == null);
                assertTrue("Back must be available", activity.findViewById(R.id.buttonBackRecovery).isEnabled());
                assertTrue("Cancel must be available", activity.findViewById(R.id.buttonCancelRecovery).isEnabled());
                int[] disabledControls = {
                        R.id.editRecoveryKey,
                        R.id.editNewRecoveryPassword,
                        R.id.editConfirmRecoveryPassword,
                        R.id.checkShowRecoveryKey,
                        R.id.checkShowRecoveryPasswords,
                        R.id.buttonEyeRecoveryKey,
                        R.id.buttonEyeNewRecoveryPassword,
                        R.id.buttonEyeConfirmRecoveryPassword,
                        R.id.buttonResetMasterPassword
                };
                for (int id : disabledControls) {
                    assertFalse("Unavailable control became enabled: " + id,
                            activity.findViewById(id).isEnabled());
                }
                assertEquals("", ((EditText) activity.findViewById(R.id.editRecoveryKey))
                        .getText().toString());
                assertEquals("", ((EditText) activity.findViewById(R.id.editNewRecoveryPassword))
                        .getText().toString());
                assertEquals("", ((EditText) activity.findViewById(R.id.editConfirmRecoveryPassword))
                        .getText().toString());
            });
            assertTrue("Pending Recovery Key was not zeroized", allZero(key));
            assertTrue("Pending password was not zeroized", allZero(password));
            // The same unavailable state must keep navigation available after resume.
            scenario.moveToState(Lifecycle.State.STARTED);
            scenario.moveToState(Lifecycle.State.RESUMED);
            scenario.onActivity(activity -> {
                assertTrue(activity.findViewById(R.id.buttonBackRecovery).isEnabled());
                assertTrue(activity.findViewById(R.id.buttonCancelRecovery).isEnabled());
                assertFalse(activity.findViewById(R.id.editRecoveryKey).isEnabled());
                assertFalse(activity.findViewById(R.id.buttonResetMasterPassword).isEnabled());
                assertFalse(current(activity));
            });
        }
    }

    private static void setDisabled(RecoverVaultActivity activity, String message) {
        try {
            Method method = RecoverVaultActivity.class.getDeclaredMethod("setDisabled", String.class);
            method.setAccessible(true);
            method.invoke(activity, message);
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not simulate unavailable recovery error", failure);
        }
    }

    private static void setBusy(RecoverVaultActivity activity, boolean value) {
        try {
            Method method = RecoverVaultActivity.class.getDeclaredMethod("setBusy", boolean.class);
            method.setAccessible(true);
            method.invoke(activity, value);
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not set up a genuinely disabled busy form", failure);
        }
    }

    private static boolean allZero(char[] value) {
        for (char c : value) if (c != '\0') return false;
        return true;
    }

    private static boolean current(RecoverVaultActivity activity) {
        try {
            Method method = RecoverVaultActivity.class.getDeclaredMethod("current", long.class);
            method.setAccessible(true);
            return (boolean) method.invoke(activity, TOKEN);
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not inspect request callback guard", failure);
        }
    }

    private static Object get(RecoverVaultActivity activity, String name) {
        try {
            Field field = RecoverVaultActivity.class.getDeclaredField(name);
            field.setAccessible(true);
            return field.get(activity);
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not read " + name, failure);
        }
    }

    private static void set(RecoverVaultActivity activity, String name, Object value) {
        try {
            Field field = RecoverVaultActivity.class.getDeclaredField(name);
            field.setAccessible(true);
            field.set(activity, value);
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not set " + name, failure);
        }
    }
}

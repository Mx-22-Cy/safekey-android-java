package com.safekey.app.settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.os.SystemClock;
import android.widget.TextView;
import android.widget.ListView;

import androidx.appcompat.app.AlertDialog;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.R;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.session.AutoLockPreferences;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tests the actual Settings timeout picker with a temporary authenticated vault.
 * DESTRUCTIVE TEST FIXTURE: use only a disposable emulator; existing primary
 * vault storage is deleted by setup and cleanup.
 */
@RunWith(AndroidJUnit4.class)
public final class SettingsAutoLockInstrumentedTest {
    private static final String TEST_PASSWORD = "task three disposable settings password";
    private SafeKeyApplication app;
    private SecureVaultCoordinator coordinator;
    private long previousTimeout;

    @Before
    public void setUp() throws Exception {
        app = (SafeKeyApplication) InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
        coordinator = app.getSecureVaultCoordinator();
        previousTimeout = app.getAutoLockTimeoutMillis();

        onMain(SafeKeySession::lock);
        await(callback -> app.prepareForVaultAuthentication(callback));
        // This test uses an isolated, disposable emulator; never run it on real data.
        new VaultKeyEnvelopeStore(app).clear();
        app.deleteDatabase("safekey.db");

        char[] password = TEST_PASSWORD.toCharArray();
        try {
            await(callback -> coordinator.createVault(password, callback));
        } finally {
            Arrays.fill(password, '\0');
        }
        onMain(() -> {
            SafeKeySession.unlockAfterAuthentication();
            app.activateRealVault();
        });
    }

    @After
    public void tearDown() throws Exception {
        if (app == null) return;
        onMain(SafeKeySession::lock);
        await(callback -> app.prepareForVaultAuthentication(callback));
        app.deleteDatabase("safekey.db");
        new VaultKeyEnvelopeStore(app).clear();
        new AutoLockPreferences(app).setTimeoutMillis(previousTimeout);
        onMain(() -> SafeKeySession.setInactivityTimeoutMillis(previousTimeout));
    }

    @Test
    public void selectingEachOptionUpdatesTimerAndPersistsAfterRecreation() {
        long[] values = AutoLockPreferences.getSupportedTimeoutsMillis();
        int[] labels = {
                R.string.settings_auto_lock_one_minute,
                R.string.settings_auto_lock_five_minutes,
                R.string.settings_auto_lock_fifteen_minutes
        };
        assertEquals(3, values.length);
        try (ActivityScenario<SettingsActivity> scenario =
                     ActivityScenario.launch(SettingsActivity.class)) {
            // Pick all supported values, including switching back to the default.
            for (int index : new int[]{0, 2, 1}) {
                scenario.onActivity(activity -> {
                    activity.findViewById(R.id.rowSettingsAutoLock).performClick();
                    AlertDialog dialog = currentDialog(activity);
                    assertNotNull(dialog);
                    assertTrue(dialog.isShowing());
                    ListView list = dialog.getListView();
                    assertNotNull(list);
                    assertEquals(3, list.getCount());
                    assertTrue(list.performItemClick(null, index, index));
                    assertEquals(values[index], app.getAutoLockTimeoutMillis());
                    assertEquals(activity.getString(labels[index]),
                            ((TextView) activity.findViewById(
                                    R.id.textSettingsAutoLockValue)).getText().toString());
                });
                assertEquals(values[index], new AutoLockPreferences(app).getTimeoutMillis());
                scenario.recreate();
                scenario.onActivity(activity -> {
                    assertEquals(activity.getString(labels[index]),
                            ((TextView) activity.findViewById(
                                    R.id.textSettingsAutoLockValue)).getText().toString());
                    activity.findViewById(R.id.rowSettingsAutoLock).performClick();
                    AlertDialog dialog = currentDialog(activity);
                    assertNotNull(dialog);
                    assertTrue(dialog.getListView().isItemChecked(index));
                    dialog.dismiss();
                });
            }
        }
    }

    @Test
    public void cancellingSelectionLeavesExistingTimeoutUnchanged() {
        try (ActivityScenario<SettingsActivity> scenario =
                     ActivityScenario.launch(SettingsActivity.class)) {
            scenario.onActivity(activity -> {
                long before = app.getAutoLockTimeoutMillis();
                activity.findViewById(R.id.rowSettingsAutoLock).performClick();
                AlertDialog dialog = currentDialog(activity);
                assertNotNull(dialog);
                assertTrue(dialog.isShowing());
                dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
                assertEquals(before, app.getAutoLockTimeoutMillis());
                assertEquals(before, new AutoLockPreferences(app).getTimeoutMillis());
            });
        }
    }

    private static AlertDialog currentDialog(SettingsActivity activity) {
        try {
            Field field = SettingsActivity.class.getDeclaredField("autoLockDialog");
            field.setAccessible(true);
            return (AlertDialog) field.get(activity);
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError("Cannot access Settings timeout dialog", exception);
        }
    }

    private static void onMain(Runnable action) {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(action);
    }

    private static void await(Operation operation) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Exception> failure = new AtomicReference<>();
        operation.run(new VaultDataService.SimpleCallback() {
            @Override public void onSuccess() { latch.countDown(); }
            @Override public void onError(Exception error) {
                failure.set(error);
                latch.countDown();
            }
        });
        CallbackTimeoutDiagnostics.await(latch, 30L);
        if (failure.get() != null) throw failure.get();
    }

    private interface Operation {
        void run(VaultDataService.SimpleCallback callback);
    }
}

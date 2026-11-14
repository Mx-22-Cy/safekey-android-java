package com.safekey.app.session;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/** Exercises the real Android adapter in a separate, disposable preference file. */
@RunWith(AndroidJUnit4.class)
public class AutoLockPreferencesInstrumentedTest {

    private static final String TIMEOUT_KEY = "inactivity_timeout_millis";
    private Context application;
    private Context isolatedContext;
    private String testPreferencesName;
    private SharedPreferences backing;
    private AutoLockPreferences preferences;

    @Before
    public void setUp() {
        application = InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
        testPreferencesName = "safekey_test_autolock_" + UUID.randomUUID();
        backing = application.getSharedPreferences(
                testPreferencesName, Context.MODE_PRIVATE);
        assertTrue(backing.edit().clear().commit());
        isolatedContext = new ContextWrapper(application) {
            @Override
            public Context getApplicationContext() {
                return this;
            }

            @Override
            public SharedPreferences getSharedPreferences(String name, int mode) {
                assertEquals(AutoLockPreferences.PREFERENCES_NAME, name);
                assertEquals(Context.MODE_PRIVATE, mode);
                return backing;
            }
        };
        preferences = new AutoLockPreferences(isolatedContext);
    }

    @After
    public void tearDown() {
        if (application != null && testPreferencesName != null) {
            assertTrue(application.deleteSharedPreferences(testPreferencesName));
        }
    }

    @Test
    public void emptyPreferenceFile_usesFiveMinutes() {
        assertEquals(300_000L, preferences.getTimeoutMillis());
    }

    @Test
    public void supportedOptions_areWrittenThroughAndroidAdapter() {
        for (long timeout : AutoLockPreferences.getSupportedTimeoutsMillis()) {
            preferences.setTimeoutMillis(timeout);
            assertEquals(timeout, backing.getLong(TIMEOUT_KEY, -1L));
            assertEquals(timeout,
                    new AutoLockPreferences(isolatedContext).getTimeoutMillis());
        }
    }

    @Test
    public void corruptStoredType_fallsBackAndCanBeReplaced() {
        assertTrue(backing.edit().putString(TIMEOUT_KEY, "corrupt").commit());
        assertEquals(300_000L, preferences.getTimeoutMillis());
        preferences.setTimeoutMillis(60_000L);
        assertEquals(60_000L, backing.getLong(TIMEOUT_KEY, -1L));
    }

    @Test
    public void unsupportedStoredTimeout_fallsBackToDefault() {
        assertTrue(backing.edit().putLong(TIMEOUT_KEY, 0L).commit());
        assertEquals(300_000L, preferences.getTimeoutMillis());
    }

    @Test
    public void invalidSelection_preservesPreviousValueAndOtherKeys() {
        assertTrue(backing.edit().putString("unrelated", "keep").commit());
        preferences.setTimeoutMillis(900_000L);
        assertThrows(IllegalArgumentException.class,
                () -> preferences.setTimeoutMillis(0L));
        assertEquals(900_000L, preferences.getTimeoutMillis());
        assertEquals("keep", backing.getString("unrelated", null));
    }
}

package com.safekey.app.session;

import android.content.Context;
import android.content.SharedPreferences;

import com.safekey.app.session.logic.VaultSessionManager;

import java.util.Objects;

/**
 * Persists the non-secret inactivity-timeout preference.
 *
 * <p>The application loads this policy into VaultSessionManager. Settings
 * must use the application's policy-change operation so persistence and
 * the running timer are both updated. Saving this preference alone does
 * not alter a running session.</p>
 */
public final class AutoLockPreferences {

    public static final String PREFERENCES_NAME = "safekey_auto_lock";
    public static final long DEFAULT_TIMEOUT_MILLIS =
            VaultSessionManager.DEFAULT_INACTIVITY_TIMEOUT_MILLIS;

    private static final String KEY_TIMEOUT_MILLIS = "inactivity_timeout_millis";
    private static final long ONE_MINUTE_MILLIS = 60_000L;
    private static final long FIFTEEN_MINUTES_MILLIS = 15 * ONE_MINUTE_MILLIS;

    interface Store {
        long readTimeoutMillis();
        boolean writeTimeoutMillis(long timeoutMillis);
    }

    private final Store store;

    public AutoLockPreferences(Context context) {
        this(androidStore(context));
    }

    AutoLockPreferences(Store store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    public static long[] getSupportedTimeoutsMillis() {
        return new long[]{
                ONE_MINUTE_MILLIS,
                DEFAULT_TIMEOUT_MILLIS,
                FIFTEEN_MINUTES_MILLIS
        };
    }

    public static boolean isSupportedTimeoutMillis(long timeoutMillis) {
        return timeoutMillis == ONE_MINUTE_MILLIS
                || timeoutMillis == DEFAULT_TIMEOUT_MILLIS
                || timeoutMillis == FIFTEEN_MINUTES_MILLIS;
    }

    public synchronized long getTimeoutMillis() {
        final long saved;
        try {
            saved = store.readTimeoutMillis();
        } catch (ClassCastException corruptPreferenceType) {
            return DEFAULT_TIMEOUT_MILLIS;
        }
        return isSupportedTimeoutMillis(saved)
                ? saved : DEFAULT_TIMEOUT_MILLIS;
    }

    /**
     * Saves a supported policy. Failed persistence throws, so callers must
     * apply the running-session update only after this returns successfully.
     */
    public synchronized void setTimeoutMillis(long timeoutMillis) {
        if (!isSupportedTimeoutMillis(timeoutMillis)) {
            throw new IllegalArgumentException(
                    "Supported auto-lock timeouts are 1, 5 and 15 minutes.");
        }

        long previous = getTimeoutMillis();
        final boolean saved;
        try {
            saved = store.writeTimeoutMillis(timeoutMillis);
        } catch (RuntimeException failure) {
            restorePrevious(previous, failure);
            throw failure;
        }
        if (!saved) {
            IllegalStateException failure =
                    new IllegalStateException("Unable to save auto-lock timeout.");
            restorePrevious(previous, failure);
            throw failure;
        }
    }

    private void restorePrevious(long previous, RuntimeException failure) {
        // SharedPreferences can change its memory cache even when commit fails.
        try {
            if (!store.writeTimeoutMillis(previous)) {
                failure.addSuppressed(new IllegalStateException(
                        "Unable to restore the previous auto-lock timeout."));
            }
        } catch (RuntimeException rollbackFailure) {
            if (rollbackFailure != failure) {
                failure.addSuppressed(rollbackFailure);
            }
        }
    }

    private static Store androidStore(Context supplied) {
        Context app = Objects.requireNonNull(
                Objects.requireNonNull(supplied, "context")
                        .getApplicationContext(),
                "applicationContext");
        SharedPreferences preferences =
                app.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
        return new Store() {
            @Override
            public long readTimeoutMillis() {
                return preferences.getLong(
                        KEY_TIMEOUT_MILLIS, DEFAULT_TIMEOUT_MILLIS);
            }

            @Override
            public boolean writeTimeoutMillis(long timeoutMillis) {
                return preferences.edit()
                        .putLong(KEY_TIMEOUT_MILLIS, timeoutMillis)
                        .commit();
            }
        };
    }
}

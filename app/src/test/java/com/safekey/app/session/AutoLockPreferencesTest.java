package com.safekey.app.session;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AutoLockPreferencesTest {

    @Test
    public void default_isFiveMinutes() {
        assertEquals(300_000L,
                new AutoLockPreferences(new MemoryStore()).getTimeoutMillis());
    }

    @Test
    public void everySupportedOption_roundTrips() {
        MemoryStore store = new MemoryStore();
        AutoLockPreferences preferences = new AutoLockPreferences(store);
        for (long timeout : AutoLockPreferences.getSupportedTimeoutsMillis()) {
            preferences.setTimeoutMillis(timeout);
            assertEquals(timeout, preferences.getTimeoutMillis());
        }
    }

    @Test
    public void anotherInstance_readsSavedPolicy() {
        MemoryStore store = new MemoryStore();
        new AutoLockPreferences(store).setTimeoutMillis(60_000L);
        assertEquals(60_000L,
                new AutoLockPreferences(store).getTimeoutMillis());
    }

    @Test
    public void unsupportedSavedValues_useDefault() {
        MemoryStore store = new MemoryStore();
        AutoLockPreferences preferences = new AutoLockPreferences(store);
        for (long unsupported : new long[]{
                -1L, 0L, 1L, 120_000L, Long.MAX_VALUE}) {
            store.value = unsupported;
            assertEquals(300_000L, preferences.getTimeoutMillis());
        }
    }

    @Test
    public void corruptPreferenceType_usesDefaultAndCanBeReplaced() {
        MemoryStore store = new MemoryStore();
        store.value = "invalid preference type";
        AutoLockPreferences preferences = new AutoLockPreferences(store);
        assertEquals(300_000L, preferences.getTimeoutMillis());
        preferences.setTimeoutMillis(60_000L);
        assertEquals(60_000L, preferences.getTimeoutMillis());
    }

    @Test
    public void invalidRequestedValues_neverWrite() {
        MemoryStore store = new MemoryStore();
        AutoLockPreferences preferences = new AutoLockPreferences(store);
        for (long unsupported : new long[]{0L, -1L, 120_000L, Long.MAX_VALUE}) {
            assertThrows(IllegalArgumentException.class,
                    () -> preferences.setTimeoutMillis(unsupported));
        }
        assertEquals(0, store.writes);
        assertEquals(300_000L, preferences.getTimeoutMillis());
    }

    @Test
    public void optionsArray_cannotModifySupportedPolicy() {
        long[] options = AutoLockPreferences.getSupportedTimeoutsMillis();
        assertArrayEquals(new long[]{60_000L, 300_000L, 900_000L}, options);
        options[0] = 0L;
        assertArrayEquals(new long[]{60_000L, 300_000L, 900_000L},
                AutoLockPreferences.getSupportedTimeoutsMillis());
    }

    @Test
    public void failedCommit_restoresPreviousMemoryValueAndThrows() {
        MemoryStore store = new MemoryStore();
        store.value = 60_000L;
        store.failedWrites = 1;
        AutoLockPreferences preferences = new AutoLockPreferences(store);
        assertThrows(IllegalStateException.class,
                () -> preferences.setTimeoutMillis(900_000L));
        assertEquals(60_000L, preferences.getTimeoutMillis());
        assertEquals(2, store.writes);
    }

    @Test
    public void throwingCommit_restoresPreviousValueAndPreservesFailure() {
        MemoryStore store = new MemoryStore();
        store.value = 900_000L;
        store.throwingWrites = 1;
        AutoLockPreferences preferences = new AutoLockPreferences(store);
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> preferences.setTimeoutMillis(60_000L));
        assertEquals("Simulated persistence exception.", error.getMessage());
        assertEquals(900_000L, preferences.getTimeoutMillis());
    }

    @Test
    public void failedRollback_isReportedAsSuppressedFailure() {
        MemoryStore store = new MemoryStore();
        store.failedWrites = 2;
        AutoLockPreferences preferences = new AutoLockPreferences(store);
        IllegalStateException error = assertThrows(
                IllegalStateException.class,
                () -> preferences.setTimeoutMillis(60_000L));
        assertEquals(1, error.getSuppressed().length);
        assertTrue(error.getSuppressed()[0] instanceof IllegalStateException);
    }

    @Test
    public void unexpectedReadFailure_isNotHidden() {
        AutoLockPreferences preferences =
                new AutoLockPreferences(new AutoLockPreferences.Store() {
                    @Override public long readTimeoutMillis() {
                        throw new IllegalStateException("Simulated read failure.");
                    }
                    @Override public boolean writeTimeoutMillis(long value) {
                        throw new AssertionError("Write should not occur.");
                    }
                });
        assertThrows(IllegalStateException.class, preferences::getTimeoutMillis);
    }

    @Test
    public void missingStore_isRejected() {
        assertThrows(NullPointerException.class,
                () -> new AutoLockPreferences((AutoLockPreferences.Store) null));
    }

    private static final class MemoryStore implements AutoLockPreferences.Store {
        private Object value = 300_000L;
        private int writes;
        private int failedWrites;
        private int throwingWrites;

        @Override
        public long readTimeoutMillis() {
            return (Long) value;
        }

        @Override
        public boolean writeTimeoutMillis(long timeoutMillis) {
            writes++;
            // Model SharedPreferences updating memory before persistence.
            value = timeoutMillis;
            if (throwingWrites > 0) {
                throwingWrites--;
                throw new IllegalArgumentException(
                        "Simulated persistence exception.");
            }
            if (failedWrites > 0) {
                failedWrites--;
                return false;
            }
            return true;
        }
    }
}

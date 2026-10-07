package com.safekey.app.security.storage;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class VaultKeyEnvelopeStoreInstrumentedTest {

    private static final String WRAPPED_DATABASE_KEY =
            "SK1.AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBB";

    private Context context;

    private VaultKeyEnvelopeStore store;

    @Before
    public void setUp() {
        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        clearPreferences();

        store =
                new VaultKeyEnvelopeStore(
                        context
                );
    }

    @After
    public void tearDown() {
        clearPreferences();

        store = null;
        context = null;
    }

    @Test
    public void load_withoutStoredEnvelope_returnsNull() {
        assertFalse(
                store.hasEnvelope()
        );

        assertNull(
                store.load()
        );
    }

    @Test
    public void load_withIncorrectStoredFieldType_reportsInvalidEnvelope() {

        store.save(
                new VaultKeyEnvelope(
                        createSalt(),
                        WRAPPED_DATABASE_KEY
                )
        );

        SharedPreferences preferences =
                context.getSharedPreferences(
                        VaultKeyEnvelopeStore.PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                );

        boolean corrupted =
                preferences
                        .edit()
                        .putString(
                                VaultKeyEnvelopeStore.KEY_FORMAT_VERSION,
                                "not-an-integer"
                        )
                        .commit();

        assertTrue(
                corrupted
        );

        IllegalStateException exception =
                assertThrows(
                        IllegalStateException.class,
                        store::load
                );

        assertEquals(
                "Stored vault key envelope is invalid.",
                exception.getMessage()
        );
    }

    @Test
    public void saveAndLoad_preservesEnvelope() {
        byte[] salt =
                createSalt();

        VaultKeyEnvelope envelope =
                new VaultKeyEnvelope(
                        salt,
                        WRAPPED_DATABASE_KEY
                );

        store.save(
                envelope
        );

        assertTrue(
                store.hasEnvelope()
        );

        VaultKeyEnvelope loadedEnvelope =
                store.load();

        assertEquals(
                VaultKeyEnvelope.CURRENT_FORMAT_VERSION,
                loadedEnvelope.getFormatVersion()
        );

        assertArrayEquals(
                salt,
                loadedEnvelope.getSalt()
        );

        assertEquals(
                WRAPPED_DATABASE_KEY,
                loadedEnvelope.getWrappedDatabaseKey()
        );
    }

    @Test
    public void save_persistsAcrossStoreInstances() {
        byte[] salt =
                createSalt();

        store.save(
                new VaultKeyEnvelope(
                        salt,
                        WRAPPED_DATABASE_KEY
                )
        );

        VaultKeyEnvelopeStore reopenedStore =
                new VaultKeyEnvelopeStore(
                        context
                );

        VaultKeyEnvelope loadedEnvelope =
                reopenedStore.load();

        assertArrayEquals(
                salt,
                loadedEnvelope.getSalt()
        );

        assertEquals(
                WRAPPED_DATABASE_KEY,
                loadedEnvelope.getWrappedDatabaseKey()
        );
    }

    @Test
    public void clear_removesStoredEnvelope() {
        store.save(
                new VaultKeyEnvelope(
                        createSalt(),
                        WRAPPED_DATABASE_KEY
                )
        );

        store.clear();

        assertFalse(
                store.hasEnvelope()
        );

        assertNull(
                store.load()
        );
    }

    @Test
    public void load_incompleteEnvelope_throwsIllegalStateException() {
        preferences()
                .edit()
                .putInt(
                        VaultKeyEnvelopeStore.KEY_FORMAT_VERSION,
                        VaultKeyEnvelope.CURRENT_FORMAT_VERSION
                )
                .commit();

        assertTrue(
                store.hasEnvelope()
        );

        IllegalStateException exception =
                assertThrows(
                        IllegalStateException.class,
                        store::load
                );

        assertEquals(
                "Stored vault key envelope is invalid.",
                exception.getMessage()
        );
    }

    @Test
    public void load_invalidSaltEncoding_throwsIllegalStateException() {
        preferences()
                .edit()
                .putInt(
                        VaultKeyEnvelopeStore.KEY_FORMAT_VERSION,
                        VaultKeyEnvelope.CURRENT_FORMAT_VERSION
                )
                .putString(
                        VaultKeyEnvelopeStore.KEY_SALT,
                        "%%%not-valid-base64%%%"
                )
                .putString(
                        VaultKeyEnvelopeStore.KEY_WRAPPED_DATABASE_KEY,
                        WRAPPED_DATABASE_KEY
                )
                .commit();

        IllegalStateException exception =
                assertThrows(
                        IllegalStateException.class,
                        store::load
                );

        assertEquals(
                "Stored vault key envelope is invalid.",
                exception.getMessage()
        );
    }

    @Test
    public void load_wrongSaltLength_throwsIllegalStateException() {
        preferences()
                .edit()
                .putInt(
                        VaultKeyEnvelopeStore.KEY_FORMAT_VERSION,
                        VaultKeyEnvelope.CURRENT_FORMAT_VERSION
                )
                .putString(
                        VaultKeyEnvelopeStore.KEY_SALT,
                        "AQID"
                )
                .putString(
                        VaultKeyEnvelopeStore.KEY_WRAPPED_DATABASE_KEY,
                        WRAPPED_DATABASE_KEY
                )
                .commit();

        IllegalStateException exception =
                assertThrows(
                        IllegalStateException.class,
                        store::load
                );

        assertEquals(
                "Stored vault key envelope is invalid.",
                exception.getMessage()
        );
    }

    @Test
    public void load_unsupportedVersion_throwsIllegalStateException() {
        store.save(
                new VaultKeyEnvelope(
                        createSalt(),
                        WRAPPED_DATABASE_KEY
                )
        );

        preferences()
                .edit()
                .putInt(
                        VaultKeyEnvelopeStore.KEY_FORMAT_VERSION,
                        VaultKeyEnvelope.CURRENT_FORMAT_VERSION
                                + 1
                )
                .commit();

        IllegalStateException exception =
                assertThrows(
                        IllegalStateException.class,
                        store::load
                );

        assertEquals(
                "Stored vault key envelope is invalid.",
                exception.getMessage()
        );
    }

    private SharedPreferences preferences() {
        return context.getSharedPreferences(
                VaultKeyEnvelopeStore.PREFERENCES_NAME,
                Context.MODE_PRIVATE
        );
    }

    private void clearPreferences() {
        if (context == null) {
            return;
        }

        context
                .getSharedPreferences(
                        VaultKeyEnvelopeStore.PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                )
                .edit()
                .clear()
                .commit();
    }

    private static byte[] createSalt() {
        byte[] salt =
                new byte[
                        Argon2idMasterKeyDeriver
                                .SALT_LENGTH_BYTES
                        ];

        for (
                int index = 0;
                index < salt.length;
                index++
        ) {
            salt[index] =
                    (byte) (
                            index + 1
                    );
        }

        return salt;
    }
}

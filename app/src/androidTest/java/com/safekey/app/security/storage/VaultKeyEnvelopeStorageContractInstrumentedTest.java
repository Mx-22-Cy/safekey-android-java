package com.safekey.app.security.storage;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class VaultKeyEnvelopeStorageContractInstrumentedTest {

    private static final String FIRST_WRAPPED_KEY =
            "SK1.AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBB";

    private static final String REPLACEMENT_WRAPPED_KEY =
            "SK1.CCCCCCCCCCCCCCCC.DDDDDDDDDDDDDDDD";

    private Context context;

    @Before
    public void setUp() {
        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        clearPreferences();
    }

    @After
    public void tearDown() {
        clearPreferences();

        context = null;
    }

    @Test
    public void primaryStore_canBeUsedThroughStorageInterface() {
        VaultKeyEnvelopeStorage storage =
                new VaultKeyEnvelopeStore(
                        context
                );

        assertFalse(
                storage.hasEnvelope()
        );

        assertNull(
                storage.load()
        );

        byte[] salt =
                createSalt(
                        1
                );

        storage.save(
                new VaultKeyEnvelope(
                        salt,
                        FIRST_WRAPPED_KEY
                )
        );

        assertTrue(
                storage.hasEnvelope()
        );

        VaultKeyEnvelope loaded =
                storage.load();

        assertArrayEquals(
                salt,
                loaded.getSalt()
        );

        assertEquals(
                FIRST_WRAPPED_KEY,
                loaded.getWrappedDatabaseKey()
        );
    }

    @Test
    public void storageInterface_canReplaceProtectedEnvelope() {
        VaultKeyEnvelopeStorage storage =
                new VaultKeyEnvelopeStore(
                        context
                );

        byte[] firstSalt =
                createSalt(
                        1
                );

        byte[] replacementSalt =
                createSalt(
                        50
                );

        storage.save(
                new VaultKeyEnvelope(
                        firstSalt,
                        FIRST_WRAPPED_KEY
                )
        );

        storage.save(
                new VaultKeyEnvelope(
                        replacementSalt,
                        REPLACEMENT_WRAPPED_KEY
                )
        );

        VaultKeyEnvelope loaded =
                storage.load();

        assertArrayEquals(
                replacementSalt,
                loaded.getSalt()
        );

        assertEquals(
                REPLACEMENT_WRAPPED_KEY,
                loaded.getWrappedDatabaseKey()
        );
    }

    @Test
    public void storageInterface_canClearProtectedEnvelope() {
        VaultKeyEnvelopeStorage storage =
                new VaultKeyEnvelopeStore(
                        context
                );

        storage.save(
                new VaultKeyEnvelope(
                        createSalt(
                                5
                        ),
                        FIRST_WRAPPED_KEY
                )
        );

        assertTrue(
                storage.hasEnvelope()
        );

        storage.clear();

        assertFalse(
                storage.hasEnvelope()
        );

        assertNull(
                storage.load()
        );
    }

    @Test
    public void primaryAndDecoyStores_shareContractButNotStorage() {
        VaultKeyEnvelopeStorage primaryStorage =
                new VaultKeyEnvelopeStore(
                        context
                );

        VaultKeyEnvelopeStorage decoyStorage =
                VaultKeyEnvelopeStore.forDecoy(
                        context
                );

        primaryStorage.save(
                new VaultKeyEnvelope(
                        createSalt(
                                1
                        ),
                        FIRST_WRAPPED_KEY
                )
        );

        assertTrue(
                primaryStorage.hasEnvelope()
        );

        assertFalse(
                decoyStorage.hasEnvelope()
        );

        decoyStorage.save(
                new VaultKeyEnvelope(
                        createSalt(
                                50
                        ),
                        REPLACEMENT_WRAPPED_KEY
                )
        );

        assertEquals(
                FIRST_WRAPPED_KEY,
                primaryStorage
                        .load()
                        .getWrappedDatabaseKey()
        );

        assertEquals(
                REPLACEMENT_WRAPPED_KEY,
                decoyStorage
                        .load()
                        .getWrappedDatabaseKey()
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

        context
                .getSharedPreferences(
                        VaultKeyEnvelopeStore.DECOY_PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                )
                .edit()
                .clear()
                .commit();
    }

    private static byte[] createSalt(
            int startingValue
    ) {
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
                            startingValue
                                    + index
                    );
        }

        return salt;
    }
}

package com.safekey.app.security.keystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class BiometricKeyEnvelopeStoreInstrumentedTest {

    private Context context;

    private BiometricKeyEnvelopeStore store;

    @Before
    public void setUp() {

        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        store =
                new BiometricKeyEnvelopeStore(
                        context
                );

        store.clear();
    }

    @After
    public void tearDown() {

        if (store != null) {
            store.clear();
        }
    }

    @Test
    public void saveLoadAndClearPreservesEncryptedEnvelope() {

        byte[] iv =
                new byte[]{
                        1, 2, 3, 4,
                        5, 6, 7, 8,
                        9, 10, 11, 12
                };

        byte[] ciphertext =
                new byte[]{
                        21, 22, 23, 24,
                        25, 26, 27, 28,
                        29, 30, 31, 32,
                        33, 34, 35, 36
                };

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                new BiometricVaultKeyProtector.WrappedKey(
                        iv,
                        ciphertext
                );

        assertFalse(
                store.hasEnvelope()
        );

        store.save(
                wrappedKey
        );

        assertTrue(
                store.hasEnvelope()
        );

        BiometricVaultKeyProtector.WrappedKey loaded =
                store.load();

        assertNotNull(
                loaded
        );

        assertArrayEquals(
                iv,
                loaded.getIv()
        );

        assertArrayEquals(
                ciphertext,
                loaded.getCiphertext()
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
    public void missingEnvelopeReturnsNull() {

        assertFalse(
                store.hasEnvelope()
        );

        assertNull(
                store.load()
        );
    }

    @Test
    public void nullWrappedKeyIsRejected() {

        try {

            store.save(
                    null
            );

            fail(
                    "Expected null wrapped key to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }
    }
}
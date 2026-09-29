package com.safekey.app.security.keystore;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class BiometricKeyStoreInstrumentedTest {

    private BiometricKeyStore keyStore;

    @Before
    public void setUp()
            throws Exception {

        keyStore =
                new BiometricKeyStore();

        keyStore.deleteKey();

        assertFalse(
                keyStore.containsKey()
        );
    }

    @After
    public void tearDown()
            throws Exception {

        if (keyStore != null) {

            keyStore.deleteKey();
        }
    }

    @Test
    public void decryptionDoesNotCreateMissingKey()
            throws Exception {

        byte[] iv =
                new byte[]{
                        1, 2, 3, 4,
                        5, 6, 7, 8,
                        9, 10, 11, 12
                };

        try {

            keyStore.createDecryptionCipher(
                    iv
            );

            fail(
                    "Expected missing biometric key to be rejected."
            );

        } catch (BiometricKeyStore.BiometricKeyMissingException expected) {

            assertNotNull(
                    expected
            );
        }

        /*
         * The unlock path must not silently create
         * a replacement Android Keystore key.
         */
        assertFalse(
                keyStore.containsKey()
        );
    }

    @Test
    public void decryptionRejectsInvalidIvLength()
            throws Exception {

        try {

            keyStore.createDecryptionCipher(
                    new byte[11]
            );

            fail(
                    "Expected short IV to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }

        assertFalse(
                keyStore.containsKey()
        );

        try {

            keyStore.createDecryptionCipher(
                    new byte[13]
            );

            fail(
                    "Expected long IV to be rejected."
            );

        } catch (IllegalArgumentException expected) {

            assertNotNull(
                    expected
            );
        }

        assertFalse(
                keyStore.containsKey()
        );
    }
}
package com.safekey.app.security.keystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.Base64;

@RunWith(AndroidJUnit4.class)
public class BiometricKeyEnvelopeStoreInstrumentedTest {

    private Context context;

    private BiometricKeyEnvelopeStore store;

    private SharedPreferences preferences;

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

        preferences =
                context.getSharedPreferences(
                        BiometricKeyEnvelopeStore
                                .PREFERENCES_NAME,
                        Context.MODE_PRIVATE
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
                validIv();

        byte[] ciphertext =
                validCiphertext();

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

    @Test
    public void incompleteEnvelopeIsRejected() {

        preferences.edit()
                .putInt(
                        BiometricKeyEnvelopeStore.KEY_VERSION,
                        BiometricKeyEnvelopeStore.ENVELOPE_VERSION
                )
                .putString(
                        BiometricKeyEnvelopeStore.KEY_IV,
                        encode(
                                validIv()
                        )
                )
                .commit();

        try {

            store.load();

            fail(
                    "Expected incomplete envelope to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void unsupportedEnvelopeVersionIsRejected() {

        writeRawEnvelope(
                2,
                encode(
                        validIv()
                ),
                encode(
                        validCiphertext()
                )
        );

        try {

            store.load();

            fail(
                    "Expected unsupported envelope version to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void malformedBase64IsRejected() {

        writeRawEnvelope(
                BiometricKeyEnvelopeStore.ENVELOPE_VERSION,
                "%%%not-valid-base64%%%",
                encode(
                        validCiphertext()
                )
        );

        try {

            store.load();

            fail(
                    "Expected malformed Base64 to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void corruptStoredFieldTypeIsRejected() {

        preferences.edit()
                .putString(
                        BiometricKeyEnvelopeStore.KEY_VERSION,
                        "one"
                )
                .putString(
                        BiometricKeyEnvelopeStore.KEY_IV,
                        encode(
                                validIv()
                        )
                )
                .putString(
                        BiometricKeyEnvelopeStore.KEY_CIPHERTEXT,
                        encode(
                                validCiphertext()
                        )
                )
                .commit();

        try {

            store.load();

            fail(
                    "Expected corrupt stored field type to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void invalidIvLengthIsRejected() {

        writeRawEnvelope(
                BiometricKeyEnvelopeStore.ENVELOPE_VERSION,
                encode(
                        new byte[11]
                ),
                encode(
                        validCiphertext()
                )
        );

        try {

            store.load();

            fail(
                    "Expected invalid IV length to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void shortCiphertextIsRejected() {

        writeRawEnvelope(
                BiometricKeyEnvelopeStore.ENVELOPE_VERSION,
                encode(
                        validIv()
                ),
                encode(
                        new byte[47]
                )
        );

        try {

            store.load();

            fail(
                    "Expected short ciphertext to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void longCiphertextIsRejected() {

        writeRawEnvelope(
                BiometricKeyEnvelopeStore.ENVELOPE_VERSION,
                encode(
                        validIv()
                ),
                encode(
                        new byte[49]
                )
        );

        try {

            store.load();

            fail(
                    "Expected long ciphertext to be rejected."
            );

        } catch (IllegalStateException expected) {

            assertNotNull(
                    expected
            );
        }
    }

    @Test
    public void loadedEnvelopeUsesDefensiveCopies() {

        byte[] originalIv =
                validIv();

        byte[] originalCiphertext =
                validCiphertext();

        BiometricVaultKeyProtector.WrappedKey wrappedKey =
                new BiometricVaultKeyProtector.WrappedKey(
                        originalIv,
                        originalCiphertext
                );

        store.save(
                wrappedKey
        );

        BiometricVaultKeyProtector.WrappedKey loaded =
                store.load();

        assertNotNull(
                loaded
        );

        byte[] returnedIv =
                loaded.getIv();

        byte[] returnedCiphertext =
                loaded.getCiphertext();

        returnedIv[0] ^= 0x01;
        returnedCiphertext[0] ^= 0x01;

        assertArrayEquals(
                originalIv,
                loaded.getIv()
        );

        assertArrayEquals(
                originalCiphertext,
                loaded.getCiphertext()
        );
    }

    private void writeRawEnvelope(
            int version,
            String encodedIv,
            String encodedCiphertext
    ) {

        preferences.edit()
                .putInt(
                        BiometricKeyEnvelopeStore.KEY_VERSION,
                        version
                )
                .putString(
                        BiometricKeyEnvelopeStore.KEY_IV,
                        encodedIv
                )
                .putString(
                        BiometricKeyEnvelopeStore.KEY_CIPHERTEXT,
                        encodedCiphertext
                )
                .commit();
    }

    private String encode(
            byte[] value
    ) {

        return Base64.getEncoder()
                .encodeToString(
                        value
                );
    }

    private byte[] validIv() {

        return new byte[]{
                1, 2, 3, 4,
                5, 6, 7, 8,
                9, 10, 11, 12
        };
    }

    private byte[] validCiphertext() {

        byte[] ciphertext =
                new byte[48];

        for (int index = 0;
             index < ciphertext.length;
             index++) {

            ciphertext[index] =
                    (byte) (
                            index + 1
                    );
        }

        return ciphertext;
    }
}
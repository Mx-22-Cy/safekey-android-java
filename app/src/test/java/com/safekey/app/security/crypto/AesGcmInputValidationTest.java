package com.safekey.app.security.crypto;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class AesGcmInputValidationTest {

    private static final byte[] VALID_KEY =
            new byte[AesGcmCipher.KEY_LENGTH_BYTES];

    private static final byte[] ASSOCIATED_DATA =
            "safekey:test:v1".getBytes(
                    StandardCharsets.UTF_8
            );

    @Test(expected = NullPointerException.class)
    public void constructor_nullSecureRandom_throwsNullPointerException() {
        new AesGcmCipher(null);
    }

    @Test(expected = NullPointerException.class)
    public void encrypt_nullPlaintext_throwsNullPointerException()
            throws AesGcmException {

        new AesGcmCipher().encrypt(
                null,
                VALID_KEY,
                ASSOCIATED_DATA
        );
    }

    @Test(expected = NullPointerException.class)
    public void encrypt_nullKey_throwsNullPointerException()
            throws AesGcmException {

        new AesGcmCipher().encrypt(
                new byte[0],
                null,
                ASSOCIATED_DATA
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void encrypt_shortKey_throwsIllegalArgumentException()
            throws AesGcmException {

        new AesGcmCipher().encrypt(
                new byte[0],
                new byte[
                        AesGcmCipher.KEY_LENGTH_BYTES - 1
                        ],
                ASSOCIATED_DATA
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void encrypt_longKey_throwsIllegalArgumentException()
            throws AesGcmException {

        new AesGcmCipher().encrypt(
                new byte[0],
                new byte[
                        AesGcmCipher.KEY_LENGTH_BYTES + 1
                        ],
                ASSOCIATED_DATA
        );
    }

    @Test(expected = NullPointerException.class)
    public void encrypt_nullAssociatedData_throwsNullPointerException()
            throws AesGcmException {

        new AesGcmCipher().encrypt(
                new byte[0],
                VALID_KEY,
                null
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void encrypt_emptyAssociatedData_throwsIllegalArgumentException()
            throws AesGcmException {

        new AesGcmCipher().encrypt(
                new byte[0],
                VALID_KEY,
                new byte[0]
        );
    }

    @Test(expected = NullPointerException.class)
    public void decrypt_nullEncryptedValue_throwsNullPointerException()
            throws AesGcmException {

        new AesGcmCipher().decrypt(
                null,
                VALID_KEY,
                ASSOCIATED_DATA
        );
    }

    @Test
    public void decrypt_invalidNonceLength_throwsSafeException() {
        String envelope =
                createEnvelope(
                        new byte[
                                AesGcmCipher.NONCE_LENGTH_BYTES - 1
                                ],
                        new byte[16]
                );

        assertSafeDecryptionFailure(envelope);
    }

    @Test
    public void decrypt_valueShorterThanAuthenticationTag_throwsSafeException() {
        String envelope =
                createEnvelope(
                        new byte[
                                AesGcmCipher.NONCE_LENGTH_BYTES
                                ],
                        new byte[15]
                );

        assertSafeDecryptionFailure(envelope);
    }

    @Test
    public void encrypt_doesNotModifyCallerArrays()
            throws AesGcmException {

        byte[] plaintext =
                "credential secret".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] key =
                createKey();

        byte[] associatedData =
                Arrays.copyOf(
                        ASSOCIATED_DATA,
                        ASSOCIATED_DATA.length
                );

        byte[] expectedPlaintext =
                Arrays.copyOf(
                        plaintext,
                        plaintext.length
                );

        byte[] expectedKey =
                Arrays.copyOf(
                        key,
                        key.length
                );

        byte[] expectedAssociatedData =
                Arrays.copyOf(
                        associatedData,
                        associatedData.length
                );

        new AesGcmCipher().encrypt(
                plaintext,
                key,
                associatedData
        );

        assertArrayEquals(
                expectedPlaintext,
                plaintext
        );

        assertArrayEquals(
                expectedKey,
                key
        );

        assertArrayEquals(
                expectedAssociatedData,
                associatedData
        );
    }

    @Test
    public void decrypt_doesNotModifyCallerArrays()
            throws AesGcmException {

        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] plaintext =
                "credential secret".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] key =
                createKey();

        byte[] associatedData =
                Arrays.copyOf(
                        ASSOCIATED_DATA,
                        ASSOCIATED_DATA.length
                );

        String encryptedValue =
                cipher.encrypt(
                        plaintext,
                        key,
                        associatedData
                );

        byte[] expectedKey =
                Arrays.copyOf(
                        key,
                        key.length
                );

        byte[] expectedAssociatedData =
                Arrays.copyOf(
                        associatedData,
                        associatedData.length
                );

        byte[] decrypted =
                cipher.decrypt(
                        encryptedValue,
                        key,
                        associatedData
                );

        assertArrayEquals(
                plaintext,
                decrypted
        );

        assertArrayEquals(
                expectedKey,
                key
        );

        assertArrayEquals(
                expectedAssociatedData,
                associatedData
        );
    }

    private String createEnvelope(
            byte[] nonce,
            byte[] ciphertextAndTag
    ) {
        Base64.Encoder encoder =
                Base64.getUrlEncoder()
                        .withoutPadding();

        return AesGcmCipher.ENVELOPE_VERSION
                + "."
                + encoder.encodeToString(nonce)
                + "."
                + encoder.encodeToString(
                ciphertextAndTag
        );
    }

    private void assertSafeDecryptionFailure(
            String envelope
    ) {
        try {
            new AesGcmCipher().decrypt(
                    envelope,
                    VALID_KEY,
                    ASSOCIATED_DATA
            );

            fail(
                    "Expected decryption to fail."
            );

        } catch (AesGcmException exception) {
            assertEquals(
                    "Unable to decrypt protected data.",
                    exception.getMessage()
            );
        }
    }

    private byte[] createKey() {
        byte[] key =
                new byte[AesGcmCipher.KEY_LENGTH_BYTES];

        new SecureRandom().nextBytes(key);

        return key;
    }
}

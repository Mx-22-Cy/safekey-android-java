package com.safekey.app.security.crypto;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AesGcmCipherTest {

    @Test
    public void configuration_matchesWeekFourPlan() {
        assertEquals(
                32,
                AesGcmCipher.KEY_LENGTH_BYTES
        );

        assertEquals(
                12,
                AesGcmCipher.NONCE_LENGTH_BYTES
        );

        assertEquals(
                128,
                AesGcmCipher.AUTHENTICATION_TAG_LENGTH_BITS
        );

        assertEquals(
                "SK1",
                AesGcmCipher.ENVELOPE_VERSION
        );
    }

    @Test
    public void encrypt_createsVersionedEnvelopeWithNonceAndTag()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] plaintext =
                "protected credential".getBytes(
                        StandardCharsets.UTF_8
                );

        String encryptedValue =
                cipher.encrypt(
                        plaintext,
                        createKey(0),
                        passwordContext()
                );

        String[] parts =
                encryptedValue.split(
                        "\\.",
                        -1
                );

        assertEquals(
                3,
                parts.length
        );

        assertEquals(
                AesGcmCipher.ENVELOPE_VERSION,
                parts[0]
        );

        byte[] nonce =
                Base64.getUrlDecoder()
                        .decode(parts[1]);

        byte[] ciphertextAndTag =
                Base64.getUrlDecoder()
                        .decode(parts[2]);

        assertEquals(
                AesGcmCipher.NONCE_LENGTH_BYTES,
                nonce.length
        );

        assertEquals(
                plaintext.length
                        + AesGcmCipher
                        .AUTHENTICATION_TAG_LENGTH_BITS
                        / 8,
                ciphertextAndTag.length
        );
    }

    @Test
    public void encryptThenDecrypt_unicodePlaintext_returnsOriginal()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] plaintext =
                "كلمة مرور آمنة جدًا 🔐".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] key =
                createKey(20);

        byte[] associatedData =
                passwordContext();

        String encryptedValue =
                cipher.encrypt(
                        plaintext,
                        key,
                        associatedData
                );

        byte[] decryptedValue =
                cipher.decrypt(
                        encryptedValue,
                        key,
                        associatedData
                );

        assertArrayEquals(
                plaintext,
                decryptedValue
        );
    }

    @Test
    public void encrypt_sameInputsTwice_returnsDifferentValues()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] plaintext =
                "same protected value".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] key =
                createKey(40);

        byte[] associatedData =
                passwordContext();

        String firstEncryptedValue =
                cipher.encrypt(
                        plaintext,
                        key,
                        associatedData
                );

        String secondEncryptedValue =
                cipher.encrypt(
                        plaintext,
                        key,
                        associatedData
                );

        assertNotEquals(
                firstEncryptedValue,
                secondEncryptedValue
        );
    }

    @Test
    public void encryptThenDecrypt_emptyPlaintext_returnsEmptyPlaintext()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] key =
                createKey(60);

        byte[] associatedData =
                notesContext();

        String encryptedValue =
                cipher.encrypt(
                        new byte[0],
                        key,
                        associatedData
                );

        byte[] decryptedValue =
                cipher.decrypt(
                        encryptedValue,
                        key,
                        associatedData
                );

        assertEquals(
                0,
                decryptedValue.length
        );
    }

    @Test
    public void decrypt_wrongKey_throwsSafeException()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        String encryptedValue =
                cipher.encrypt(
                        "protected value".getBytes(
                                StandardCharsets.UTF_8
                        ),
                        createKey(1),
                        passwordContext()
                );

        AesGcmException exception =
                assertThrows(
                        AesGcmException.class,
                        () -> cipher.decrypt(
                                encryptedValue,
                                createKey(2),
                                passwordContext()
                        )
                );

        assertEquals(
                "Unable to decrypt protected data.",
                exception.getMessage()
        );
    }

    @Test
    public void decrypt_wrongAssociatedData_throwsSafeException()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] key =
                createKey(80);

        String encryptedValue =
                cipher.encrypt(
                        "protected value".getBytes(
                                StandardCharsets.UTF_8
                        ),
                        key,
                        passwordContext()
                );

        AesGcmException exception =
                assertThrows(
                        AesGcmException.class,
                        () -> cipher.decrypt(
                                encryptedValue,
                                key,
                                notesContext()
                        )
                );

        assertEquals(
                "Unable to decrypt protected data.",
                exception.getMessage()
        );
    }

    @Test
    public void decrypt_modifiedNonce_throwsSafeException()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] key =
                createKey(100);

        String encryptedValue =
                cipher.encrypt(
                        "protected value".getBytes(
                                StandardCharsets.UTF_8
                        ),
                        key,
                        passwordContext()
                );

        String modifiedValue =
                modifyEnvelopePart(
                        encryptedValue,
                        1
                );

        assertThrows(
                AesGcmException.class,
                () -> cipher.decrypt(
                        modifiedValue,
                        key,
                        passwordContext()
                )
        );
    }

    @Test
    public void decrypt_modifiedCiphertextOrTag_throwsSafeException()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] key =
                createKey(120);

        String encryptedValue =
                cipher.encrypt(
                        "protected value".getBytes(
                                StandardCharsets.UTF_8
                        ),
                        key,
                        passwordContext()
                );

        String modifiedValue =
                modifyEnvelopePart(
                        encryptedValue,
                        2
                );

        assertThrows(
                AesGcmException.class,
                () -> cipher.decrypt(
                        modifiedValue,
                        key,
                        passwordContext()
                )
        );
    }

    @Test
    public void decrypt_malformedEnvelopes_throwSafeException() {
        AesGcmCipher cipher =
                new AesGcmCipher();

        String[] malformedValues = {
                "",
                "SK2.AA.AA",
                "SK1.only-two-parts",
                "SK1.!.!"
        };

        for (String malformedValue : malformedValues) {
            AesGcmException exception =
                    assertThrows(
                            AesGcmException.class,
                            () -> cipher.decrypt(
                                    malformedValue,
                                    createKey(0),
                                    passwordContext()
                            )
                    );

            assertEquals(
                    "Unable to decrypt protected data.",
                    exception.getMessage()
            );
        }
    }

    private static byte[] createKey(
            int startingValue
    ) {
        byte[] key =
                new byte[AesGcmCipher.KEY_LENGTH_BYTES];

        for (
                int index = 0;
                index < key.length;
                index++
        ) {
            key[index] =
                    (byte) (
                            startingValue
                                    + index
                    );
        }

        return key;
    }

    private static byte[] passwordContext() {
        return "safekey:credential:password:v1"
                .getBytes(
                        StandardCharsets.UTF_8
                );
    }

    private static byte[] notesContext() {
        return "safekey:credential:notes:v1"
                .getBytes(
                        StandardCharsets.UTF_8
                );
    }

    private static String modifyEnvelopePart(
            String encryptedValue,
            int partIndex
    ) {
        String[] parts =
                encryptedValue.split(
                        "\\.",
                        -1
                );

        byte[] decodedPart =
                Base64.getUrlDecoder()
                        .decode(parts[partIndex]);

        decodedPart[0] =
                (byte) (
                        decodedPart[0]
                                ^ 1
                );

        parts[partIndex] =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                decodedPart
                        );

        return parts[0]
                + "."
                + parts[1]
                + "."
                + parts[2];
    }
}

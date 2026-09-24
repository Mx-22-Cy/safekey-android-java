package com.safekey.app.security.crypto;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class AesGcmKnownAnswerTest {

    @Test
    public void encrypt_fixedAes256GcmVector_matchesExpectedResult()
            throws AesGcmException {
        byte[] key =
                decodeHex(
                        "feffe9928665731c6d6a8f9467308308"
                                + "feffe9928665731c6d6a8f9467308308"
                );

        byte[] nonce =
                decodeHex(
                        "cafebabefacedbaddecaf888"
                );

        byte[] plaintext =
                decodeHex(
                        "d9313225f88406e5a55909c5aff5269a"
                                + "86a7a9531534f7da2e4c303d8a318a72"
                                + "1c3c0c95956809532fcf0e2449a6b525"
                                + "b16aedf5aa0de657ba637b391aafd255"
                );

        byte[] associatedData =
                decodeHex(
                        "feedfacedeadbeeffeedfacedeadbeef"
                                + "abaddad2"
                );

        byte[] expectedCiphertext =
                decodeHex(
                        "522dc1f099567d07f47f37a32a84427d"
                                + "643a8cdcbfe5c0c97598a2bd2555d1aa"
                                + "8cb08e48590dbb3da7b08b1056828838"
                                + "c5f61e6393ba7a0abcc9f662898015ad"
                );

        byte[] expectedTag =
                decodeHex(
                        "2df7cd675b4f09163b41ebf980a7f638"
                );

        AesGcmCipher cipher =
                new AesGcmCipher(
                        new FixedSecureRandom(
                                nonce
                        )
                );

        String encryptedValue =
                cipher.encrypt(
                        plaintext,
                        key,
                        associatedData
                );

        String[] envelopeParts =
                encryptedValue.split(
                        "\\.",
                        -1
                );

        assertEquals(
                AesGcmCipher.ENVELOPE_VERSION,
                envelopeParts[0]
        );

        assertArrayEquals(
                nonce,
                Base64.getUrlDecoder()
                        .decode(envelopeParts[1])
        );

        assertArrayEquals(
                concatenate(
                        expectedCiphertext,
                        expectedTag
                ),
                Base64.getUrlDecoder()
                        .decode(envelopeParts[2])
        );
    }

    @Test
    public void decrypt_modifiedAuthenticationTag_throwsSafeException()
            throws AesGcmException {
        AesGcmCipher cipher =
                new AesGcmCipher();

        byte[] key =
                new byte[AesGcmCipher.KEY_LENGTH_BYTES];

        byte[] associatedData =
                new byte[]{1};

        String encryptedValue =
                cipher.encrypt(
                        new byte[]{10, 20, 30},
                        key,
                        associatedData
                );

        String[] envelopeParts =
                encryptedValue.split(
                        "\\.",
                        -1
                );

        byte[] ciphertextAndTag =
                Base64.getUrlDecoder()
                        .decode(envelopeParts[2]);

        int finalByteIndex =
                ciphertextAndTag.length - 1;

        ciphertextAndTag[finalByteIndex] =
                (byte) (
                        ciphertextAndTag[finalByteIndex]
                                ^ 1
                );

        envelopeParts[2] =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                ciphertextAndTag
                        );

        String modifiedValue =
                envelopeParts[0]
                        + "."
                        + envelopeParts[1]
                        + "."
                        + envelopeParts[2];

        AesGcmException exception =
                assertThrows(
                        AesGcmException.class,
                        () -> cipher.decrypt(
                                modifiedValue,
                                key,
                                associatedData
                        )
                );

        assertEquals(
                "Unable to decrypt protected data.",
                exception.getMessage()
        );
    }

    private static byte[] concatenate(
            byte[] first,
            byte[] second
    ) {
        byte[] result =
                Arrays.copyOf(
                        first,
                        first.length + second.length
                );

        System.arraycopy(
                second,
                0,
                result,
                first.length,
                second.length
        );

        return result;
    }

    private static byte[] decodeHex(
            String value
    ) {
        if (value.length() % 2 != 0) {
            throw new IllegalArgumentException(
                    "Hex value must contain complete bytes."
            );
        }

        byte[] result =
                new byte[value.length() / 2];

        for (
                int index = 0;
                index < result.length;
                index++
        ) {
            int characterIndex =
                    index * 2;

            int high =
                    Character.digit(
                            value.charAt(characterIndex),
                            16
                    );

            int low =
                    Character.digit(
                            value.charAt(characterIndex + 1),
                            16
                    );

            if (
                    high < 0
                            || low < 0
            ) {
                throw new IllegalArgumentException(
                        "Hex value contains an invalid character."
                );
            }

            result[index] =
                    (byte) (
                            high << 4
                                    | low
                    );
        }

        return result;
    }

    private static final class FixedSecureRandom
            extends SecureRandom {

        private final byte[] fixedBytes;

        private FixedSecureRandom(
                byte[] fixedBytes
        ) {
            this.fixedBytes =
                    Arrays.copyOf(
                            fixedBytes,
                            fixedBytes.length
                    );
        }

        @Override
        public void nextBytes(
                byte[] output
        ) {
            if (output.length != fixedBytes.length) {
                throw new IllegalArgumentException(
                        "Unexpected random-output length."
                );
            }

            System.arraycopy(
                    fixedBytes,
                    0,
                    output,
                    0,
                    fixedBytes.length
            );
        }
    }
}

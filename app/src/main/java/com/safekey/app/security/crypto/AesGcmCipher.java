package com.safekey.app.security.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcmCipher {

    public static final int KEY_LENGTH_BYTES = 32;
    public static final int NONCE_LENGTH_BYTES = 12;
    public static final int AUTHENTICATION_TAG_LENGTH_BITS = 128;
    public static final String ENVELOPE_VERSION = "SK1";

    private static final int AUTHENTICATION_TAG_LENGTH_BYTES =
            AUTHENTICATION_TAG_LENGTH_BITS / 8;

    private static final String TRANSFORMATION =
            "AES/GCM/NoPadding";

    private static final String KEY_ALGORITHM =
            "AES";

    private static final String SEPARATOR =
            ".";

    private static final String DECRYPTION_ERROR_MESSAGE =
            "Unable to decrypt protected data.";

    private static final Base64.Encoder BASE64_ENCODER =
            Base64.getUrlEncoder()
                    .withoutPadding();

    private static final Base64.Decoder BASE64_DECODER =
            Base64.getUrlDecoder();

    private final SecureRandom secureRandom;

    public AesGcmCipher() {
        this(new SecureRandom());
    }

    AesGcmCipher(
            SecureRandom secureRandom
    ) {
        this.secureRandom =
                Objects.requireNonNull(
                        secureRandom,
                        "secureRandom"
                );
    }

    public String encrypt(
            byte[] plaintext,
            byte[] key,
            byte[] associatedData
    ) throws AesGcmException {
        Objects.requireNonNull(
                plaintext,
                "plaintext"
        );

        validateKey(key);
        validateAssociatedData(associatedData);

        byte[] nonce =
                new byte[NONCE_LENGTH_BYTES];

        secureRandom.nextBytes(nonce);

        try {
            Cipher cipher =
                    initializeCipher(
                            Cipher.ENCRYPT_MODE,
                            key,
                            nonce,
                            associatedData
                    );

            byte[] ciphertextAndTag =
                    cipher.doFinal(plaintext);

            return ENVELOPE_VERSION
                    + SEPARATOR
                    + BASE64_ENCODER.encodeToString(
                    nonce
            )
                    + SEPARATOR
                    + BASE64_ENCODER.encodeToString(
                    ciphertextAndTag
            );

        } catch (GeneralSecurityException exception) {
            throw new AesGcmException(
                    "Unable to encrypt protected data.",
                    exception
            );
        }
    }

    public byte[] decrypt(
            String encryptedValue,
            byte[] key,
            byte[] associatedData
    ) throws AesGcmException {
        Objects.requireNonNull(
                encryptedValue,
                "encryptedValue"
        );

        validateKey(key);
        validateAssociatedData(associatedData);

        String[] envelopeParts =
                encryptedValue.split(
                        "\\.",
                        -1
                );

        if (
                envelopeParts.length != 3
                        || !ENVELOPE_VERSION.equals(
                        envelopeParts[0]
                )
        ) {
            throw new AesGcmException(
                    DECRYPTION_ERROR_MESSAGE
            );
        }

        byte[] nonce;
        byte[] ciphertextAndTag;

        try {
            nonce =
                    BASE64_DECODER.decode(
                            envelopeParts[1]
                    );

            ciphertextAndTag =
                    BASE64_DECODER.decode(
                            envelopeParts[2]
                    );

        } catch (IllegalArgumentException exception) {
            throw new AesGcmException(
                    DECRYPTION_ERROR_MESSAGE,
                    exception
            );
        }

        if (
                nonce.length != NONCE_LENGTH_BYTES
                        || ciphertextAndTag.length
                        < AUTHENTICATION_TAG_LENGTH_BYTES
        ) {
            throw new AesGcmException(
                    DECRYPTION_ERROR_MESSAGE
            );
        }

        try {
            Cipher cipher =
                    initializeCipher(
                            Cipher.DECRYPT_MODE,
                            key,
                            nonce,
                            associatedData
                    );

            return cipher.doFinal(
                    ciphertextAndTag
            );

        } catch (GeneralSecurityException exception) {
            throw new AesGcmException(
                    DECRYPTION_ERROR_MESSAGE,
                    exception
            );
        }
    }

    private Cipher initializeCipher(
            int operationMode,
            byte[] key,
            byte[] nonce,
            byte[] associatedData
    ) throws GeneralSecurityException {
        Cipher cipher =
                Cipher.getInstance(
                        TRANSFORMATION
                );

        SecretKeySpec secretKey =
                new SecretKeySpec(
                        key,
                        KEY_ALGORITHM
                );

        GCMParameterSpec parameters =
                new GCMParameterSpec(
                        AUTHENTICATION_TAG_LENGTH_BITS,
                        nonce
                );

        cipher.init(
                operationMode,
                secretKey,
                parameters
        );

        cipher.updateAAD(
                associatedData
        );

        return cipher;
    }

    private void validateKey(
            byte[] key
    ) {
        Objects.requireNonNull(
                key,
                "key"
        );

        if (key.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "AES-256 key must contain exactly "
                            + KEY_LENGTH_BYTES
                            + " bytes."
            );
        }
    }

    private void validateAssociatedData(
            byte[] associatedData
    ) {
        Objects.requireNonNull(
                associatedData,
                "associatedData"
        );

        if (associatedData.length == 0) {
            throw new IllegalArgumentException(
                    "Associated data must not be empty."
            );
        }
    }
}

package com.safekey.app.security.storage;

import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

final class RecoveryKeyProtector {

    private static final int RECOVERY_SECRET_BYTES = 16;
    private static final String HEX_DIGITS = "0123456789ABCDEF";
    private static final byte[] RECOVERY_CONTEXT =
            "safekey.recovery.database-key.v1".getBytes(StandardCharsets.UTF_8);

    private final Argon2idMasterKeyDeriver keyDeriver;
    private final AesGcmCipher cipher;
    private final SecureRandom secureRandom;

    RecoveryKeyProtector(
            Argon2idMasterKeyDeriver keyDeriver,
            AesGcmCipher cipher,
            SecureRandom secureRandom
    ) {
        this.keyDeriver = keyDeriver;
        this.cipher = cipher;
        this.secureRandom = secureRandom;
    }

    /** The caller owns and clears the returned Recovery key. */
    char[] generateRecoveryKey() {
        byte[] randomBytes = new byte[RECOVERY_SECRET_BYTES];
        try {
            secureRandom.nextBytes(randomBytes);
            char[] recoveryKey = new char[randomBytes.length * 2];
            for (int i = 0; i < randomBytes.length; i++) {
                int value = randomBytes[i] & 0xff;
                recoveryKey[i * 2] = HEX_DIGITS.charAt(value >>> 4);
                recoveryKey[i * 2 + 1] = HEX_DIGITS.charAt(value & 0x0f);
            }
            return recoveryKey;
        } finally {
            Arrays.fill(randomBytes, (byte) 0);
        }
    }

    /** The caller retains ownership of both input arrays. */
    VaultKeyEnvelope wrap(char[] recoveryKey, byte[] databaseKey) throws AesGcmException {
        byte[] salt = keyDeriver.generateSalt();
        byte[] wrappingKey = null;
        try {
            wrappingKey = deriveWrappingKey(recoveryKey, salt);
            String wrappedKey = cipher.encrypt(databaseKey, wrappingKey, RECOVERY_CONTEXT);
            return new VaultKeyEnvelope(salt, wrappedKey);
        } finally {
            if (wrappingKey != null) {
                Arrays.fill(wrappingKey, (byte) 0);
            }
            Arrays.fill(salt, (byte) 0);
        }
    }

    /** The caller owns and clears the returned database key. */
    byte[] unwrap(char[] recoveryKey, VaultKeyEnvelope envelope) throws AesGcmException {
        byte[] salt = envelope.getSalt();
        byte[] wrappingKey = null;
        try {
            wrappingKey = deriveWrappingKey(recoveryKey, salt);
            return cipher.decrypt(envelope.getWrappedDatabaseKey(), wrappingKey, RECOVERY_CONTEXT);
        } finally {
            if (wrappingKey != null) {
                Arrays.fill(wrappingKey, (byte) 0);
            }
            Arrays.fill(salt, (byte) 0);
        }
    }

    private byte[] deriveWrappingKey(char[] recoveryKey, byte[] salt) {
        if (recoveryKey == null || recoveryKey.length != RECOVERY_SECRET_BYTES * 2) {
            throw new IllegalArgumentException("Invalid Recovery key format.");
        }
        for (char digit : recoveryKey) {
            if (HEX_DIGITS.indexOf(digit) < 0) {
                throw new IllegalArgumentException("Invalid Recovery key format.");
            }
        }
        return keyDeriver.deriveKey(recoveryKey, salt);
    }
}

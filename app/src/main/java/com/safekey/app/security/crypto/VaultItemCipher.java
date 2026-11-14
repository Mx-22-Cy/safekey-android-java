package com.safekey.app.security.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * AES-GCM protection for the sensitive fields in one opened vault.
 *
 * <p>Create one instance from that vault's random database key. The caller
 * retains ownership of its database-key array and may erase it after the
 * constructor returns. This instance owns a purpose-separated derived key;
 * it does not retain the supplied database-key array.</p>
 *
 * <p>The database must persist a canonical UUID for each record before
 * encrypting its fields. Reuse that UUID on reads and edits. The UUID is
 * separate from a numeric row ID and is never regenerated for an edit.</p>
 *
 * <p>Format v1 uses the existing SK1 AES-GCM envelope and authenticates:
 * safekey:vault-item:v1:table:record-uuid:column. Explicit database migration
 * metadata must identify legacy values; failed decryption must not fall
 * back to plaintext. The KDF labels and associated-data format are part of
 * the persistent format and must remain stable for existing v1 records.</p>
 *
 * <p>Close during normal vault closure, failed opening, shutdown and Panic
 * cleanup. Close waits for an in-flight operation and erases this instance's
 * owned key array. JVM/provider copies and returned Strings cannot be
 * guaranteed erased. Session authorization and stale-callback rejection
 * remain the responsibility of the surrounding vault service.</p>
 */
public final class VaultItemCipher implements AutoCloseable {

    public static final int ENCRYPTION_VERSION = 1;

    private static final String KDF_SALT =
            "SafeKey:VaultItemCipher:HKDF-SHA256:v1";
    private static final String KDF_INFO =
            "SafeKey:item-fields:AES-256-GCM:v1";
    private static final String ASSOCIATED_DATA_PREFIX =
            "safekey:vault-item:v1:";

    public enum Field {
        CREDENTIAL_PASSWORD("credentials", "password_ciphertext"),
        CREDENTIAL_NOTES("credentials", "notes_ciphertext"),
        SECURE_NOTE_CONTENT("secure_notes", "content_ciphertext");

        private final String table;
        private final String column;

        Field(String table, String column) {
            this.table = table;
            this.column = column;
        }
    }

    private final AesGcmCipher cipher;
    private final byte[] itemKey;
    private boolean closed;

    public VaultItemCipher(byte[] databaseKey) {
        this(databaseKey, new AesGcmCipher());
    }

    // Allows the unit test to control nonce generation during a close race.
    VaultItemCipher(byte[] databaseKey, AesGcmCipher cipher) {
        Objects.requireNonNull(databaseKey, "databaseKey");
        this.cipher = Objects.requireNonNull(cipher, "cipher");
        if (databaseKey.length != AesGcmCipher.KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "Database key must contain exactly 32 bytes.");
        }

        byte[] keyCopy = databaseKey.clone();
        try {
            itemKey = hkdfSha256(
                    keyCopy,
                    KDF_SALT.getBytes(StandardCharsets.UTF_8),
                    KDF_INFO.getBytes(StandardCharsets.UTF_8),
                    AesGcmCipher.KEY_LENGTH_BYTES);
        } finally {
            Arrays.fill(keyCopy, (byte) 0);
        }
    }

    /**
     * Returns an SK1 envelope for a non-null value. Empty text is supported.
     * Password policy and record validation belong to the calling layer.
     */
    public synchronized String encrypt(
            Field field,
            String recordIdentity,
            String plaintext
    ) throws AesGcmException {
        requireOpen();
        byte[] associatedData = associatedData(field, recordIdentity);
        Objects.requireNonNull(plaintext, "plaintext");
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            return cipher.encrypt(plaintextBytes, itemKey, associatedData);
        } finally {
            Arrays.fill(plaintextBytes, (byte) 0);
        }
    }

    /**
     * Authenticates the key, field and record identity before returning text.
     * Malformed, legacy or unauthenticated values are rejected.
     */
    public synchronized String decrypt(
            Field field,
            String recordIdentity,
            String encryptedValue
    ) throws AesGcmException {
        requireOpen();
        byte[] associatedData = associatedData(field, recordIdentity);
        Objects.requireNonNull(encryptedValue, "encryptedValue");
        byte[] plaintextBytes = cipher.decrypt(
                encryptedValue, itemKey, associatedData);
        try {
            return new String(plaintextBytes, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintextBytes, (byte) 0);
        }
    }

    public synchronized boolean isClosed() {
        return closed;
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            closed = true;
            Arrays.fill(itemKey, (byte) 0);
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Vault item cipher is closed.");
        }
    }

    private static byte[] associatedData(
            Field field,
            String recordIdentity
    ) {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(recordIdentity, "recordIdentity");
        if (recordIdentity.length() != 36
                || !UUID.fromString(recordIdentity).toString()
                .equals(recordIdentity)) {
            throw new IllegalArgumentException(
                    "Record identity must be a canonical lowercase UUID.");
        }
        return (ASSOCIATED_DATA_PREFIX + field.table + ":"
                + recordIdentity + ":" + field.column)
                .getBytes(StandardCharsets.UTF_8);
    }

    // Package-private so RFC 5869 vectors can verify the KDF wrapper.
    // The caller owns the returned array. This is not a password KDF.
    static byte[] hkdfSha256(
            byte[] inputKeyMaterial,
            byte[] salt,
            byte[] info,
            int outputLength
    ) {
        Objects.requireNonNull(inputKeyMaterial, "inputKeyMaterial");
        if (outputLength <= 0 || outputLength > 255 * 32) {
            throw new IllegalArgumentException("Invalid HKDF output length.");
        }
        byte[] output = new byte[outputLength];
        try {
            HKDFBytesGenerator generator =
                    new HKDFBytesGenerator(new SHA256Digest());
            generator.init(new HKDFParameters(inputKeyMaterial, salt, info));
            generator.generateBytes(output, 0, output.length);
            return output;
        } catch (RuntimeException | Error failure) {
            Arrays.fill(output, (byte) 0);
            throw failure;
        }
    }
}

package com.safekey.app.security.totp;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Android persistence adapter. Use off the main thread after authentication.
 * This class does not authorize enrollment, replacement or removal.
 *
 * The TOTP service must hold LOCK across each load/verify/save transaction.
 * There is no cached plaintext state or exported encryption-key byte array.
 */
public final class TotpSecretStore
        implements TotpEnrollmentService.EnrollmentStore {

    static final Object LOCK = new Object();

    private static final String PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "safekey_totp_state_key_v1";
    private static final String FILE_NAME = "safekey_totp_state.enc";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String CONTEXT = "safekey:totp-state:v1";

    private static final int FILE_VERSION = 1;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private static final int FILE_LENGTH =
            Integer.BYTES + NONCE_LENGTH
                    + TotpState.ENCODED_LENGTH + TAG_BITS / 8;

    private final String keyAlias;
    private final File baseFile;
    private final AtomicFile atomicFile;

    public TotpSecretStore(Context context) {
        this(context, KEY_ALIAS, FILE_NAME);
    }

    // Dedicated names let instrumented tests avoid production TOTP state.
    TotpSecretStore(Context context, String keyAlias, String fileName) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(keyAlias, "keyAlias");
        Objects.requireNonNull(fileName, "fileName");

        if (!keyAlias.startsWith("safekey_totp_")
                || !fileName.matches("[A-Za-z0-9_-]+\\.enc")) {
            throw new IllegalArgumentException("Invalid TOTP storage names.");
        }

        this.keyAlias = keyAlias;

        File directory = Objects.requireNonNull(
                context.getApplicationContext().getNoBackupFilesDir(),
                "noBackupFilesDir"
        );

        this.baseFile = new File(directory, fileName);
        this.atomicFile = new AtomicFile(baseFile);
    }

    @Override
    public Object getTransactionLock() {
        return LOCK;
    }

    public boolean isConfigured()
            throws GeneralSecurityException, IOException {
        synchronized (LOCK) {
            return hasFileArtifacts()
                    || openKeyStore().containsAlias(keyAlias);
        }
    }

    /** Returns null only when neither state files nor a key alias exist. */
    public TotpState load()
            throws GeneralSecurityException, IOException {
        synchronized (LOCK) {
            KeyStore keyStore = openKeyStore();

            if (!keyStore.containsAlias(keyAlias)) {
                if (hasFileArtifacts()) {
                    throw new GeneralSecurityException(
                            "TOTP protection key is missing."
                    );
                }

                return null;
            }

            SecretKey key = requireKey(keyStore);
            byte[] envelope = readEnvelope();
            byte[] plaintext = null;

            try {
                ByteBuffer input = ByteBuffer.wrap(envelope);

                if (input.getInt() != FILE_VERSION) {
                    throw new IOException(
                            "Unsupported TOTP storage version."
                    );
                }

                byte[] nonce = new byte[NONCE_LENGTH];
                input.get(nonce);

                byte[] ciphertext = new byte[input.remaining()];
                input.get(ciphertext);

                Cipher cipher = Cipher.getInstance(TRANSFORMATION);

                cipher.init(
                        Cipher.DECRYPT_MODE,
                        key,
                        new GCMParameterSpec(TAG_BITS, nonce)
                );

                cipher.updateAAD(
                        CONTEXT.getBytes(StandardCharsets.UTF_8)
                );

                plaintext = cipher.doFinal(ciphertext);

                try {
                    return TotpState.decode(plaintext);
                } catch (IllegalArgumentException invalidState) {
                    throw new IOException(
                            "Stored TOTP state is invalid.",
                            invalidState
                    );
                }
            } finally {
                if (plaintext != null) {
                    Arrays.fill(plaintext, (byte) 0);
                }
            }
        }
    }

    public void save(TotpState state)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(state, "state");

        synchronized (LOCK) {
            byte[] plaintext = state.encode();

            try {
                KeyStore keyStore = openKeyStore();
                SecretKey key;

                if (keyStore.containsAlias(keyAlias)) {
                    key = requireKey(keyStore);
                } else {
                    if (hasFileArtifacts()) {
                        throw new GeneralSecurityException(
                                "TOTP protection key is missing."
                        );
                    }

                    key = generateKey();
                }

                Cipher cipher = Cipher.getInstance(TRANSFORMATION);

                // Android Keystore generates a fresh encryption nonce.
                cipher.init(Cipher.ENCRYPT_MODE, key);

                cipher.updateAAD(
                        CONTEXT.getBytes(StandardCharsets.UTF_8)
                );

                byte[] ciphertext = cipher.doFinal(plaintext);
                byte[] nonce = cipher.getIV();

                if (nonce == null
                        || nonce.length != NONCE_LENGTH
                        || ciphertext.length
                        != TotpState.ENCODED_LENGTH + TAG_BITS / 8) {
                    throw new GeneralSecurityException(
                            "Unexpected TOTP encryption format."
                    );
                }

                byte[] envelope = ByteBuffer.allocate(FILE_LENGTH)
                        .putInt(FILE_VERSION)
                        .put(nonce)
                        .put(ciphertext)
                        .array();

                writeEnvelope(envelope);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    /** Call only after authorized disable, or during the full Panic wipe. */
    public void clear()
            throws GeneralSecurityException, IOException {
        synchronized (LOCK) {
            for (File artifact : artifacts()) {
                if (artifact.exists() && !artifact.delete()) {
                    throw new IOException(
                            "Unable to remove TOTP state."
                    );
                }
            }

            KeyStore keyStore = openKeyStore();

            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias);
            }

            if (keyStore.containsAlias(keyAlias)) {
                throw new GeneralSecurityException(
                        "Unable to remove TOTP protection key."
                );
            }
        }
    }

    private SecretKey generateKey()
            throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                PROVIDER
        );

        generator.init(
                new KeyGenParameterSpec.Builder(
                        keyAlias,
                        KeyProperties.PURPOSE_ENCRYPT
                                | KeyProperties.PURPOSE_DECRYPT
                )
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(
                                KeyProperties.ENCRYPTION_PADDING_NONE
                        )
                        .setRandomizedEncryptionRequired(true)
                        .setUserAuthenticationRequired(false)
                        .build()
        );

        return generator.generateKey();
    }

    private SecretKey requireKey(KeyStore keyStore)
            throws GeneralSecurityException {
        Key key = keyStore.getKey(keyAlias, null);

        if (!(key instanceof SecretKey)) {
            throw new GeneralSecurityException(
                    "TOTP protection key is unavailable."
            );
        }

        return (SecretKey) key;
    }

    private static KeyStore openKeyStore()
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(PROVIDER);
        keyStore.load(null);
        return keyStore;
    }

    private boolean hasFileArtifacts() {
        for (File artifact : artifacts()) {
            if (artifact.exists()) {
                return true;
            }
        }

        return false;
    }

    private File[] artifacts() {
        return new File[]{
                baseFile,
                new File(baseFile.getPath() + ".bak"),
                new File(baseFile.getPath() + ".new")
        };
    }

    private byte[] readEnvelope() throws IOException {
        byte[] envelope = new byte[FILE_LENGTH];

        try (FileInputStream input = atomicFile.openRead()) {
            int offset = 0;

            while (offset < envelope.length) {
                int count = input.read(
                        envelope,
                        offset,
                        envelope.length - offset
                );

                if (count < 0) {
                    throw new IOException(
                            "Stored TOTP data is truncated."
                    );
                }

                offset += count;
            }

            if (input.read() != -1) {
                throw new IOException(
                        "Stored TOTP data is oversized."
                );
            }
        }

        return envelope;
    }

    private void writeEnvelope(byte[] envelope) throws IOException {
        FileOutputStream output = null;

        try {
            output = atomicFile.startWrite();
            output.write(envelope);
            output.getFD().sync();

            atomicFile.finishWrite(output);
            output = null;

            if (!Arrays.equals(envelope, readEnvelope())) {
                throw new IOException(
                        "Unable to confirm saved TOTP state."
                );
            }
        } finally {
            if (output != null) {
                atomicFile.failWrite(output);
            }
        }
    }
}

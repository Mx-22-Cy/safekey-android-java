package com.safekey.app.security.panic;

import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Argon2id plus an authenticated, purpose-bound proof; never stores passwords. */
public final class PanicPasswordCrypto implements PanicPasswordService.Crypto {
    private static final byte[] PROOF =
            "SafeKey Panic verifier version 1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AAD =
            "safekey:panic-password:v1".getBytes(StandardCharsets.US_ASCII);
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private final SecureRandom random = new SecureRandom();
    private final Argon2idMasterKeyDeriver deriver = new Argon2idMasterKeyDeriver();

    @Override
    public Record create(char[] password) throws Exception {
        requireBounded(password);
        byte[] salt = deriver.generateSalt();
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        byte[] key = null;
        char[] copy = password.clone();
        try {
            key = deriver.deriveKey(copy, salt);
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, key, nonce);
            return new Record(salt, nonce, cipher.doFinal(PROOF));
        } finally {
            Arrays.fill(copy, '\0');
            if (key != null) { Arrays.fill(key, (byte) 0); }
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
        }
    }

    @Override
    public boolean matches(char[] password, Record record) throws Exception {
        Objects.requireNonNull(record, "record");
        requireBounded(password);
        byte[] key = null;
        byte[] plaintext = null;
        char[] copy = password.clone();
        try {
            key = deriver.deriveKey(copy, record.salt);
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, key, record.nonce);
            try {
                plaintext = cipher.doFinal(record.ciphertext);
            } catch (AEADBadTagException wrongPasswordOrTamperedProof) {
                return false;
            }
            return MessageDigest.isEqual(PROOF, plaintext);
        } finally {
            Arrays.fill(copy, '\0');
            if (key != null) { Arrays.fill(key, (byte) 0); }
            if (plaintext != null) { Arrays.fill(plaintext, (byte) 0); }
        }
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(AAD);
        return cipher;
    }

    private static void requireBounded(char[] password) {
        if (password == null || password.length == 0
                || password.length > MasterPasswordPolicy.MAX_LENGTH * 2) {
            throw new IllegalArgumentException("Invalid Panic password length.");
        }
    }

    public static final class Record {
        private static final int VERSION = 1;
        public static final int ENCODED_LENGTH = Integer.BYTES
                + Argon2idMasterKeyDeriver.SALT_LENGTH_BYTES
                + NONCE_BYTES + PROOF.length + TAG_BITS / 8;
        private final byte[] salt;
        private final byte[] nonce;
        private final byte[] ciphertext;

        private Record(byte[] salt, byte[] nonce, byte[] ciphertext) {
            this.salt = salt.clone();
            this.nonce = nonce.clone();
            this.ciphertext = ciphertext.clone();
        }

        public byte[] encode() {
            return ByteBuffer.allocate(ENCODED_LENGTH).putInt(VERSION)
                    .put(salt).put(nonce).put(ciphertext).array();
        }

        public static Record decode(byte[] encoded) {
            if (encoded == null || encoded.length != ENCODED_LENGTH) {
                throw new IllegalArgumentException("Invalid Panic proof size.");
            }
            ByteBuffer input = ByteBuffer.wrap(encoded);
            if (input.getInt() != VERSION) {
                throw new IllegalArgumentException("Unsupported Panic proof version.");
            }
            byte[] salt = new byte[Argon2idMasterKeyDeriver.SALT_LENGTH_BYTES];
            byte[] nonce = new byte[NONCE_BYTES];
            byte[] ciphertext = new byte[PROOF.length + TAG_BITS / 8];
            input.get(salt).get(nonce).get(ciphertext);
            return new Record(salt, nonce, ciphertext);
        }
    }
}

package com.safekey.app.security.crypto;

import org.junit.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static com.safekey.app.security.crypto.VaultItemCipher.Field.CREDENTIAL_NOTES;
import static com.safekey.app.security.crypto.VaultItemCipher.Field.CREDENTIAL_PASSWORD;
import static com.safekey.app.security.crypto.VaultItemCipher.Field.SECURE_NOTE_CONTENT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class VaultItemCipherTest {

    private static final String FIRST_RECORD =
            "11111111-1111-4111-8111-111111111111";
    private static final String SECOND_RECORD =
            "22222222-2222-4222-8222-222222222222";
    private static final String UNICODE_VALUE =
            "Fictional \u0645\u0644\u0627\u062d\u0638\u0629 \uD83D\uDD10";

    @Test
    public void hkdf_matchesRfc5869Sha256CaseOne() {
        byte[] input = new byte[22];
        Arrays.fill(input, (byte) 0x0b);
        byte[] derived = VaultItemCipher.hkdfSha256(input,
                hex("000102030405060708090a0b0c"),
                hex("f0f1f2f3f4f5f6f7f8f9"), 42);
        try {
            assertArrayEquals(hex(
                    "3cb25f25faacd57a90434f64d0362f2a"
                            + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                            + "34007208d5b887185865"), derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    @Test
    public void hkdf_matchesRfc5869Sha256CaseThree() {
        byte[] input = new byte[22];
        Arrays.fill(input, (byte) 0x0b);
        byte[] derived = VaultItemCipher.hkdfSha256(
                input, new byte[0], new byte[0], 42);
        try {
            assertArrayEquals(hex(
                    "8da4e775a563c18f715f802a063c5a31"
                            + "b8a11f5c5ee1879ec3454e5f3c738d2d9"
                            + "d201395faa4b61a96c8"), derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    @Test
    public void decrypt_readsIndependentVersionOneFixture() throws Exception {
        // Python hmac/hashlib HKDF + cryptography AESGCM, not this Java code.
        String envelope = "SK1.AAECAwQFBgcICQoL."
                + "T9t59eIM2fe_NhIi8D03w0271-aP2rRYIxj3zDT8NayZeF-5RC0e";
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(0))) {
            assertEquals("Fictional password \uD83D\uDD10",
                    cipher.decrypt(CREDENTIAL_PASSWORD, FIRST_RECORD, envelope));
        }
    }

    @Test
    public void everySupportedField_roundTripsUnicode() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(1))) {
            for (VaultItemCipher.Field field : VaultItemCipher.Field.values()) {
                String encrypted = cipher.encrypt(
                        field, FIRST_RECORD, UNICODE_VALUE);
                assertTrue(encrypted.startsWith("SK1."));
                assertNotEquals(UNICODE_VALUE, encrypted);
                assertEquals(UNICODE_VALUE,
                        cipher.decrypt(field, FIRST_RECORD, encrypted));
            }
        }
    }

    @Test
    public void emptyOptionalFields_areEncryptedAndRoundTrip() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(2))) {
            for (VaultItemCipher.Field field : new VaultItemCipher.Field[]{
                    CREDENTIAL_NOTES, SECURE_NOTE_CONTENT}) {
                String encrypted = cipher.encrypt(field, FIRST_RECORD, "");
                assertFalse(encrypted.isEmpty());
                assertEquals("", cipher.decrypt(field, FIRST_RECORD, encrypted));
            }
        }
    }

    @Test
    public void reopenedCipher_readsValuesUsingSameDatabaseKey() throws Exception {
        String encrypted;
        try (VaultItemCipher first = new VaultItemCipher(databaseKey(3))) {
            encrypted = first.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, "Fictional password");
        }
        try (VaultItemCipher reopened = new VaultItemCipher(databaseKey(3))) {
            assertEquals("Fictional password", reopened.decrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, encrypted));
        }
    }

    @Test
    public void constructor_preservesCallerKeyAndOwnsIndependentDerivedKey()
            throws Exception {
        byte[] supplied = databaseKey(4);
        byte[] original = supplied.clone();
        try (VaultItemCipher cipher = new VaultItemCipher(supplied)) {
            assertArrayEquals(original, supplied);
            Arrays.fill(supplied, (byte) 0);
            String encrypted = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            try (VaultItemCipher reopened = new VaultItemCipher(original)) {
                assertEquals(UNICODE_VALUE, reopened.decrypt(
                        CREDENTIAL_PASSWORD, FIRST_RECORD, encrypted));
            }
        } finally {
            Arrays.fill(original, (byte) 0);
        }
    }

    @Test
    public void anotherVaultKey_cannotDecrypt() throws Exception {
        try (VaultItemCipher real = new VaultItemCipher(databaseKey(5));
             VaultItemCipher decoy = new VaultItemCipher(databaseKey(6))) {
            String encrypted = real.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, "Real test value");
            assertThrows(AesGcmException.class, () -> decoy.decrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, encrypted));
        }
    }

    @Test
    public void ciphertext_cannotMoveToAnotherRecord() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(7))) {
            String encrypted = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            assertThrows(AesGcmException.class, () -> cipher.decrypt(
                    CREDENTIAL_PASSWORD, SECOND_RECORD, encrypted));
        }
    }

    @Test
    public void ciphertext_cannotMoveBetweenCredentialFields() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(8))) {
            String encrypted = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            assertThrows(AesGcmException.class, () -> cipher.decrypt(
                    CREDENTIAL_NOTES, FIRST_RECORD, encrypted));
        }
    }

    @Test
    public void ciphertext_cannotMoveBetweenRecordTypes() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(9))) {
            String encrypted = cipher.encrypt(
                    CREDENTIAL_NOTES, FIRST_RECORD, UNICODE_VALUE);
            assertThrows(AesGcmException.class, () -> cipher.decrypt(
                    SECURE_NOTE_CONTENT, FIRST_RECORD, encrypted));
        }
    }

    @Test
    public void encryptingSameValueAgain_usesFreshNonce() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(10))) {
            String first = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            String second = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            assertNotEquals(first, second);
            assertNotEquals(first.split("\\.")[1], second.split("\\.")[1]);
        }
    }

    @Test
    public void modifiedNonce_isRejected() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(11))) {
            String encrypted = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            assertThrows(AesGcmException.class, () -> cipher.decrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, modifyPart(encrypted, 1)));
        }
    }

    @Test
    public void modifiedCiphertextOrTag_isRejected() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(12))) {
            String encrypted = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            assertThrows(AesGcmException.class, () -> cipher.decrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, modifyPart(encrypted, 2)));
        }
    }

    @Test
    public void malformedAndLegacyValues_areRejectedWithoutPlaintextFallback()
            throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(13))) {
            for (String value : new String[]{
                    "", "legacy plaintext", "SK1.only-two-parts",
                    "SK2.AA.AA", "SK1.!.!", "SK1.AA.AA"}) {
                assertThrows(AesGcmException.class, () -> cipher.decrypt(
                        CREDENTIAL_PASSWORD, FIRST_RECORD, value));
            }
        }
    }

    @Test
    public void invalidRecordIdentities_areRejected() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(14))) {
            for (String value : new String[]{
                    "", "7", "not-a-uuid", "1-1-1-1-1",
                    "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}) {
                assertThrows(IllegalArgumentException.class,
                        () -> cipher.encrypt(CREDENTIAL_PASSWORD, value, "test"));
            }
        }
    }

    @Test
    public void missingOrWrongLengthDatabaseKey_isRejected() {
        assertThrows(NullPointerException.class, () -> new VaultItemCipher(null));
        for (int length : new int[]{0, 16, 31, 33}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new VaultItemCipher(new byte[length]));
        }
    }

    @Test
    public void nullFieldIdentityAndValues_areRejected() throws Exception {
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey(15))) {
            assertThrows(NullPointerException.class,
                    () -> cipher.encrypt(null, FIRST_RECORD, "test"));
            assertThrows(NullPointerException.class,
                    () -> cipher.encrypt(CREDENTIAL_PASSWORD, null, "test"));
            assertThrows(NullPointerException.class,
                    () -> cipher.encrypt(CREDENTIAL_PASSWORD, FIRST_RECORD, null));
            assertThrows(NullPointerException.class,
                    () -> cipher.decrypt(null, FIRST_RECORD, "test"));
            assertThrows(NullPointerException.class,
                    () -> cipher.decrypt(CREDENTIAL_PASSWORD, null, "test"));
            assertThrows(NullPointerException.class,
                    () -> cipher.decrypt(CREDENTIAL_PASSWORD, FIRST_RECORD, null));
        }
    }

    @Test
    public void fieldEncryption_doesNotReuseRawDatabaseKey() throws Exception {
        byte[] databaseKey = databaseKey(16);
        try (VaultItemCipher cipher = new VaultItemCipher(databaseKey)) {
            String encrypted = cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            byte[] aad = ("safekey:vault-item:v1:credentials:" + FIRST_RECORD
                    + ":password_ciphertext").getBytes(StandardCharsets.UTF_8);
            assertThrows(AesGcmException.class, () -> new AesGcmCipher().decrypt(
                    encrypted, databaseKey, aad));
        } finally {
            Arrays.fill(databaseKey, (byte) 0);
        }
    }

    @Test
    public void close_erasesOwnedKeyAndRejectsFurtherOperations() throws Exception {
        VaultItemCipher cipher = new VaultItemCipher(databaseKey(17));
        String encrypted = cipher.encrypt(
                CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
        byte[] ownedKey = ownedKey(cipher);
        assertFalse(allZero(ownedKey));
        try {
            cipher.close();
            assertTrue(cipher.isClosed());
            assertTrue(allZero(ownedKey));
            assertThrows(IllegalStateException.class, () -> cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE));
            assertThrows(IllegalStateException.class, () -> cipher.decrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, encrypted));
        } finally {
            cipher.close();
        }
    }

    @Test
    public void close_isIdempotentAndLeavesOtherInstancesUsable() throws Exception {
        VaultItemCipher first = new VaultItemCipher(databaseKey(18));
        try (VaultItemCipher second = new VaultItemCipher(databaseKey(18))) {
            first.close();
            first.close();
            String encrypted = second.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE);
            assertEquals(UNICODE_VALUE,
                    second.decrypt(CREDENTIAL_PASSWORD, FIRST_RECORD, encrypted));
        } finally {
            first.close();
        }
    }

    @Test
    public void close_waitsForInFlightEncryptionThenRejectsFurtherWork()
            throws Exception {
        CountDownLatch nonceRequested = new CountDownLatch(1);
        CountDownLatch releaseNonce = new CountDownLatch(1);
        CountDownLatch closeStarted = new CountDownLatch(1);
        SecureRandom blockingRandom = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                nonceRequested.countDown();
                try {
                    if (!releaseNonce.await(5, TimeUnit.SECONDS)) {
                        throw new AssertionError("Nonce generation was not released.");
                    }
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(error);
                }
                Arrays.fill(bytes, (byte) 7);
            }
        };
        VaultItemCipher cipher = new VaultItemCipher(
                databaseKey(19), new AesGcmCipher(blockingRandom));
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<String> encryption = workers.submit(() -> cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, UNICODE_VALUE));
            assertTrue(nonceRequested.await(5, TimeUnit.SECONDS));
            Future<?> close = workers.submit(() -> {
                closeStarted.countDown();
                cipher.close();
            });
            assertTrue(closeStarted.await(5, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class,
                    () -> close.get(100, TimeUnit.MILLISECONDS));
            releaseNonce.countDown();
            assertTrue(encryption.get(5, TimeUnit.SECONDS).startsWith("SK1."));
            close.get(5, TimeUnit.SECONDS);
            assertTrue(cipher.isClosed());
            assertTrue(allZero(ownedKey(cipher)));
            assertThrows(IllegalStateException.class, () -> cipher.encrypt(
                    CREDENTIAL_PASSWORD, FIRST_RECORD, "later"));
        } finally {
            releaseNonce.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
            cipher.close();
        }
    }

    private static byte[] databaseKey(int start) {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) {
            key[index] = (byte) (start + index);
        }
        return key;
    }

    private static byte[] hex(String value) {
        if (value.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex must have an even length.");
        }
        byte[] bytes = new byte[value.length() / 2];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) Integer.parseInt(
                    value.substring(index * 2, index * 2 + 2), 16);
        }
        return bytes;
    }

    private static String modifyPart(String envelope, int part) {
        String[] parts = envelope.split("\\.", -1);
        byte[] decoded = Base64.getUrlDecoder().decode(parts[part]);
        decoded[0] ^= 1;
        parts[part] = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(decoded);
        return String.join(".", parts);
    }

    private static byte[] ownedKey(VaultItemCipher cipher) throws Exception {
        Field field = VaultItemCipher.class.getDeclaredField("itemKey");
        field.setAccessible(true);
        return (byte[]) field.get(cipher);
    }

    private static boolean allZero(byte[] value) {
        for (byte element : value) {
            if (element != 0) {
                return false;
            }
        }
        return true;
    }
}

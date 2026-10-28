package com.safekey.app.security.panic;

import org.junit.Test;

import java.util.Arrays;

import static com.safekey.app.security.panic.PanicTestSupport.*;
import static org.junit.Assert.*;

/** Gradle runs these with the project's real Argon2id implementation. */
public class PanicPasswordCryptoTest {
    private final PanicPasswordCrypto crypto = new PanicPasswordCrypto();

    @Test public void correctPasswordMatchesButMasterDecoyAndWrongPasswordDoNot() throws Exception {
        PanicPasswordCrypto.Record record = crypto.create(chars(PANIC));
        assertTrue(crypto.matches(chars(PANIC), record));
        assertFalse(crypto.matches(chars(MASTER), record));
        assertFalse(crypto.matches(chars(DECOY), record));
        assertFalse(crypto.matches(chars("Incorrect Panic candidate"), record));
    }

    @Test public void repeatEnrollmentUsesFreshSaltAndNonce() throws Exception {
        byte[] first = crypto.create(chars(PANIC)).encode();
        byte[] second = crypto.create(chars(PANIC)).encode();
        assertFalse(Arrays.equals(first, second));
        assertTrue(crypto.matches(chars(PANIC), PanicPasswordCrypto.Record.decode(first)));
        assertTrue(crypto.matches(chars(PANIC), PanicPasswordCrypto.Record.decode(second)));
    }

    @Test public void tamperedProofCannotTriggerPanic() throws Exception {
        byte[] encoded = crypto.create(chars(PANIC)).encode();
        encoded[encoded.length - 1] ^= 1;
        assertFalse(crypto.matches(chars(PANIC), PanicPasswordCrypto.Record.decode(encoded)));
    }

    @Test public void recordRejectsTruncatedOversizedAndUnknownVersionData() throws Exception {
        byte[] encoded = crypto.create(chars(PANIC)).encode();
        expect(IllegalArgumentException.class, () -> PanicPasswordCrypto.Record.decode(
                Arrays.copyOf(encoded, encoded.length - 1)));
        expect(IllegalArgumentException.class, () -> PanicPasswordCrypto.Record.decode(
                Arrays.copyOf(encoded, encoded.length + 1)));
        encoded[3] = 2;
        expect(IllegalArgumentException.class, () -> PanicPasswordCrypto.Record.decode(encoded));
    }

    @Test public void callerAndEncodedArraysCannotMutateAnExistingRecord() throws Exception {
        char[] password = chars(PANIC);
        PanicPasswordCrypto.Record original = crypto.create(password);
        assertArrayEquals(chars(PANIC), password);
        byte[] encoded = original.encode();
        PanicPasswordCrypto.Record decoded = PanicPasswordCrypto.Record.decode(encoded);
        Arrays.fill(encoded, (byte) 0);
        assertTrue(crypto.matches(chars(PANIC), original));
        assertTrue(crypto.matches(chars(PANIC), decoded));
    }
}

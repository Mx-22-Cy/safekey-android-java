package com.safekey.app.security.panic;

import org.junit.Test;

import static com.safekey.app.security.panic.PanicTestSupport.*;
import static org.junit.Assert.*;

public class PanicPasswordPolicyTest {
    @Test public void threeDifferentAuthenticatedPasswordsAreAccepted() {
        assertEquals(PanicPasswordPolicy.Result.VALID, validate(MASTER, DECOY, PANIC, PANIC));
    }

    @Test public void everyPairMustDiffer() {
        assertEquals(PanicPasswordPolicy.Result.PASSWORDS_MUST_DIFFER,
                validate(MASTER, MASTER, PANIC, PANIC));
        assertEquals(PanicPasswordPolicy.Result.PASSWORDS_MUST_DIFFER,
                validate(MASTER, DECOY, MASTER, MASTER));
        assertEquals(PanicPasswordPolicy.Result.PASSWORDS_MUST_DIFFER,
                validate(MASTER, DECOY, DECOY, DECOY));
    }

    @Test public void allThreeEqualAreRejected() {
        assertEquals(PanicPasswordPolicy.Result.PASSWORDS_MUST_DIFFER,
                validate(PANIC, PANIC, PANIC, PANIC));
    }

    @Test public void missingRolePasswordsCannotAuthorizeEnrollment() {
        assertEquals(PanicPasswordPolicy.Result.MASTER_REQUIRED,
                PanicPasswordPolicy.validate(null, chars(DECOY), chars(PANIC), chars(PANIC)));
        assertEquals(PanicPasswordPolicy.Result.DECOY_REQUIRED,
                validate(MASTER, "", PANIC, PANIC));
    }

    @Test public void shortCommonAndExcessivePanicPasswordsAreRejected() {
        for (String bad : new String[]{"short", "password1234567",
                new String(new char[129]).replace('\0', 'x')}) {
            assertEquals(PanicPasswordPolicy.Result.INVALID_PANIC_PASSWORD,
                    validate(MASTER, DECOY, bad, bad));
        }
    }

    @Test public void confirmationMustMatchExactly() {
        assertEquals(PanicPasswordPolicy.Result.CONFIRMATION_MISMATCH,
                validate(MASTER, DECOY, PANIC, PANIC + "x"));
        assertEquals(PanicPasswordPolicy.Result.CONFIRMATION_MISMATCH,
                PanicPasswordPolicy.validate(chars(MASTER), chars(DECOY), chars(PANIC), null));
    }

    private static PanicPasswordPolicy.Result validate(String master, String decoy,
                                                       String panic, String confirmation) {
        return PanicPasswordPolicy.validate(chars(master), chars(decoy),
                chars(panic), chars(confirmation));
    }
}

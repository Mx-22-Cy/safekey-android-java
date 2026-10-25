package com.safekey.app.security.panic;

import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordValidationResult;

import java.util.Arrays;

/** Enrollment policy; the supplied master/Decoy values must also be authenticated. */
public final class PanicPasswordPolicy {
    public enum Result {
        VALID, MASTER_REQUIRED, DECOY_REQUIRED, INVALID_PANIC_PASSWORD,
        CONFIRMATION_MISMATCH, PASSWORDS_MUST_DIFFER
    }

    private PanicPasswordPolicy() { }

    public static Result validate(char[] master, char[] decoy,
                                  char[] panic, char[] confirmation) {
        if (master == null || master.length == 0) {
            return Result.MASTER_REQUIRED;
        }
        if (decoy == null || decoy.length == 0) {
            return Result.DECOY_REQUIRED;
        }
        if (MasterPasswordPolicy.validate(panic)
                != MasterPasswordValidationResult.VALID) {
            return Result.INVALID_PANIC_PASSWORD;
        }
        if (confirmation == null || !Arrays.equals(panic, confirmation)) {
            return Result.CONFIRMATION_MISMATCH;
        }
        if (Arrays.equals(master, decoy) || Arrays.equals(master, panic)
                || Arrays.equals(decoy, panic)) {
            return Result.PASSWORDS_MUST_DIFFER;
        }
        return Result.VALID;
    }
}

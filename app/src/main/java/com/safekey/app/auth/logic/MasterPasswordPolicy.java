package com.safekey.app.auth.logic;

import java.util.Arrays;

public final class MasterPasswordPolicy {

    public static final int MIN_LENGTH = 15;
    public static final int MAX_LENGTH = 128;

    private MasterPasswordPolicy() {
        // Utility class.
    }

    public static MasterPasswordValidationResult validate(char[] password) {
        if (password == null || password.length == 0) {
            return MasterPasswordValidationResult.REQUIRED;
        }

        int characterCount =
                Character.codePointCount(
                        password,
                        0,
                        password.length
                );

        if (characterCount < MIN_LENGTH) {
            return MasterPasswordValidationResult.TOO_SHORT;
        }

        if (characterCount > MAX_LENGTH) {
            return MasterPasswordValidationResult.TOO_LONG;
        }

        return MasterPasswordValidationResult.VALID;
    }

    public static MasterPasswordValidationResult validateForEnrollment(
            char[] password,
            char[] confirmation
    ) {
        MasterPasswordValidationResult passwordResult =
                validate(password);

        if (passwordResult != MasterPasswordValidationResult.VALID) {
            return passwordResult;
        }

        if (confirmation == null || confirmation.length == 0) {
            return MasterPasswordValidationResult.CONFIRMATION_REQUIRED;
        }

        if (!Arrays.equals(password, confirmation)) {
            return MasterPasswordValidationResult.PASSWORDS_DO_NOT_MATCH;
        }

        return MasterPasswordValidationResult.VALID;
    }
}

package com.safekey.app.auth.logic;

import java.util.Arrays;

public final class MasterPasswordPolicy {

    public static final int MIN_LENGTH = 15;
    public static final int MAX_LENGTH = 128;

    private static final String[] BLOCKED_PASSWORDS = {
            "passwordpassword",
            "password1234567",
            "123456789012345",
            "qwertyuiopasdfgh",
            "safekeypassword",
            "letmeinletmeinletmein",
            "adminadminadmin",
            "iloveyouiloveyou",
            "welcome123456789"
    };

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

        if (isEasilyGuessed(password)) {
            return MasterPasswordValidationResult.EASILY_GUESSED;
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

    private static boolean isEasilyGuessed(char[] password) {
        if (isRepeatedShortPattern(password)) {
            return true;
        }

        for (String blockedPassword : BLOCKED_PASSWORDS) {
            if (matchesIgnoringCase(password, blockedPassword)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isRepeatedShortPattern(char[] password) {
        final int maximumPatternLength = 4;

        for (
                int patternLength = 1;
                patternLength <= maximumPatternLength;
                patternLength++
        ) {
            if (password.length % patternLength != 0) {
                continue;
            }

            boolean repeated = true;

            for (int index = patternLength; index < password.length; index++) {
                if (password[index] != password[index % patternLength]) {
                    repeated = false;
                    break;
                }
            }

            if (repeated) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchesIgnoringCase(
            char[] password,
            String blockedPassword
    ) {
        if (password.length != blockedPassword.length()) {
            return false;
        }

        for (int index = 0; index < password.length; index++) {
            char passwordCharacter =
                    Character.toLowerCase(password[index]);

            char blockedCharacter =
                    Character.toLowerCase(blockedPassword.charAt(index));

            if (passwordCharacter != blockedCharacter) {
                return false;
            }
        }

        return true;
    }
}

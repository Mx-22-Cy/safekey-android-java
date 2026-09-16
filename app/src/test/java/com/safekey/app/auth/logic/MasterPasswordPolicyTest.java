package com.safekey.app.auth.logic;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MasterPasswordPolicyTest {

    @Test
    public void validate_nullPassword_returnsRequired() {
        assertEquals(
                MasterPasswordValidationResult.REQUIRED,
                MasterPasswordPolicy.validate(null)
        );
    }

    @Test
    public void validate_emptyPassword_returnsRequired() {
        assertEquals(
                MasterPasswordValidationResult.REQUIRED,
                MasterPasswordPolicy.validate(new char[0])
        );
    }

    @Test
    public void validate_fourteenCharacters_returnsTooShort() {
        assertEquals(
                MasterPasswordValidationResult.TOO_SHORT,
                MasterPasswordPolicy.validate(
                        "12345678901234".toCharArray()
                )
        );
    }

    @Test
    public void validate_fifteenCharacters_returnsValid() {
        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(
                        "123456789012345".toCharArray()
                )
        );
    }

    @Test
    public void validate_passphraseWithSpaces_returnsValid() {
        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(
                        "correct horse battery staple".toCharArray()
                )
        );
    }

    @Test
    public void validate_maximumLength_returnsValid() {
        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(
                        "a".repeat(
                                MasterPasswordPolicy.MAX_LENGTH
                        ).toCharArray()
                )
        );
    }

    @Test
    public void validate_aboveMaximumLength_returnsTooLong() {
        assertEquals(
                MasterPasswordValidationResult.TOO_LONG,
                MasterPasswordPolicy.validate(
                        "a".repeat(
                                MasterPasswordPolicy.MAX_LENGTH + 1
                        ).toCharArray()
                )
        );
    }

    @Test
    public void validate_unicodeCharacters_countsCodePoints() {
        char[] password =
                "\uD83D\uDE00".repeat(65).toCharArray();

        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(password)
        );
    }
}

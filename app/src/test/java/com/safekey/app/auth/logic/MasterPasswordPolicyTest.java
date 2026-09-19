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
    public void validate_fifteenUniqueCharacters_returnsValid() {
        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(
                        "clouds drift by".toCharArray()
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
    public void validate_lowercasePassphrase_returnsValid() {
        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(
                        "clouds drift quietly over mountains".toCharArray()
                )
        );
    }

    @Test
    public void validate_maximumLength_returnsValid() {
        char[] password = (
                "abcdefghijklmnopqrstuvwxyz".repeat(4)
                        + "abcdefghijklmnopqrstuvwx"
        ).toCharArray();

        assertEquals(
                MasterPasswordPolicy.MAX_LENGTH,
                password.length
        );

        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(password)
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
        char[] password = (
                "\uD83D\uDE00".repeat(64) + "Z"
        ).toCharArray();

        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validate(password)
        );
    }

    @Test
    public void validate_repeatedCharacter_returnsEasilyGuessed() {
        assertEquals(
                MasterPasswordValidationResult.EASILY_GUESSED,
                MasterPasswordPolicy.validate(
                        "aaaaaaaaaaaaaaa".toCharArray()
                )
        );
    }

    @Test
    public void validate_repeatedShortPattern_returnsEasilyGuessed() {
        assertEquals(
                MasterPasswordValidationResult.EASILY_GUESSED,
                MasterPasswordPolicy.validate(
                        "abcabcabcabcabc".toCharArray()
                )
        );
    }

    @Test
    public void validate_commonPassword_returnsEasilyGuessed() {
        assertEquals(
                MasterPasswordValidationResult.EASILY_GUESSED,
                MasterPasswordPolicy.validate(
                        "passwordpassword".toCharArray()
                )
        );
    }

    @Test
    public void validate_commonPasswordIgnoringCase_returnsEasilyGuessed() {
        assertEquals(
                MasterPasswordValidationResult.EASILY_GUESSED,
                MasterPasswordPolicy.validate(
                        "PasswordPassword".toCharArray()
                )
        );
    }

    @Test
    public void validate_numericSequence_returnsEasilyGuessed() {
        assertEquals(
                MasterPasswordValidationResult.EASILY_GUESSED,
                MasterPasswordPolicy.validate(
                        "123456789012345".toCharArray()
                )
        );
    }
}

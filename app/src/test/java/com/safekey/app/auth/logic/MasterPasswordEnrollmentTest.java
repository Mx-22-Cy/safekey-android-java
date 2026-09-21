package com.safekey.app.auth.logic;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MasterPasswordEnrollmentTest {

    private static final String VALID_PASSWORD =
            "correct horse battery staple";

    @Test
    public void validateForEnrollment_nullPassword_returnsRequired() {
        assertEquals(
                MasterPasswordValidationResult.REQUIRED,
                MasterPasswordPolicy.validateForEnrollment(
                        null,
                        null
                )
        );
    }

    @Test
    public void validateForEnrollment_shortPassword_returnsTooShort() {
        assertEquals(
                MasterPasswordValidationResult.TOO_SHORT,
                MasterPasswordPolicy.validateForEnrollment(
                        "short".toCharArray(),
                        "short".toCharArray()
                )
        );
    }

    @Test
    public void validateForEnrollment_easilyGuessedPassword_returnsEasilyGuessed() {
        char[] password =
                "passwordpassword".toCharArray();

        assertEquals(
                MasterPasswordValidationResult.EASILY_GUESSED,
                MasterPasswordPolicy.validateForEnrollment(
                        password,
                        password
                )
        );
    }

    @Test
    public void validateForEnrollment_nullConfirmation_returnsConfirmationRequired() {
        assertEquals(
                MasterPasswordValidationResult.CONFIRMATION_REQUIRED,
                MasterPasswordPolicy.validateForEnrollment(
                        VALID_PASSWORD.toCharArray(),
                        null
                )
        );
    }

    @Test
    public void validateForEnrollment_emptyConfirmation_returnsConfirmationRequired() {
        assertEquals(
                MasterPasswordValidationResult.CONFIRMATION_REQUIRED,
                MasterPasswordPolicy.validateForEnrollment(
                        VALID_PASSWORD.toCharArray(),
                        new char[0]
                )
        );
    }

    @Test
    public void validateForEnrollment_differentConfirmation_returnsPasswordsDoNotMatch() {
        assertEquals(
                MasterPasswordValidationResult.PASSWORDS_DO_NOT_MATCH,
                MasterPasswordPolicy.validateForEnrollment(
                        VALID_PASSWORD.toCharArray(),
                        "different password value".toCharArray()
                )
        );
    }

    @Test
    public void validateForEnrollment_matchingPasswords_returnsValid() {
        assertEquals(
                MasterPasswordValidationResult.VALID,
                MasterPasswordPolicy.validateForEnrollment(
                        VALID_PASSWORD.toCharArray(),
                        VALID_PASSWORD.toCharArray()
                )
        );
    }
}

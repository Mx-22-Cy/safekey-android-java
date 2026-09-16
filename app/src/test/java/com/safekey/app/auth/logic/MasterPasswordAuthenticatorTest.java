package com.safekey.app.auth.logic;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MasterPasswordAuthenticatorTest {

    @Test(expected = NullPointerException.class)
    public void constructor_nullVerifier_throwsNullPointerException() {
        new MasterPasswordAuthenticator(null);
    }

    @Test
    public void authenticate_nullPassword_returnsPasswordRequired() {
        MasterPasswordAuthenticator authenticator =
                new MasterPasswordAuthenticator(
                        candidatePassword -> {
                            throw new AssertionError(
                                    "Verifier must not be called"
                            );
                        }
                );

        assertEquals(
                MasterPasswordAuthenticationResult.PASSWORD_REQUIRED,
                authenticator.authenticate(null)
        );
    }

    @Test
    public void authenticate_emptyPassword_returnsPasswordRequired() {
        MasterPasswordAuthenticator authenticator =
                new MasterPasswordAuthenticator(
                        candidatePassword -> {
                            throw new AssertionError(
                                    "Verifier must not be called"
                            );
                        }
                );

        assertEquals(
                MasterPasswordAuthenticationResult.PASSWORD_REQUIRED,
                authenticator.authenticate(new char[0])
        );
    }

    @Test
    public void authenticate_matchingPassword_returnsSuccess() {
        MasterPasswordAuthenticator authenticator =
                new MasterPasswordAuthenticator(
                        candidatePassword -> true
                );

        assertEquals(
                MasterPasswordAuthenticationResult.SUCCESS,
                authenticator.authenticate(
                        "correct horse battery staple".toCharArray()
                )
        );
    }

    @Test
    public void authenticate_nonMatchingPassword_returnsInvalidPassword() {
        MasterPasswordAuthenticator authenticator =
                new MasterPasswordAuthenticator(
                        candidatePassword -> false
                );

        assertEquals(
                MasterPasswordAuthenticationResult.INVALID_PASSWORD,
                authenticator.authenticate(
                        "incorrect password value".toCharArray()
                )
        );
    }

    @Test
    public void authenticate_existingShortPassword_defersToVerifier() {
        MasterPasswordAuthenticator authenticator =
                new MasterPasswordAuthenticator(
                        candidatePassword -> true
                );

        assertEquals(
                MasterPasswordAuthenticationResult.SUCCESS,
                authenticator.authenticate(
                        "short".toCharArray()
                )
        );
    }
}

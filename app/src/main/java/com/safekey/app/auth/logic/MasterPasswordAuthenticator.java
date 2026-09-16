package com.safekey.app.auth.logic;

import java.util.Objects;

public final class MasterPasswordAuthenticator {

    private final MasterPasswordVerifier verifier;

    public MasterPasswordAuthenticator(
            MasterPasswordVerifier verifier
    ) {
        this.verifier =
                Objects.requireNonNull(
                        verifier,
                        "verifier"
                );
    }

    public MasterPasswordAuthenticationResult authenticate(
            char[] password
    ) {
        if (password == null || password.length == 0) {
            return MasterPasswordAuthenticationResult.PASSWORD_REQUIRED;
        }

        if (verifier.verify(password)) {
            return MasterPasswordAuthenticationResult.SUCCESS;
        }

        return MasterPasswordAuthenticationResult.INVALID_PASSWORD;
    }
}

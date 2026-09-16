package com.safekey.app.auth.logic;

@FunctionalInterface
public interface MasterPasswordVerifier {

    /**
     * Verifies a candidate master password.
     *
     * Implementations must not retain or modify the supplied array.
     */
    boolean verify(char[] candidatePassword);
}

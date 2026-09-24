package com.safekey.app.security.crypto;

public interface MasterKeyDeriver {

    /**
     * Derives a cryptographic key from a master password and salt.
     * The caller owns the returned array and must clear it after use.
     */
    byte[] deriveKey(
            char[] masterPassword,
            byte[] salt
    );
}

package com.safekey.app.security.totp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** A one-way configuration binding; never retains an authenticator secret. */
public final class TotpConfigurationFingerprint {
    private TotpConfigurationFingerprint() { }

    public static byte[] ofSecret(byte[] secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(secret == null ? (byte) 0 : (byte) 1);
            if (secret != null) { digest.update(secret); }
            return digest.digest();
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable.", unavailable);
        }
    }
}

package com.safekey.app.security.totp;

import android.content.Context;

/** Dedicated on-device storage names for Panic enrollment regression tests. */
public final class PanicEnrollmentTotpTestSupport {
    private PanicEnrollmentTotpTestSupport() { }
    public static TotpSecretStore create(Context context, String prefix) {
        if (!prefix.matches("safekey_panic_test_[A-Za-z0-9_-]+_")) {
            throw new IllegalArgumentException("Isolated test prefix is required.");
        }
        return new TotpSecretStore(context, "safekey_totp_" + prefix, prefix + "totp.enc");
    }
}

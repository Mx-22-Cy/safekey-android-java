package com.safekey.app.security.storage;

import android.content.Context;
import android.os.SystemClock;

import com.safekey.app.security.totp.TotpVerificationService;
import com.safekey.app.security.totp.VaultUnlockGate;

/** Real password/SQLCipher path with an isolated real TOTP store and fixed clock. */
public final class PanicEnrollmentVaultTestSupport {
    public static final long WALL_CLOCK_MILLIS = 1_800_000_000_000L;
    private PanicEnrollmentVaultTestSupport() { }
    public static SecureVaultCoordinator create(Context context, TotpVerificationService.StateStore store) {
        return new SecureVaultCoordinator(context,
                new VaultUnlockGate(store, () -> WALL_CLOCK_MILLIS, SystemClock::elapsedRealtime), null);
    }
}

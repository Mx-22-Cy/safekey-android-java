package com.safekey.app.security.panic;

import android.content.Context;
import android.os.SystemClock;

import java.util.Objects;

/** Uses the same credential snapshots as the shared Sign In checker. */
public final class AndroidPanicPasswordSeparation {
    private AndroidPanicPasswordSeparation() { }

    public static PanicPasswordSeparation create(Context context, PanicRuntimeScope scope) {
        return new PanicPasswordSeparation(Objects.requireNonNull(scope, "scope").getWorkGate(),
                new AndroidPanicPasswordCredentials(Objects.requireNonNull(context, "context")),
                SystemClock::elapsedRealtime, 60_000L);
    }
}

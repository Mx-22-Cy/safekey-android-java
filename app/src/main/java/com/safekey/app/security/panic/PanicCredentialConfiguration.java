package com.safekey.app.security.panic;

/** Shared, process-local serialization for master, Decoy and Panic credentials. */
public final class PanicCredentialConfiguration {
    private static final Object LOCK = new Object();
    private static long version;

    private PanicCredentialConfiguration() { }
    public static Object lock() { return LOCK; }

    public static long version() {
        synchronized (LOCK) { return version; }
    }

    /** Invalidate grants even when a storage write fails after changing cached state. */
    public static void changed() {
        if (!Thread.holdsLock(LOCK)) {
            throw new IllegalStateException("Credential configuration lock is required.");
        }
        version++;
    }
}

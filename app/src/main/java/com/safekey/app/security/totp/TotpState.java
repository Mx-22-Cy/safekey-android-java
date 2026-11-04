package com.safekey.app.security.totp;

import com.safekey.app.security.panic.PanicRuntimeScope;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/** Owns a copy of the TOTP secret. Close after use to clear that copy. */
public final class TotpState implements AutoCloseable {

    public static final int SECRET_LENGTH_BYTES = 20;

    static final int ENCODED_LENGTH =
            Integer.BYTES + SECRET_LENGTH_BYTES + Long.BYTES
                    + Integer.BYTES + Long.BYTES;

    private static final int FORMAT_VERSION = 1;

    private final byte[] secret;
    private final long lastAcceptedStep;
    private final int failedAttempts;
    private final long blockedUntilEpochMillis;
    private boolean closed;
    private PanicRuntimeScope runtimeScope;
    private PanicRuntimeScope.PendingOperation pendingWork;

    public TotpState(
            byte[] secret,
            long lastAcceptedStep,
            int failedAttempts,
            long blockedUntilEpochMillis
    ) {
        Objects.requireNonNull(secret, "secret");

        if (secret.length != SECRET_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "SafeKey TOTP secrets must contain exactly 20 bytes."
            );
        }

        long maximumStep =
                Long.MAX_VALUE / TotpGenerator.DEFAULT_PERIOD_SECONDS;

        if (lastAcceptedStep < -1L || lastAcceptedStep > maximumStep
                || failedAttempts < 0 || blockedUntilEpochMillis < 0L) {
            throw new IllegalArgumentException("Invalid TOTP state.");
        }

        this.secret = secret.clone();
        this.lastAcceptedStep = lastAcceptedStep;
        this.failedAttempts = failedAttempts;
        this.blockedUntilEpochMillis = blockedUntilEpochMillis;
    }

    public synchronized byte[] copySecret() {
        requireOpen();
        return secret.clone();
    }

    public synchronized long getLastAcceptedStep() {
        requireOpen();
        return lastAcceptedStep;
    }

    public synchronized int getFailedAttempts() {
        requireOpen();
        return failedAttempts;
    }

    public synchronized long getBlockedUntilEpochMillis() {
        requireOpen();
        return blockedUntilEpochMillis;
    }

    public synchronized TotpState withVerificationState(
            long acceptedStep,
            int failures,
            long blockedUntil
    ) {
        requireOpen();
        TotpState updated = new TotpState(secret, acceptedStep, failures, blockedUntil);
        return runtimeScope == null ? updated : updated.bindRuntime(runtimeScope);
    }

    synchronized byte[] encode() {
        requireOpen();

        return ByteBuffer.allocate(ENCODED_LENGTH)
                .putInt(FORMAT_VERSION)
                .put(secret)
                .putLong(lastAcceptedStep)
                .putInt(failedAttempts)
                .putLong(blockedUntilEpochMillis)
                .array();
    }

    static TotpState decode(byte[] plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");

        if (plaintext.length != ENCODED_LENGTH) {
            throw new IllegalArgumentException("Invalid TOTP state length.");
        }

        ByteBuffer input = ByteBuffer.wrap(plaintext);

        if (input.getInt() != FORMAT_VERSION) {
            throw new IllegalArgumentException("Unsupported TOTP state version.");
        }

        byte[] secret = new byte[SECRET_LENGTH_BYTES];

        try {
            input.get(secret);

            return new TotpState(
                    secret,
                    input.getLong(),
                    input.getInt(),
                    input.getLong()
            );
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    @Override
    public synchronized void close() {
        if (pendingWork == null) { wipeSecret(); }
        else { pendingWork.close(); }
    }

    synchronized TotpState bindRuntime(PanicRuntimeScope scope) {
        requireOpen();
        if (runtimeScope != null) { throw new IllegalStateException("TOTP state is already bound."); }
        runtimeScope = Objects.requireNonNull(scope, "scope");
        try { pendingWork = runtimeScope.pending(this::wipeSecret, () -> {}); }
        catch (RuntimeException stopped) { wipeSecret(); throw stopped; }
        return this;
    }

    private synchronized void wipeSecret() {
        Arrays.fill(secret, (byte) 0);
        closed = true;
    }

    private void requireOpen() {
        if (closed || (runtimeScope != null && runtimeScope.isStopped())) {
            throw new IllegalStateException("TOTP state has been closed.");
        }
    }
}

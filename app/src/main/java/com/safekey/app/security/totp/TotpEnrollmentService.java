package com.safekey.app.security.totp;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWorkGate;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * Backend for first-time TOTP enrollment. Call through authenticated Settings.
 * The coordinator must authorize each operation and close abandoned setup.
 * This class does not authenticate the master password or grant vault access.
 */
public final class TotpEnrollmentService {

    public static final long SETUP_LIFETIME_MILLIS = 300_000L;
    public static final int MAX_CONFIRMATION_ATTEMPTS = 5;

    public enum Confirmation {
        ENABLED,
        INVALID_CODE,
        EXPIRED,
        ATTEMPT_LIMIT_REACHED,
        CANCELLED,
        ALREADY_CONFIGURED
    }

    public interface EnrollmentStore extends TotpVerificationService.StateStore {
        void clear() throws GeneralSecurityException, IOException;
    }

    public static final class PendingSetup implements AutoCloseable {
        private static final char[] BASE32 =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

        private final Object owner;
        private final byte[] secret;
        private final PanicRuntimeScope.PendingOperation pendingWork;
        private final LongSupplier monotonicMillis;
        private final long createdAtMillis;
        private int failedAttempts;
        private boolean closed;

        private PendingSetup(
                Object owner,
                byte[] secret,
                LongSupplier monotonicMillis,
                long createdAtMillis,
            PanicRuntimeScope runtimeScope
        ) {
            this.owner = owner;
            this.secret = secret.clone();
            this.monotonicMillis = monotonicMillis;
            this.createdAtMillis = createdAtMillis;
            try { pendingWork = runtimeScope.pending(this::wipeSecret, () -> {}); }
            catch (RuntimeException stopped) { wipeSecret(); throw stopped; }
        }

        /** Caller owns and must clear the returned manual-entry key. */
        public synchronized char[] copyBase32Secret() {
            requireActive();
            char[] encoded = new char[(secret.length * 8 + 4) / 5];
            int buffer = 0;
            int bits = 0;
            int output = 0;

            for (byte value : secret) {
                buffer = (buffer << 8) | (value & 0xFF);
                bits += 8;

                while (bits >= 5) {
                    bits -= 5;
                    encoded[output++] = BASE32[(buffer >>> bits) & 31];
                }
            }

            if (bits > 0) {
                encoded[output] = BASE32[(buffer << (5 - bits)) & 31];
            }

            return encoded;
        }

        /** Sensitive payload for local QR rendering; do not log or persist it. */
        public synchronized String getAuthenticatorUri() {
            char[] encoded = copyBase32Secret();

            try {
                return "otpauth://totp/SafeKey:Vault?secret="
                        + new String(encoded)
                        + "&issuer=SafeKey&algorithm=SHA1&digits=6&period=30";
            } finally {
                Arrays.fill(encoded, '\0');
            }
        }

        public synchronized boolean isActive() {
            expireIfNeeded();
            return !closed;
        }

        public synchronized int getRemainingAttempts() {
            return isActive()
                    ? MAX_CONFIRMATION_ATTEMPTS - failedAttempts
                    : 0;
        }

        @Override
        public synchronized void close() { pendingWork.close(); }

        private synchronized void wipeSecret() {
            Arrays.fill(secret, (byte) 0);
            closed = true;
        }

        private void requireActive() {
            if (!isActive()) {
                throw new IllegalStateException("TOTP setup is no longer active.");
            }
        }

        // Called only while holding this PendingSetup's monitor.
        private boolean expireIfNeeded() {
            if (closed) {
                return false;
            }

            long age = monotonicMillis.getAsLong() - createdAtMillis;

            if (age < 0L || age >= SETUP_LIFETIME_MILLIS) {
                close();
                return true;
            }

            return false;
        }
    }

    private final PanicRuntimeScope runtimeScope;
    private final EnrollmentStore store;
    private final Object transactionLock;
    private final Object owner = new Object();
    private final SecureRandom random;
    private final LongSupplier wallClockMillis;
    private final LongSupplier monotonicMillis;

    public TotpEnrollmentService(EnrollmentStore store) {
        this(
                store,
                new SecureRandom(),
                System::currentTimeMillis,
                () -> System.nanoTime() / 1_000_000L
        );
    }

    /** Android integrations can supply SystemClock::elapsedRealtime here. */
    public TotpEnrollmentService(
            EnrollmentStore store,
            SecureRandom random,
            LongSupplier wallClockMillis,
            LongSupplier monotonicMillis
    ) {
        this.store = Objects.requireNonNull(store, "store");
        runtimeScope = Objects.requireNonNull(store.getPanicRuntimeScope(), "runtimeScope");
        this.transactionLock = Objects.requireNonNull(
                store.getTransactionLock(), "transactionLock"
        );
        this.random = Objects.requireNonNull(random, "random");
        this.wallClockMillis = Objects.requireNonNull(wallClockMillis, "wallClockMillis");
        this.monotonicMillis = Objects.requireNonNull(monotonicMillis, "monotonicMillis");
    }

    private PendingSetup beginWhileRunning() throws GeneralSecurityException, IOException {
        synchronized (transactionLock) {
            try (TotpState existing = store.load()) {
                if (existing != null) {
                    throw new IllegalStateException("TOTP is already configured.");
                }
            }

            byte[] secret = new byte[TotpState.SECRET_LENGTH_BYTES];

            try {
                random.nextBytes(secret);
                long created = monotonicMillis.getAsLong();
                return new PendingSetup(owner, secret, monotonicMillis, created, runtimeScope);
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
        }
    }

    private Confirmation confirmWhileRunning(PendingSetup pending, char[] submittedCode)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(pending, "pending");

        if (pending.owner != owner) {
            throw new IllegalArgumentException("Setup belongs to another enrollment service.");
        }

        char[] codeCopy = submittedCode != null
                && submittedCode.length == TotpGenerator.DEFAULT_DIGITS
                ? submittedCode.clone()
                : null;

        try {
            synchronized (transactionLock) {
                synchronized (pending) {
                    if (pending.closed) {
                        return Confirmation.CANCELLED;
                    }

                    if (pending.expireIfNeeded()) {
                        return Confirmation.EXPIRED;
                    }

                    try (TotpState existing = store.load()) {
                        if (existing != null) {
                            pending.close();
                            return Confirmation.ALREADY_CONFIGURED;
                        }
                    }

                    if (pending.expireIfNeeded()) {
                        return Confirmation.EXPIRED;
                    }

                    long now = wallClockMillis.getAsLong();

                    if (now < 0L) {
                        throw new IllegalStateException("The TOTP clock is invalid.");
                    }

                    long step = TotpVerifier.findMatchingStep(
                            pending.secret, codeCopy, now / 1_000L, -1L
                    );

                    if (step == TotpVerifier.NO_MATCH) {
                        pending.failedAttempts++;

                        if (pending.failedAttempts >= MAX_CONFIRMATION_ATTEMPTS) {
                            pending.close();
                            return Confirmation.ATTEMPT_LIMIT_REACHED;
                        }

                        return Confirmation.INVALID_CODE;
                    }

                    try (TotpState enrolled = new TotpState(pending.secret, step, 0, 0L)) {
                        try {
                            store.save(enrolled);
                        } catch (GeneralSecurityException | IOException | RuntimeException failure) {
                            // No previous configuration existed under this same lock.
                            try {
                                store.clear();
                            } catch (GeneralSecurityException | IOException | RuntimeException cleanup) {
                                failure.addSuppressed(cleanup);
                                pending.close();
                            }
                            throw failure;
                        }
                    }

                    pending.close();
                    return Confirmation.ENABLED;
                }
            }
        } finally {
            if (codeCopy != null) {
                Arrays.fill(codeCopy, '\0');
            }
        }
    }

    public PendingSetup begin() throws GeneralSecurityException, IOException {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return beginWhileRunning();
        }
    }


    public Confirmation confirm(PendingSetup pending, char[] submittedCode)
            throws GeneralSecurityException, IOException {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            return confirmWhileRunning(pending, submittedCode);
        }
    }

}

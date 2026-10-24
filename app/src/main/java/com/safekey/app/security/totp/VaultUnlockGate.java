package com.safekey.app.security.totp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * Owns a pending database key between primary authentication and vault opening.
 * The coordinator must start an attempt before asynchronous authentication,
 * cancel it on abandonment, and serialize key handoff with database cleanup.
 * This class does not open a database or unlock the application session.
 */
public final class VaultUnlockGate {

    public static final int DATABASE_KEY_LENGTH_BYTES = 32;
    public static final long ATTEMPT_LIFETIME_MILLIS = 120_000L;

    public enum Stage {
        WAITING_FOR_PRIMARY,
        TOTP_REQUIRED,
        READY_TO_OPEN,
        OPENING,
        COMPLETED,
        CANCELLED,
        EXPIRED
    }

    public static final class Attempt implements AutoCloseable {
        private final VaultUnlockGate owner;
        private final long startedAtMillis;
        private Stage stage = Stage.WAITING_FOR_PRIMARY;
        private byte[] databaseKey;
        private byte[] totpSecret;

        private Attempt(VaultUnlockGate owner, long startedAtMillis) {
            this.owner = owner;
            this.startedAtMillis = startedAtMillis;
        }

        @Override
        public void close() {
            owner.cancel(this);
        }
    }

    private final TotpVerificationService.StateStore store;
    private final Object storeLock;
    private final TotpVerificationService verification;
    private final LongSupplier monotonicMillis;
    private Attempt current;

    public VaultUnlockGate(TotpVerificationService.StateStore store) {
        this(
                store,
                System::currentTimeMillis,
                () -> System.nanoTime() / 1_000_000L
        );
    }

    /** Android callers should supply SystemClock::elapsedRealtime. */
    public VaultUnlockGate(
            TotpVerificationService.StateStore store,
            LongSupplier wallClockMillis,
            LongSupplier monotonicMillis
    ) {
        this.store = Objects.requireNonNull(store, "store");
        this.storeLock = Objects.requireNonNull(
                store.getTransactionLock(), "storeLock"
        );
        this.verification = new TotpVerificationService(
                store,
                Objects.requireNonNull(wallClockMillis, "wallClockMillis")
        );
        this.monotonicMillis = Objects.requireNonNull(
                monotonicMillis, "monotonicMillis"
        );
    }

    /** Start before deriving a password key or displaying the biometric prompt. */
    public synchronized Attempt begin() {
        if (current != null) {
            cancel(current);
        }
        current = new Attempt(this, monotonicMillis.getAsLong());
        return current;
    }

    /**
     * Call only after successful primary authentication. The supplied key is
     * copied; its caller remains responsible for clearing the original.
     */
    public synchronized Stage acceptPrimary(
            Attempt attempt,
            byte[] databaseKey
    ) throws GeneralSecurityException, IOException {
        requireStage(attempt, Stage.WAITING_FOR_PRIMARY);

        if (databaseKey == null
                || databaseKey.length != DATABASE_KEY_LENGTH_BYTES) {
            cancel(attempt);
            throw new IllegalArgumentException(
                    "A 32-byte database key is required."
            );
        }

        try {
            synchronized (storeLock) {
                attempt.totpSecret = readTotpSecret();
                requireActive(attempt);
                attempt.databaseKey = databaseKey.clone();
                attempt.stage = attempt.totpSecret == null
                        ? Stage.READY_TO_OPEN
                        : Stage.TOTP_REQUIRED;
                return attempt.stage;
            }
        } catch (GeneralSecurityException | IOException | RuntimeException failure) {
            cancel(attempt);
            throw failure;
        }
    }

    /** Replay protection and failed-attempt limits are persisted by the service. */
    public synchronized TotpVerificationService.Result verifyTotp(
            Attempt attempt,
            char[] submittedCode
    ) throws GeneralSecurityException, IOException {
        requireStage(attempt, Stage.TOTP_REQUIRED);

        try {
            synchronized (storeLock) {
                requireUnchangedConfiguration(attempt);

                TotpVerificationService.Result result =
                        verification.verify(submittedCode);

                requireActive(attempt);

                if (result.getStatus()
                        == TotpVerificationService.Status.VERIFIED) {
                    attempt.stage = Stage.READY_TO_OPEN;
                } else if (result.getStatus()
                        == TotpVerificationService.Status.NOT_CONFIGURED) {
                    throw new IllegalStateException(
                            "TOTP configuration is unavailable."
                    );
                }

                return result;
            }
        } catch (GeneralSecurityException | IOException | RuntimeException failure) {
            cancel(attempt);
            throw failure;
        }
    }

    /**
     * One-time handoff to the database adapter, only after all required factors.
     * The coordinator must clear the returned key after the adapter copies it.
     */
    public synchronized byte[] takeKeyForOpening(Attempt attempt)
            throws GeneralSecurityException, IOException {
        requireStage(attempt, Stage.READY_TO_OPEN);

        try {
            synchronized (storeLock) {
                requireUnchangedConfiguration(attempt);
                requireActive(attempt);

                byte[] key = attempt.databaseKey;
                attempt.databaseKey = null;
                attempt.stage = Stage.OPENING;

                clear(attempt.totpSecret);
                attempt.totpSecret = null;

                return key;
            }
        } catch (GeneralSecurityException | IOException | RuntimeException failure) {
            cancel(attempt);
            throw failure;
        }
    }

    /** Only a still-current successful database-open callback may complete. */
    public synchronized boolean complete(Attempt attempt) {
        requireOwner(attempt);
        expireIfNeeded(attempt);

        if (attempt != current || attempt.stage != Stage.OPENING) {
            return false;
        }

        attempt.stage = Stage.COMPLETED;
        wipe(attempt);
        current = null;
        return true;
    }

    public synchronized Stage getStage(Attempt attempt) {
        requireOwner(attempt);
        expireIfNeeded(attempt);
        return attempt.stage;
    }

    public synchronized boolean isActive(Attempt attempt) {
        requireOwner(attempt);
        expireIfNeeded(attempt);
        return attempt == current;
    }

    public synchronized void cancel(Attempt attempt) {
        requireOwner(attempt);

        if (attempt.stage != Stage.COMPLETED
                && attempt.stage != Stage.EXPIRED) {
            attempt.stage = Stage.CANCELLED;
        }

        wipe(attempt);

        if (attempt == current) {
            current = null;
        }
    }

    public synchronized void cancelAll() {
        if (current != null) {
            cancel(current);
        }
    }

    private byte[] readTotpSecret()
            throws GeneralSecurityException, IOException {
        try (TotpState state = store.load()) {
            return state == null ? null : state.copySecret();
        }
    }

    private void requireUnchangedConfiguration(Attempt attempt)
            throws GeneralSecurityException, IOException {
        byte[] latest = readTotpSecret();

        try {
            boolean same = attempt.totpSecret == null
                    ? latest == null
                    : latest != null
                      && MessageDigest.isEqual(attempt.totpSecret, latest);

            if (!same) {
                throw new IllegalStateException(
                        "TOTP configuration changed. Authenticate again."
                );
            }
        } finally {
            clear(latest);
        }
    }

    private void requireStage(Attempt attempt, Stage expected) {
        requireActive(attempt);

        if (attempt.stage != expected) {
            throw new IllegalStateException(
                    "This authentication step is not available."
            );
        }
    }

    private void requireActive(Attempt attempt) {
        requireOwner(attempt);
        expireIfNeeded(attempt);

        if (attempt != current) {
            throw new IllegalStateException(
                    "The unlock attempt is no longer active."
            );
        }
    }

    private void requireOwner(Attempt attempt) {
        Objects.requireNonNull(attempt, "attempt");

        if (attempt.owner != this) {
            throw new IllegalArgumentException(
                    "The unlock attempt belongs to another gate."
            );
        }
    }

    private void expireIfNeeded(Attempt attempt) {
        if (attempt != current) {
            return;
        }

        long age = monotonicMillis.getAsLong() - attempt.startedAtMillis;

        if (age < 0L || age >= ATTEMPT_LIFETIME_MILLIS) {
            attempt.stage = Stage.EXPIRED;
            wipe(attempt);
            current = null;
        }
    }

    private static void wipe(Attempt attempt) {
        clear(attempt.databaseKey);
        clear(attempt.totpSecret);
        attempt.databaseKey = null;
        attempt.totpSecret = null;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}

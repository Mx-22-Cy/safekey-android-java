package com.safekey.app.security.panic;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;

/** Synchronous backend. All methods run on a worker, with no UI or navigation. */
public final class PanicPasswordService {
    public interface Store {
        /** Stable lock shared by every adapter for this stored proof. */
        Object transactionLock();
        PanicPasswordCrypto.Record load() throws Exception;
        void save(PanicPasswordCrypto.Record record) throws Exception;
    }

    /**
     * Non-destructive collision check for master/Decoy setup and changes.
     * Their integration must hold its credential-configuration authorization
     * across this check and the update, so concurrent role changes cannot race.
     */
    public boolean isReservedPassword(char[] candidate) throws Exception {
        char[] password = copy(candidate);
        try {
            if (wipe.isRecoveryRequired()) {
                throw new CancellationException("Panic recovery is required.");
            }
            synchronized (store.transactionLock()) {
                try (PanicWorkGate.Operation ignored = gate.begin()) {
                    PanicPasswordCrypto.Record record = store.load();
                    return record != null && crypto.matches(password, record);
                }
            }
        } finally {
            clear(password);
        }
    }

    public interface Crypto {
        PanicPasswordCrypto.Record create(char[] password) throws Exception;
        boolean matches(char[] password, PanicPasswordCrypto.Record record)
                throws Exception;
    }

    public interface Commit {
        void run() throws Exception;
    }

    /**
     * Integration must verify a current REAL session with completed TOTP,
     * reauthenticate the actual master password, and verify the configured
     * Decoy password. Do not authorize from unverified text or UI visibility.
     */
    public interface EnrollmentAuthority {
        Grant authenticate(char[] master, char[] decoy) throws Exception;
    }

    public interface Grant extends AutoCloseable {
        /**
         * Atomically reject stale session AND role-password configuration
         * generations before committing. No asynchronous check-then-save gap.
         */
        void commitIfCurrent(Commit commit) throws Exception;
        @Override
        void close();
    }

    private final PanicWorkGate gate;
    private final Store store;
    private final Crypto crypto;
    private final PanicWipeCoordinator wipe;

    public PanicPasswordService(PanicWorkGate gate, Store store, Crypto crypto,
                                 PanicWipeCoordinator wipe) {
        this.gate = Objects.requireNonNull(gate, "gate");
        this.store = Objects.requireNonNull(store, "store");
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.wipe = Objects.requireNonNull(wipe, "wipe");
        if (!wipe.usesGate(gate)) {
            throw new IllegalArgumentException("Panic components must share a work gate.");
        }
    }

    public void enroll(char[] master, char[] decoy, char[] panic,
                       char[] confirmation, EnrollmentAuthority authority)
            throws Exception {
        Objects.requireNonNull(authority, "authority");
        char[][] copies = {copy(master), copy(decoy), copy(panic), copy(confirmation)};
        try {
            PanicPasswordPolicy.Result result = PanicPasswordPolicy.validate(
                    copies[0], copies[1], copies[2], copies[3]);
            if (result != PanicPasswordPolicy.Result.VALID) {
                throw new IllegalArgumentException(result.name());
            }
            if (wipe.isRecoveryRequired()) {
                throw new CancellationException("Panic recovery is required.");
            }
            synchronized (store.transactionLock()) {
                try (PanicWorkGate.Operation operation = gate.begin();
                     Grant grant = Objects.requireNonNull(
                             authority.authenticate(copies[0], copies[1]), "grant")) {
                    PanicPasswordCrypto.Record record = crypto.create(copies[2]);
                    grant.commitIfCurrent(() -> {
                        if (!operation.ticket().isCurrent()) {
                            throw new CancellationException("Vault runtime is stopped.");
                        }
                        store.save(record);
                    });
                    if (!operation.ticket().isCurrent()) {
                        throw new CancellationException("Vault runtime is stopped.");
                    }
                }
            }
        } finally {
            for (char[] value : copies) { clear(value); }
        }
    }

    /**
     * Wrong or absent credentials never delete data. Once verified, block new
     * work before releasing the verification operation, then drain and wipe.
     * Shared Sign In must still perform its uniform role checks and routing.
     */
    public boolean checkAndWipe(char[] candidate) throws Exception {
        char[] password = copy(candidate);
        try {
            if (wipe.resumeIfPending()) {
                return true;
            }
            synchronized (store.transactionLock()) {
                try (PanicWorkGate.Operation ignored = gate.begin()) {
                    PanicPasswordCrypto.Record record = store.load();
                    if (record == null || !crypto.matches(password, record)) {
                        return false;
                    }
                    gate.blockNewWork();
                }
            }
            wipe.wipe();
            return true;
        } finally {
            clear(password);
        }
    }

    private static char[] copy(char[] value) {
        return value == null ? null : value.clone();
    }

    private static void clear(char[] value) {
        if (value != null) { Arrays.fill(value, '\0'); }
    }
}

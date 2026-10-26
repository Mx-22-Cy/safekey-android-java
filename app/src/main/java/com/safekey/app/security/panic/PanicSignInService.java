package com.safekey.app.security.panic;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;

/** Checks every password role before routing or authorizing destructive cleanup. */
public final class PanicSignInService {
    /** MASTER/DECOY identify a role; neither opens a vault nor completes authentication. */
    public enum Result { NO_MATCH, MASTER, DECOY, PANIC_WIPED }

    interface Submission extends AutoCloseable {
        /** Transfers one privately owned copy. The service clears it before releasing its work lease. */
        char[] takePassword();
        void commitIfCurrent(PanicPasswordService.Commit action) throws Exception;
        @Override void close();
    }

    interface Credentials { Snapshot capture() throws Exception; }
    interface Snapshot {
        boolean matchesMaster(char[] candidate) throws Exception;
        boolean matchesDecoy(char[] candidate) throws Exception;
        boolean matchesPanic(char[] candidate) throws Exception;
        void commitIfCurrent(PanicPasswordService.Commit action) throws Exception;
    }

    private final PanicWorkGate gate;
    private final Credentials credentials;
    private final PanicWipeCoordinator wipe;

    PanicSignInService(PanicWorkGate gate, Credentials credentials, PanicWipeCoordinator wipe) {
        this.gate = Objects.requireNonNull(gate, "gate");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.wipe = Objects.requireNonNull(wipe, "wipe");
        if (!wipe.usesGate(gate)) { throw new IllegalArgumentException("Sign In must share the Panic work gate."); }
    }

    /** Use an independent control worker. No counted vault worker may wait for its own drain. */
    Result run(Submission submission) throws Exception {
        Objects.requireNonNull(submission, "submission");
        Result[] decided = {Result.NO_MATCH};
        try (Submission ignoredSubmission = submission) {
            // Pending recovery is handled by startup, never as a new password match.
            if (wipe.isRecoveryRequired()) { throw new CancellationException("Startup recovery is required."); }
            try (PanicWorkGate.Operation operation = gate.begin()) {
                char[] candidate = submission.takePassword();
                try {
                    if (candidate == null || candidate.length == 0 || candidate.length > com.safekey.app.auth.logic.MasterPasswordPolicy.MAX_LENGTH * 2) {
                        throw new IllegalArgumentException("Invalid sign-in input length.");
                    }
                    Snapshot snapshot = credentials.capture();
                    boolean[] matches = new boolean[3];
                    GeneralSecurityException failure = new GeneralSecurityException("Password checks failed.");
                    // Never short-circuit on a match or on one role's ordinary storage/crypto error.
                    try { matches[0] = snapshot.matchesMaster(candidate); }
                    catch (Exception error) { failure.addSuppressed(error); }
                    try { matches[1] = snapshot.matchesDecoy(candidate); }
                    catch (Exception error) { failure.addSuppressed(error); }
                    try { matches[2] = snapshot.matchesPanic(candidate); }
                    catch (Exception error) { failure.addSuppressed(error); }
                    if (failure.getSuppressed().length != 0) { throw failure; }
                    int count = (matches[0] ? 1 : 0) + (matches[1] ? 1 : 0) + (matches[2] ? 1 : 0);
                    if (count > 1) { throw new GeneralSecurityException("Password roles are ambiguous."); }
                    Result result = matches[2] ? Result.PANIC_WIPED
                            : matches[1] ? Result.DECOY : matches[0] ? Result.MASTER : Result.NO_MATCH;
                    snapshot.commitIfCurrent(() -> submission.commitIfCurrent(() -> {
                        if (!operation.ticket().isCurrent()) { throw new CancellationException("Sign In was invalidated."); }
                        if (result == Result.PANIC_WIPED) { gate.blockNewWork(); }
                        decided[0] = result;
                    }));
                } finally { if (candidate != null) { Arrays.fill(candidate, '\0'); } }
            }
        }
        // All input copies and this request's leases are gone before the shutdown waits.
        if (decided[0] == Result.PANIC_WIPED) { wipe.wipe(); }
        return decided[0];
    }
}

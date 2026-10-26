package com.safekey.app.security.panic;

import org.junit.Test;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.CancellationException;

import static org.junit.Assert.*;

public class PanicEnrollmentAuthorityTest {
    private static final class Fixture {
        final PanicWorkGate gate = new PanicWorkGate();
        long now;
        long sessionVersion;
        long credentialVersion;
        boolean authenticated = true;
        boolean real = true;
        boolean masterMatches = true;
        boolean decoyMatches = true;
        boolean corrupt;
        int masterChecks;
        int decoyChecks;
        int saves;
        char[] masterCopy;
        char[] decoyCopy;
        final PanicEnrollmentAuthority authority = new PanicEnrollmentAuthority(gate, () -> {
            if (!authenticated || !real) { throw new CancellationException(); }
            long expected = sessionVersion;
            return action -> {
                if (!authenticated || !real || sessionVersion != expected) { throw new CancellationException(); }
                action.run();
            };
        }, () -> {
            if (corrupt) { throw new GeneralSecurityException("Corrupt credentials."); }
            long expected = credentialVersion;
            return new PanicEnrollmentAuthority.CredentialProof() {
                @Override public boolean matchesMaster(char[] password) {
                    masterCopy = password; masterChecks++; return masterMatches;
                }
                @Override public boolean matchesDecoy(char[] password) {
                    decoyCopy = password; decoyChecks++; return decoyMatches;
                }
                @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
                    if (credentialVersion != expected) { throw new CancellationException(); }
                    action.run();
                }
            };
        }, () -> now, 60_000L);

        PanicPasswordService.Grant authenticate() throws Exception {
            return authority.authenticate("master input".toCharArray(), "decoy input".toCharArray());
        }
        void commit(PanicPasswordService.Grant grant) throws Exception { grant.commitIfCurrent(() -> saves++); }
    }

    private static void rejects(PanicPasswordService.Commit action) throws Exception {
        try { action.run(); fail("Stale/invalid authorization was accepted."); }
        catch (CancellationException | GeneralSecurityException expected) { }
    }

    @Test public void verifiedRealSessionAndBothPasswordsAllowOneCommit() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordService.Grant grant = f.authenticate()) { f.commit(grant); }
        assertEquals(1, f.saves);
        assertEquals(1, f.masterChecks); assertEquals(1, f.decoyChecks);
    }

    @Test public void lockedSessionCannotAuthorizeEnrollment() throws Exception {
        Fixture f = new Fixture(); f.authenticated = false;
        rejects(() -> f.authenticate()); assertEquals(0, f.saves);
    }

    @Test public void decoySessionCannotAuthorizeEnrollment() throws Exception {
        Fixture f = new Fixture(); f.real = false;
        rejects(() -> f.authenticate()); assertEquals(0, f.saves);
    }

    @Test public void wrongMasterStillChecksDecoyButNeverReturnsGrant() throws Exception {
        Fixture f = new Fixture(); f.masterMatches = false;
        rejects(() -> f.authenticate());
        assertEquals(1, f.masterChecks); assertEquals(1, f.decoyChecks); assertEquals(0, f.saves);
    }

    @Test public void wrongDecoyCannotAuthorizeEnrollment() throws Exception {
        Fixture f = new Fixture(); f.decoyMatches = false;
        rejects(() -> f.authenticate()); assertEquals(0, f.saves);
    }

    @Test public void corruptStoredCredentialIsAnErrorNotAuthorization() throws Exception {
        Fixture f = new Fixture(); f.corrupt = true;
        rejects(() -> f.authenticate()); assertEquals(0, f.saves);
    }

    @Test public void sessionLockBeforeCommitRejectsGrant() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordService.Grant grant = f.authenticate()) {
            f.authenticated = false; rejects(() -> f.commit(grant));
        }
        assertEquals(0, f.saves);
    }

    @Test public void reauthenticationBeforeCommitRejectsOldGrant() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordService.Grant grant = f.authenticate()) {
            f.sessionVersion++; rejects(() -> f.commit(grant));
        }
        assertEquals(0, f.saves);
    }

    @Test public void credentialChangeBeforeCommitRejectsOldGrant() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordService.Grant grant = f.authenticate()) {
            f.credentialVersion++; rejects(() -> f.commit(grant));
        }
        assertEquals(0, f.saves);
    }

    @Test public void stoppedRuntimeCannotCommitPreviouslyAuthorizedProof() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordService.Grant grant = f.authenticate()) {
            f.gate.blockNewWork(); rejects(() -> f.commit(grant));
        }
        assertEquals(0, f.saves);
    }

    @Test public void grantCannotBeUsedAfterExplicitClose() throws Exception {
        Fixture f = new Fixture(); PanicPasswordService.Grant grant = f.authenticate();
        grant.close(); rejects(() -> f.commit(grant)); assertEquals(0, f.saves);
    }

    @Test public void grantCannotBeCommittedTwice() throws Exception {
        Fixture f = new Fixture();
        try (PanicPasswordService.Grant grant = f.authenticate()) {
            f.commit(grant); rejects(() -> f.commit(grant));
        }
        assertEquals(1, f.saves);
    }

    @Test public void expiredOrReversedClockRejectsGrant() throws Exception {
        for (long time : new long[]{60_000L, -1L}) {
            Fixture f = new Fixture();
            try (PanicPasswordService.Grant grant = f.authenticate()) {
                f.now = time; rejects(() -> f.commit(grant));
            }
            assertEquals(0, f.saves);
        }
    }

    @Test public void authorityClearsOnlyItsCopiesAfterSuccess() throws Exception {
        Fixture f = new Fixture();
        char[] master = "master input".toCharArray(); char[] decoy = "decoy input".toCharArray();
        try (PanicPasswordService.Grant ignored = f.authority.authenticate(master, decoy)) {
            assertArrayEquals("master input".toCharArray(), master);
            assertArrayEquals("decoy input".toCharArray(), decoy);
            assertTrue(Arrays.equals(new char[f.masterCopy.length], f.masterCopy));
            assertTrue(Arrays.equals(new char[f.decoyCopy.length], f.decoyCopy));
        }
    }

    @Test public void authorityClearsItsCopiesAfterReauthenticationFailure() throws Exception {
        Fixture f = new Fixture(); f.masterMatches = false;
        rejects(() -> f.authenticate());
        assertArrayEquals(new char[f.masterCopy.length], f.masterCopy);
        assertArrayEquals(new char[f.decoyCopy.length], f.decoyCopy);
    }
}

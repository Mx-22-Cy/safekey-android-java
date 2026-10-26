package com.safekey.app.auth.logic;

import com.safekey.app.breach.PasswordBreachResult;

import org.junit.Test;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.safekey.app.auth.logic.MasterPasswordScreening.Outcome;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;

public class MasterPasswordScreeningTest {

    private static final String CANDIDATE = "clouds drift quietly over mountains";

    @Test
    public void localBlocklistRejectsBeforeNetwork() {
        assertLocalRejection("PasswordPassword", "PasswordPassword",
                MasterPasswordValidationResult.EASILY_GUESSED);
    }

    @Test
    public void shortPasswordRejectsBeforeNetwork() {
        assertLocalRejection("short", "short", MasterPasswordValidationResult.TOO_SHORT);
    }

    @Test
    public void missingPasswordRejectsBeforeNetwork() {
        assertLocalRejection(null, null, MasterPasswordValidationResult.REQUIRED);
    }

    @Test
    public void missingConfirmationRejectsBeforeNetwork() {
        assertLocalRejection(CANDIDATE, null,
                MasterPasswordValidationResult.CONFIRMATION_REQUIRED);
    }

    @Test
    public void mismatchRejectsBeforeNetwork() {
        assertLocalRejection(CANDIDATE, "another long password",
                MasterPasswordValidationResult.PASSWORDS_DO_NOT_MATCH);
    }

    @Test
    public void blockedWordInsideDifferentPassphraseIsNotRejectedLocally() {
        FakeChecker checker = new FakeChecker();
        char[] password = "passwordpassword under violet skies".toCharArray();
        MasterPasswordScreening.Request request =
                new MasterPasswordScreening(checker).checkNewPassword(
                        password, password, ignored -> { });
        assertEquals(1, checker.calls);
        request.close();
        assertEquals(1, checker.cancellations);
    }

    @Test
    public void networkReceivesCopyIndependentOfCallerClearingInput() {
        FakeChecker checker = new FakeChecker();
        char[] password = CANDIDATE.toCharArray();
        char[] confirmation = CANDIDATE.toCharArray();
        MasterPasswordScreening.Request request =
                new MasterPasswordScreening(checker).checkNewPassword(
                        password, confirmation, ignored -> { });
        assertNotSame(password, checker.ownedPassword);
        assertNotSame(confirmation, checker.ownedPassword);
        Arrays.fill(password, '\0');
        Arrays.fill(confirmation, '\0');
        assertArrayEquals(CANDIDATE.toCharArray(), checker.ownedPassword);
        request.close();
        assertArrayEquals(new char[checker.ownedPassword.length], checker.ownedPassword);
    }

    @Test
    public void breachedPasswordAlwaysRejects() {
        assertOutcome(PasswordBreachResult.breached(1), Outcome.BREACHED);
    }

    @Test
    public void noMatchIsOnlineAcceptance() {
        assertOutcome(PasswordBreachResult.notFound(), Outcome.CHECKED_ACCEPTABLE);
    }

    @Test
    public void offlineRequiresExplicitChoice() {
        assertOutcome(PasswordBreachResult.error(PasswordBreachResult.ErrorReason.OFFLINE),
                Outcome.OFFLINE_CHOICE_REQUIRED);
    }

    @Test
    public void timeoutRequiresExplicitChoice() {
        assertOutcome(PasswordBreachResult.error(PasswordBreachResult.ErrorReason.TIMEOUT),
                Outcome.OFFLINE_CHOICE_REQUIRED);
    }

    @Test
    public void networkErrorRequiresExplicitChoice() {
        assertOutcome(PasswordBreachResult.error(PasswordBreachResult.ErrorReason.NETWORK_ERROR),
                Outcome.OFFLINE_CHOICE_REQUIRED);
    }

    @Test
    public void malformedResponseDoesNotEnableOfflineBypass() {
        assertOutcome(PasswordBreachResult.error(PasswordBreachResult.ErrorReason.INVALID_RESPONSE),
                Outcome.RETRY_REQUIRED);
    }

    @Test
    public void invalidInputDoesNotEnableOfflineBypass() {
        assertOutcome(PasswordBreachResult.error(PasswordBreachResult.ErrorReason.INVALID_INPUT),
                Outcome.RETRY_REQUIRED);
    }

    @Test
    public void uncheckedIsNeitherOnlineAcceptanceNorOfflineChoice() {
        assertOutcome(PasswordBreachResult.notChecked(), Outcome.RETRY_REQUIRED);
    }

    @Test
    public void missingResultRequiresRetry() {
        assertOutcome(null, Outcome.RETRY_REQUIRED);
    }

    @Test
    public void cancellationSuppressesQueuedAndDuplicateResults() {
        FakeChecker checker = new FakeChecker();
        AtomicInteger callbacks = new AtomicInteger();
        MasterPasswordScreening.Request request = newCheck(checker,
                ignored -> callbacks.incrementAndGet());
        request.close();
        request.close();
        checker.complete(PasswordBreachResult.notFound());
        checker.complete(PasswordBreachResult.breached(3));
        assertEquals(0, callbacks.get());
        assertEquals(1, checker.cancellations);
    }

    @Test
    public void duplicateDeliveryCannotReplaceBreachedDecision() {
        FakeChecker checker = new FakeChecker();
        AtomicInteger callbacks = new AtomicInteger();
        AtomicReference<Outcome> outcome = new AtomicReference<>();
        MasterPasswordScreening.Request request = newCheck(checker, result -> {
            callbacks.incrementAndGet();
            outcome.set(result.getOutcome());
        });
        checker.complete(PasswordBreachResult.breached(10));
        checker.complete(PasswordBreachResult.notFound());
        request.close();
        assertEquals(1, callbacks.get());
        assertEquals(Outcome.BREACHED, outcome.get());
        assertEquals(1, checker.cancellations);
    }

    @Test
    public void oldCancelledRequestCannotDeliverAlongsideReplacement() {
        FakeChecker old = new FakeChecker();
        FakeChecker replacement = new FakeChecker();
        AtomicReference<Outcome> result = new AtomicReference<>();
        MasterPasswordScreening.Request oldRequest = newCheck(old,
                value -> result.set(value.getOutcome()));
        oldRequest.close();
        newCheck(replacement, value -> result.set(value.getOutcome()));
        old.complete(PasswordBreachResult.notFound());
        assertNull(result.get());
        replacement.complete(PasswordBreachResult.breached(2));
        assertEquals(Outcome.BREACHED, result.get());
    }

    @Test
    public void synchronousCompletionClosesHandleReturnedAfterCallback() {
        AtomicInteger cancellations = new AtomicInteger();
        AtomicReference<Outcome> result = new AtomicReference<>();
        MasterPasswordScreening screening = new MasterPasswordScreening((password, callback) -> {
            Arrays.fill(password, '\0');
            callback.onResult(PasswordBreachResult.notFound());
            return cancellations::incrementAndGet;
        });
        char[] candidate = CANDIDATE.toCharArray();
        screening.checkNewPassword(candidate, candidate,
                value -> result.set(value.getOutcome())).close();
        assertEquals(Outcome.CHECKED_ACCEPTABLE, result.get());
        assertEquals(1, cancellations.get());
    }

    @Test
    public void checkerSetupFailureClearsCopyAndRequiresRetry() {
        AtomicReference<char[]> copy = new AtomicReference<>();
        AtomicReference<Outcome> result = new AtomicReference<>();
        MasterPasswordScreening screening = new MasterPasswordScreening((password, callback) -> {
            copy.set(password);
            throw new IllegalStateException("Test scheduling failure");
        });
        char[] candidate = CANDIDATE.toCharArray();
        screening.checkNewPassword(candidate, candidate,
                value -> result.set(value.getOutcome()));
        assertArrayEquals(new char[candidate.length], copy.get());
        assertArrayEquals(CANDIDATE.toCharArray(), candidate);
        assertEquals(Outcome.RETRY_REQUIRED, result.get());
    }

    @Test
    public void recheckingLegacyPasswordDoesNotApplyNewMinimumLength() {
        FakeChecker checker = new FakeChecker();
        AtomicReference<Outcome> result = new AtomicReference<>();
        new MasterPasswordScreening(checker).recheckExistingPassword("short".toCharArray(),
                value -> result.set(value.getOutcome()));
        assertEquals(1, checker.calls);
        checker.complete(PasswordBreachResult.breached(7));
        assertEquals(Outcome.BREACHED, result.get());
    }

    @Test
    public void emptyRecheckDoesNotUseNetwork() {
        FakeChecker checker = new FakeChecker();
        AtomicReference<Outcome> result = new AtomicReference<>();
        new MasterPasswordScreening(checker).recheckExistingPassword(new char[0],
                value -> result.set(value.getOutcome()));
        assertEquals(0, checker.calls);
        assertEquals(Outcome.LOCAL_REJECTION, result.get());
    }

    private static void assertLocalRejection(
            String candidate, String confirmation, MasterPasswordValidationResult expected
    ) {
        FakeChecker checker = new FakeChecker();
        AtomicReference<MasterPasswordScreening.Result> result = new AtomicReference<>();
        new MasterPasswordScreening(checker).checkNewPassword(
                candidate == null ? null : candidate.toCharArray(),
                confirmation == null ? null : confirmation.toCharArray(), result::set);
        assertEquals(0, checker.calls);
        assertEquals(Outcome.LOCAL_REJECTION, result.get().getOutcome());
        assertEquals(expected, result.get().getValidation());
    }

    private static void assertOutcome(PasswordBreachResult supplied, Outcome expected) {
        FakeChecker checker = new FakeChecker();
        AtomicReference<Outcome> result = new AtomicReference<>();
        newCheck(checker, value -> result.set(value.getOutcome()));
        checker.complete(supplied);
        assertEquals(expected, result.get());
        assertEquals(1, checker.cancellations);
    }

    private static MasterPasswordScreening.Request newCheck(
            FakeChecker checker, MasterPasswordScreening.Callback callback
    ) {
        char[] candidate = CANDIDATE.toCharArray();
        return new MasterPasswordScreening(checker)
                .checkNewPassword(candidate, candidate, callback);
    }

    private static final class FakeChecker implements MasterPasswordScreening.BreachChecker {
        private int calls;
        private int cancellations;
        private char[] ownedPassword;
        private MasterPasswordScreening.BreachCallback callback;

        @Override
        public MasterPasswordScreening.Cancellation check(
                char[] password, MasterPasswordScreening.BreachCallback callback
        ) {
            calls++;
            ownedPassword = password;
            this.callback = callback;
            return () -> {
                cancellations++;
                Arrays.fill(ownedPassword, '\0');
            };
        }

        private void complete(PasswordBreachResult result) {
            Arrays.fill(ownedPassword, '\0');
            callback.onResult(result);
        }
    }
}

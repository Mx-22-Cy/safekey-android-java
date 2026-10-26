package com.safekey.app.security.results;

import com.safekey.app.breach.PasswordBreachResult.Status;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CredentialSecuritySummaryTest {
    @Test public void emptyVaultDoesNotInventPerfectScore() {
        CredentialSecuritySummary summary = new CredentialSecuritySummary(Collections.emptyList());
        assertEquals(CredentialSecuritySummary.Availability.EMPTY, summary.getAvailability());
        assertEquals(0, summary.getAtRiskCount());
        assertFalse(summary.hasScore());
        try { summary.getScore(); fail("An empty vault has no score"); }
        catch (IllegalStateException expected) { }
    }

    @Test public void uncheckedStrongPasswordIsNotPassed() {
        CredentialSecurityItem item = item(1, Status.NOT_CHECKED, 4, false);
        assertEquals(CredentialSecurityItem.Group.ATTENTION, item.getGroup());
        assertFalse(item.isComplete());
        assertFalse(item.hasKnownRisk());
    }

    @Test public void networkFailureDoesNotInventKnownBreach() {
        CredentialSecuritySummary summary = summary(item(1, Status.ERROR, 4, false));
        assertEquals(0, summary.getBreachCount());
        assertEquals(0, summary.getAtRiskCount());
        assertEquals(1, summary.getIncompleteCount());
        assertEquals(CredentialSecuritySummary.Availability.UNAVAILABLE, summary.getAvailability());
    }

    @Test public void weakNonBreachedPasswordNeedsAttention() {
        CredentialSecurityItem item = item(1, Status.NOT_FOUND, 2, false);
        assertTrue(item.hasKnownRisk());
        assertEquals(CredentialSecurityItem.Group.ATTENTION, item.getGroup());
    }

    @Test public void reusedStrongPasswordNeedsAttention() {
        CredentialSecurityItem item = item(1, Status.NOT_FOUND, 4, true);
        assertTrue(item.hasKnownRisk());
        assertEquals(CredentialSecurityItem.Group.ATTENTION, item.getGroup());
    }

    @Test public void breachTakesPriorityOverOtherIssues() {
        CredentialSecurityItem item = item(1, Status.BREACHED, 1, true);
        assertEquals(CredentialSecurityItem.Group.BREACHED, item.getGroup());
        CredentialSecuritySummary summary = summary(item);
        assertEquals(1, summary.getAtRiskCount());
        assertEquals(1, summary.getBreachCount());
        assertEquals(0, summary.getAttentionCount());
    }

    @Test public void cleanCredentialRequiresAllThreeConditions() {
        CredentialSecuritySummary summary = summary(item(1, Status.NOT_FOUND, 3, false));
        assertEquals(1, summary.getPassedCount());
        assertEquals(100, summary.getScore());
    }

    @Test public void scoreIsPercentOfCredentialsWithoutKnownIssues() {
        CredentialSecuritySummary summary = summary(
                item(1, Status.NOT_FOUND, 4, false), item(2, Status.NOT_FOUND, 4, false),
                item(3, Status.NOT_FOUND, 1, false), item(4, Status.BREACHED, 4, false));
        assertEquals(50, summary.getScore());
        assertEquals(2, summary.getAtRiskCount());
        assertEquals(1, summary.getBreachCount());
    }

    @Test public void scoreRoundsToNearestWholePercent() {
        assertEquals(67, summary(item(1, Status.NOT_FOUND, 4, false),
                item(2, Status.NOT_FOUND, 3, false), item(3, Status.BREACHED, 4, false)).getScore());
    }

    @Test public void oneUncheckedRecordPreventsMisleadingPartialScore() {
        CredentialSecuritySummary summary = summary(item(1, Status.NOT_FOUND, 4, false),
                item(2, Status.NOT_CHECKED, 4, false));
        assertFalse(summary.hasScore());
        assertEquals(CredentialSecuritySummary.Availability.NOT_CHECKED, summary.getAvailability());
    }

    @Test public void unavailableStrengthPreventsPassingOrNumericScore() {
        CredentialSecuritySummary summary = summary(item(1, Status.NOT_FOUND, -1, false));
        assertFalse(summary.hasScore());
        assertEquals(0, summary.getPassedCount());
        assertEquals(CredentialSecuritySummary.Availability.UNAVAILABLE, summary.getAvailability());
    }

    @Test public void missingPasswordIsKnownRiskEvenWithoutNetworkResult() {
        CredentialSecurityItem item = new CredentialSecurityItem(1, "Missing", Status.NOT_CHECKED,
                0, false, true, 0L, false, false);
        assertTrue(item.hasKnownRisk());
        assertFalse(item.isComplete());
    }

    @Test public void savedCompletedCheckRemainsValidDuringFailedRefresh() {
        CredentialSecurityItem item = new CredentialSecurityItem(1, "Saved", Status.NOT_FOUND,
                4, false, false, 0L, false, true);
        assertEquals(100, summary(item).getScore());
    }

    @Test public void duplicateIdsCannotInflateScoreOrCounts() {
        try {
            summary(item(1, Status.NOT_FOUND, 4, false), item(1, Status.NOT_FOUND, 4, false));
            fail("Duplicate IDs must be rejected");
        } catch (IllegalArgumentException expected) { }
    }

    private static CredentialSecuritySummary summary(CredentialSecurityItem... items) {
        return new CredentialSecuritySummary(Arrays.asList(items));
    }

    private static CredentialSecurityItem item(long id, Status status, int score, boolean reused) {
        return new CredentialSecurityItem(id, "Item", status, score, reused, false, 0L, false, false);
    }
}

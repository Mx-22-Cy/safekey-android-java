package com.safekey.app.security.results;

import com.safekey.app.breach.PasswordBreachResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** The same policy supplies Home counts, score and Alerts grouping. */
public final class CredentialSecuritySummary {
    public enum Availability { EMPTY, NOT_CHECKED, UNAVAILABLE, READY }

    private final List<CredentialSecurityItem> items;
    private final int atRisk;
    private final int breached;
    private final int incomplete;
    private final int attention;
    private final int passed;
    private final Availability availability;

    public CredentialSecuritySummary(List<CredentialSecurityItem> source) {
        Objects.requireNonNull(source, "source");
        List<CredentialSecurityItem> copy = new ArrayList<>(source);
        Set<Long> ids = new HashSet<>();
        int risks = 0, breaches = 0, unknown = 0, needsAttention = 0, passes = 0;
        boolean unavailable = false;
        for (CredentialSecurityItem item : copy) {
            Objects.requireNonNull(item, "item");
            if (!ids.add(item.getId())) {
                throw new IllegalArgumentException("Duplicate credential identifier.");
            }
            if (item.hasKnownRisk()) { risks++; }
            if (item.isBreached()) { breaches++; }
            if (!item.isComplete()) { unknown++; }
            if (item.getBreachStatus() == PasswordBreachResult.Status.ERROR
                    || item.getStrengthScore() < 0
                    || (item.isRefreshFailed() && !item.isComplete())) { unavailable = true; }
            if (item.getGroup() == CredentialSecurityItem.Group.ATTENTION) { needsAttention++; }
            if (item.getGroup() == CredentialSecurityItem.Group.PASSED) { passes++; }
        }
        items = Collections.unmodifiableList(copy);
        atRisk = risks;
        breached = breaches;
        incomplete = unknown;
        attention = needsAttention;
        passed = passes;
        availability = copy.isEmpty() ? Availability.EMPTY
                : unknown == 0 ? Availability.READY
                : unavailable ? Availability.UNAVAILABLE : Availability.NOT_CHECKED;
    }

    public List<CredentialSecurityItem> getItems() { return items; }
    public int getTotalCount() { return items.size(); }
    public int getAtRiskCount() { return atRisk; }
    public int getBreachCount() { return breached; }
    public int getIncompleteCount() { return incomplete; }
    public int getAttentionCount() { return attention; }
    public int getPassedCount() { return passed; }
    public Availability getAvailability() { return availability; }
    public boolean hasScore() { return availability == Availability.READY; }

    public int getScore() {
        if (!hasScore()) {
            throw new IllegalStateException("A complete security score is not available.");
        }
        return (int) Math.round(100.0d * passed / items.size());
    }
}

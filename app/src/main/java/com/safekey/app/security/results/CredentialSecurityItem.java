package com.safekey.app.security.results;

import com.safekey.app.breach.PasswordBreachResult;

import java.util.Objects;

/** Immutable presentation metadata. Never retains a credential password. */
public final class CredentialSecurityItem {
    public enum Group { BREACHED, ATTENTION, PASSED }

    private final long id;
    private final String title;
    private final PasswordBreachResult.Status breachStatus;
    private final int strengthScore;
    private final boolean reused;
    private final boolean missingPassword;
    private final long occurrences;
    private final boolean checking;
    private final boolean refreshFailed;

    public CredentialSecurityItem(long id, String title, PasswordBreachResult.Status breachStatus,
                                  int strengthScore, boolean reused, boolean missingPassword,
                                  long occurrences, boolean checking, boolean refreshFailed) {
        if (id <= 0L || strengthScore < -1 || strengthScore > 4 || occurrences < 0L) {
            throw new IllegalArgumentException("Invalid credential security metadata.");
        }
        this.id = id;
        this.title = title == null ? "" : title;
        this.breachStatus = Objects.requireNonNull(breachStatus, "breachStatus");
        this.strengthScore = strengthScore;
        this.reused = reused;
        this.missingPassword = missingPassword;
        this.occurrences = occurrences;
        this.checking = checking;
        this.refreshFailed = refreshFailed;
    }

    public long getId() { return id; }
    public String getTitle() { return title; }
    public PasswordBreachResult.Status getBreachStatus() { return breachStatus; }
    public int getStrengthScore() { return strengthScore; }
    public boolean isReused() { return reused; }
    public boolean isMissingPassword() { return missingPassword; }
    public long getOccurrences() { return occurrences; }
    public boolean isChecking() { return checking; }
    public boolean isRefreshFailed() { return refreshFailed; }
    public boolean isWeak() { return missingPassword || (strengthScore >= 0 && strengthScore < 3); }
    public boolean isBreached() { return breachStatus == PasswordBreachResult.Status.BREACHED; }

    public boolean hasKnownRisk() { return isWeak() || reused || isBreached(); }

    public boolean isComplete() {
        return strengthScore >= 0 && !missingPassword
                && (breachStatus == PasswordBreachResult.Status.BREACHED
                || breachStatus == PasswordBreachResult.Status.NOT_FOUND);
    }

    public Group getGroup() {
        if (isBreached()) { return Group.BREACHED; }
        return !isComplete() || hasKnownRisk() ? Group.ATTENTION : Group.PASSED;
    }
}

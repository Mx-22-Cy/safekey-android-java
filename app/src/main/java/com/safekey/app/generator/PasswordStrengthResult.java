package com.safekey.app.generator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable credential-strength feedback for the UI.
 * Contains an estimate and feedback, without retaining the password.
 */
public final class PasswordStrengthResult {

    private final int score;
    private final boolean empty;
    private final String warning;
    private final List<String> suggestions;

    private PasswordStrengthResult(
            int score,
            boolean empty,
            String warning,
            List<String> suggestions
    ) {
        if (score < 0 || score > 4) {
            throw new IllegalArgumentException(
                    "Strength score must be between 0 and 4."
            );
        }

        this.score = score;
        this.empty = empty;
        this.warning = warning == null ? "" : warning;

        this.suggestions = Collections.unmodifiableList(
                new ArrayList<>(
                        Objects.requireNonNull(suggestions, "suggestions")
                )
        );
    }

    static PasswordStrengthResult empty() {
        return new PasswordStrengthResult(
                0,
                true,
                "",
                Collections.emptyList()
        );
    }

    static PasswordStrengthResult fromEstimate(
            int score,
            String warning,
            List<String> suggestions
    ) {
        return new PasswordStrengthResult(
                score,
                false,
                warning,
                suggestions
        );
    }

    public boolean isEmpty() {
        return empty;
    }

    /**
     * Returns the estimated score from 0 to 4.
     * Check isEmpty() before displaying strength feedback.
     */
    public int getScore() {
        return score;
    }

    public String getLabel() {
        if (empty) {
            return "";
        }

        switch (score) {
            case 0:
                return "Very weak";
            case 1:
                return "Weak";
            case 2:
                return "Fair";
            case 3:
                return "Strong";
            case 4:
                return "Very strong";
            default:
                throw new IllegalStateException(
                        "Unexpected strength score."
                );
        }
    }

    public String getWarning() {
        return warning;
    }

    public List<String> getSuggestions() {
        return suggestions;
    }
}

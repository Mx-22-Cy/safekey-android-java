package com.safekey.app.generator;

import com.nulabinc.zxcvbn.Feedback;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;

import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Estimates credential password strength using bundled dictionaries.
 *
 * For live UI feedback, reuse an instance on a background worker.
 * The result contains only the score and feedback.
 */
public final class PasswordStrengthEvaluator {

    public static final int MAX_PASSWORD_LENGTH = 128;

    private final Function<CharSequence, Strength> measurement;

    public PasswordStrengthEvaluator() {
        this(new Zxcvbn()::measure);
    }

    // Allows tests to check input handling and cleanup.
    PasswordStrengthEvaluator(
            Function<CharSequence, Strength> measurement
    ) {
        this.measurement = Objects.requireNonNull(
                measurement,
                "measurement"
        );
    }

    /**
     * Evaluates up to 128 UTF-16 code units.
     * Null or empty input produces an empty result.
     *
     * Leaves the caller's array unchanged and clears this class's
     * working copy when evaluation finishes, including on failure.
     */
    public PasswordStrengthResult evaluate(char[] password) {
        if (password == null || password.length == 0) {
            return PasswordStrengthResult.empty();
        }

        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Strength evaluation supports at most "
                            + MAX_PASSWORD_LENGTH + " characters."
            );
        }

        char[] workingCopy = password.clone();

        try {
            CharBuffer input = CharBuffer.wrap(workingCopy)
                    .asReadOnlyBuffer();

            Strength strength = Objects.requireNonNull(
                    measurement.apply(input),
                    "Strength estimation returned no result."
            );

            Feedback feedback = strength.getFeedback();

            String warning = "";
            List<String> suggestions = Collections.emptyList();

            if (feedback != null) {
                warning = feedback.getWarning();

                List<String> feedbackSuggestions =
                        feedback.getSuggestions();

                if (feedbackSuggestions != null) {
                    suggestions = feedbackSuggestions;
                }
            }

            return PasswordStrengthResult.fromEstimate(
                    strength.getScore(),
                    warning,
                    suggestions
            );
        } finally {
            Arrays.fill(workingCopy, '\0');
        }
    }
}

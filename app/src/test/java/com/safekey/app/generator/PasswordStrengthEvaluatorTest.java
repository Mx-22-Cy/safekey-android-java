package com.safekey.app.generator;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.nulabinc.zxcvbn.Zxcvbn;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public class PasswordStrengthEvaluatorTest {

    private final PasswordStrengthEvaluator evaluator =
            new PasswordStrengthEvaluator();

    @Test
    public void evaluate_nullAndEmptyInputsDoNotRunMeasurement() {
        PasswordStrengthEvaluator controlled =
                noMeasurementExpected();

        assertEmptyResult(controlled.evaluate(null));
        assertEmptyResult(controlled.evaluate(new char[0]));
    }

    @Test(expected = IllegalArgumentException.class)
    public void evaluate_rejectsOversizedInputBeforeMeasurement() {
        noMeasurementExpected().evaluate(new char[129]);
    }

    @Test
    public void evaluate_acceptsMaximumLengthAndRecognizesRepetition() {
        char[] password = new char[128];
        Arrays.fill(password, 'a');

        try {
            PasswordStrengthResult result = evaluator.evaluate(password);

            assertFalse(result.isEmpty());
            assertTrue(
                    "A long repeated character must still receive a low estimate.",
                    result.getScore() <= 1
            );
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    public void evaluate_recognizesCommonPasswordsAndPatterns() {
        String[] fixtures = {
                "password",
                "P@ssw0rd!",
                "qwertyuiop",
                "12345678901234567890",
                "aB3!aB3!aB3!aB3!",
                "z8!Q"
        };

        for (int index = 0; index < fixtures.length; index++) {
            PasswordStrengthResult result =
                    evaluateFixture(fixtures[index]);

            assertFalse(result.isEmpty());

            assertTrue(
                    "Weak fixture " + index + " received an excessive score.",
                    result.getScore() <= 1
            );

            assertFalse(result.getLabel().isEmpty());

            assertTrue(
                    "Weak input should provide helpful feedback.",
                    !result.getWarning().isEmpty()
                            || !result.getSuggestions().isEmpty()
            );
        }
    }

    @Test
    public void evaluate_givesHigherEstimatesToIrregularFixtures() {
        // Fixed fixtures keep these tests deterministic.
        String[] fixtures = {
                "vR8!nK2@xD7#pQ4$zL9%",
                "qmdvczkxtwprjnyhfbsa"
        };

        for (String fixture : fixtures) {
            PasswordStrengthResult result = evaluateFixture(fixture);

            assertFalse(result.isEmpty());

            assertTrue(
                    "An irregular long fixture should receive a higher estimate.",
                    result.getScore() >= 3 && result.getScore() <= 4
            );

            assertFalse(result.getLabel().isEmpty());
        }
    }

    @Test
    public void evaluate_preservesCallerArrayAndClearsCopyOnSuccess() {
        AtomicReference<CharSequence> captured =
                new AtomicReference<>();

        Zxcvbn realEstimator = new Zxcvbn();

        PasswordStrengthEvaluator controlled =
                new PasswordStrengthEvaluator(input -> {
                    captured.set(input);
                    return realEstimator.measure(input);
                });

        char[] password = "password".toCharArray();
        char[] snapshot = password.clone();

        try {
            PasswordStrengthResult result =
                    controlled.evaluate(password);

            assertArrayEquals(
                    "Evaluation must leave the caller's array unchanged.",
                    snapshot,
                    password
            );

            assertWorkingCopyCleared(captured.get(), password.length);

            // Feedback remains usable after the working copy is cleared.
            assertFalse(result.isEmpty());
            assertTrue(result.getScore() <= 1);
            assertFalse(result.getSuggestions().isEmpty());
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(snapshot, '\0');
        }
    }

    @Test
    public void evaluate_propagatesFailureAndClearsWorkingCopy() {
        AtomicReference<CharSequence> captured =
                new AtomicReference<>();

        IllegalStateException expectedFailure =
                new IllegalStateException("Deliberate test failure.");

        PasswordStrengthEvaluator controlled =
                new PasswordStrengthEvaluator(input -> {
                    captured.set(input);
                    throw expectedFailure;
                });

        char[] password = "sample-input".toCharArray();
        char[] snapshot = password.clone();

        try {
            try {
                controlled.evaluate(password);
                fail("A measurement failure must be propagated.");
            } catch (IllegalStateException actualFailure) {
                assertSame(expectedFailure, actualFailure);
            }

            assertArrayEquals(
                    "Failure must leave the caller's array unchanged.",
                    snapshot,
                    password
            );

            assertWorkingCopyCleared(captured.get(), password.length);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(snapshot, '\0');
        }
    }

    @Test
    public void result_suggestionsAreAnImmutableSnapshot() {
        List<String> sourceSuggestions = new ArrayList<>();
        sourceSuggestions.add("Use a longer password.");

        PasswordStrengthResult result =
                PasswordStrengthResult.fromEstimate(
                        1,
                        "Example warning.",
                        sourceSuggestions
                );

        sourceSuggestions.clear();

        assertEquals(1, result.getSuggestions().size());
        assertEquals(
                "Use a longer password.",
                result.getSuggestions().get(0)
        );

        try {
            result.getSuggestions().add("Unexpected change.");
            fail("Suggestions must be read-only.");
        } catch (UnsupportedOperationException expected) {
            // Correct: callers cannot modify result suggestions.
        }
    }

    private PasswordStrengthResult evaluateFixture(String fixture) {
        char[] password = fixture.toCharArray();

        try {
            return evaluator.evaluate(password);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static PasswordStrengthEvaluator noMeasurementExpected() {
        return new PasswordStrengthEvaluator(input -> {
            throw new AssertionError(
                    "Measurement must not run for empty or oversized input."
            );
        });
    }

    private static void assertEmptyResult(PasswordStrengthResult result) {
        assertTrue(result.isEmpty());
        assertEquals("", result.getLabel());
        assertEquals("", result.getWarning());
        assertTrue(result.getSuggestions().isEmpty());
    }

    private static void assertWorkingCopyCleared(
            CharSequence input,
            int expectedLength
    ) {
        assertNotNull("The test must capture the working copy.", input);
        assertEquals(expectedLength, input.length());

        for (int index = 0; index < input.length(); index++) {
            assertEquals(
                    "The working copy must be cleared after evaluation.",
                    '\0',
                    input.charAt(index)
            );
        }
    }
}

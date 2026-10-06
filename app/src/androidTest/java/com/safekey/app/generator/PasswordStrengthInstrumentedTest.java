package com.safekey.app.generator;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;

@RunWith(AndroidJUnit4.class)
public class PasswordStrengthInstrumentedTest {

    @Test
    public void bundledDictionaryAndFeedbackWorkOnAndroid() {
        char[] password = "password".toCharArray();

        try {
            PasswordStrengthEvaluator evaluator =
                    new PasswordStrengthEvaluator();

            PasswordStrengthResult result =
                    evaluator.evaluate(password);

            assertFalse(result.isEmpty());
            assertTrue(
                    "A common password should receive a low estimate.",
                    result.getScore() <= 1
            );
            assertFalse(result.getLabel().isEmpty());
            assertFalse(result.getWarning().isEmpty());
            assertFalse(result.getSuggestions().isEmpty());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    public void generatedPasswordCanBeEvaluatedOnAndroid() {
        PasswordGenerator generator = new PasswordGenerator();

        char[] password = generator.generate(
                PasswordGenerator.DEFAULT_LENGTH,
                true,
                true,
                true,
                true
        );
        char[] original = password.clone();

        try {
            PasswordStrengthEvaluator evaluator =
                    new PasswordStrengthEvaluator();

            PasswordStrengthResult result =
                    evaluator.evaluate(password);

            assertEquals(
                    PasswordGenerator.DEFAULT_LENGTH,
                    password.length
            );
            assertFalse(result.isEmpty());
            assertTrue(result.getScore() >= 0);
            assertTrue(result.getScore() <= 4);
            assertFalse(result.getLabel().isEmpty());
            assertArrayEquals(original, password);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(original, '\0');
        }
    }
}

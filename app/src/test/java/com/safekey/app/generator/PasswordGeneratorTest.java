package com.safekey.app.generator;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

public class PasswordGeneratorTest {

    private static final String LOWERCASE =
            "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS =
            "0123456789";
    private static final String SYMBOLS =
            "!@#$%^&*()-_=+[]{}:,.?";

    private final PasswordGenerator generator = new PasswordGenerator();

    @Test
    public void generate_rejectsLengthsBelowMinimum() {
        for (int length : new int[]{Integer.MIN_VALUE, -1, 0, 7}) {
            assertInvalidLength(length);
        }
    }

    @Test
    public void generate_rejectsLengthsAboveMaximum() {
        for (int length : new int[]{129, Integer.MAX_VALUE}) {
            assertInvalidLength(length);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void generate_rejectsNoSelectedTypes() {
        generator.generate(20, false, false, false, false);
    }

    @Test(expected = NullPointerException.class)
    public void constructor_rejectsNullRandom() {
        new PasswordGenerator(null);
    }

    @Test
    public void generate_honorsEveryCharacterTypeCombination() {
        int[] lengths = {8, 9, 20, 64, 128};

        // Four switches produce 15 nonempty combinations.
        for (int selection = 1; selection < 16; selection++) {
            boolean lowercase = (selection & 1) != 0;
            boolean uppercase = (selection & 2) != 0;
            boolean digits = (selection & 4) != 0;
            boolean symbols = (selection & 8) != 0;

            String allowed =
                    (lowercase ? LOWERCASE : "")
                            + (uppercase ? UPPERCASE : "")
                            + (digits ? DIGITS : "")
                            + (symbols ? SYMBOLS : "");

            for (int length : lengths) {
                for (int sample = 0; sample < 5; sample++) {
                    char[] password = generator.generate(
                            length,
                            lowercase,
                            uppercase,
                            digits,
                            symbols
                    );

                    try {
                        assertEquals(
                                "Incorrect output length.",
                                length,
                                password.length
                        );

                        for (char character : password) {
                            assertTrue(
                                    "Output contains an unselected character type.",
                                    allowed.indexOf(character) >= 0
                            );
                        }

                        if (lowercase) {
                            assertContainsType(password, LOWERCASE, "lowercase");
                        }
                        if (uppercase) {
                            assertContainsType(password, UPPERCASE, "uppercase");
                        }
                        if (digits) {
                            assertContainsType(password, DIGITS, "digits");
                        }
                        if (symbols) {
                            assertContainsType(password, SYMBOLS, "symbols");
                        }
                    } finally {
                        Arrays.fill(password, '\0');
                    }
                }
            }
        }
    }

    @Test
    public void generate_retriesWhenAnySelectedTypeIsMissing() {
        // Scripted values are only for this test.
        // Alphabet indexes: a=0, A=26, 0=52, !=62.
        ScriptedRandom random = new ScriptedRandom(
                // First candidate: missing lowercase.
                26, 52, 62, 26, 52, 62, 26, 52,

                // Second candidate: missing uppercase.
                0, 52, 62, 0, 52, 62, 0, 52,

                // Third candidate: missing digits.
                0, 26, 62, 0, 26, 62, 0, 26,

                // Fourth candidate: missing symbols.
                0, 26, 52, 0, 26, 52, 0, 26,

                // Fifth candidate: contains all four types.
                0, 26, 52, 62, 0, 26, 52, 62
        );

        PasswordGenerator controlledGenerator =
                new PasswordGenerator(random);

        char[] password = controlledGenerator.generate(
                8,
                true,
                true,
                true,
                true
        );

        try {
            assertEquals(
                    "All four incomplete candidates must be rejected.",
                    40,
                    random.calls
            );

            assertArrayEquals(
                    new char[]{'a', 'A', '0', '!', 'a', 'A', '0', '!'},
                    password
            );
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    public void generate_returnsIndependentArrays() {
        char[] first = generator.generate(
                20, true, false, false, false
        );
        char[] second = generator.generate(
                20, true, false, false, false
        );
        char[] secondSnapshot = second.clone();

        try {
            assertNotSame(
                    "Each call must return its own array.",
                    first,
                    second
            );

            Arrays.fill(first, '\0');

            assertArrayEquals(
                    "Clearing the first array must not change the second.",
                    secondSnapshot,
                    second
            );
        } finally {
            Arrays.fill(first, '\0');
            Arrays.fill(second, '\0');
            Arrays.fill(secondSnapshot, '\0');
        }
    }

    private void assertInvalidLength(int length) {
        try {
            generator.generate(length, true, true, true, true);
            fail("Expected rejection of length: " + length);
        } catch (IllegalArgumentException expected) {
            // Correct: invalid lengths must be rejected.
        }
    }

    private static void assertContainsType(
            char[] password,
            String characters,
            String typeName
    ) {
        for (char character : password) {
            if (characters.indexOf(character) >= 0) {
                return;
            }
        }

        fail("Output is missing the selected type: " + typeName);
    }

    private static final class ScriptedRandom extends SecureRandom {

        private static final long serialVersionUID = 1L;

        private final int[] values;
        private int calls;

        private ScriptedRandom(int... values) {
            this.values = values.clone();
        }

        @Override
        public int nextInt(int bound) {
            if (calls >= values.length) {
                throw new AssertionError(
                        "Generator requested more random values than expected."
                );
            }

            int value = values[calls++];

            assertTrue(
                    "Scripted value must be inside the requested bound.",
                    value >= 0 && value < bound
            );

            return value;
        }
    }
}

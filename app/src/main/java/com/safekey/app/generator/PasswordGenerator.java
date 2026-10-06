package com.safekey.app.generator;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class PasswordGenerator {

    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 128;
    public static final int DEFAULT_LENGTH = 20;

    private static final String LOWERCASE =
            "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS =
            "0123456789";
    private static final String SYMBOLS =
            "!@#$%^&*()-_=+[]{}:,.?";

    private final SecureRandom secureRandom;

    public PasswordGenerator() {
        this(new SecureRandom());
    }

    PasswordGenerator(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(
                secureRandom,
                "secureRandom"
        );
    }

    /**
     * Generates a credential password containing every selected character type.
     * The caller owns the returned array and should clear it when no longer needed.
     */
    public char[] generate(
            int length,
            boolean includeLowercase,
            boolean includeUppercase,
            boolean includeDigits,
            boolean includeSymbols
    ) {
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "Password length must be between "
                            + MIN_LENGTH + " and " + MAX_LENGTH + "."
            );
        }

        List<String> selectedTypes = new ArrayList<>(4);

        if (includeLowercase) {
            selectedTypes.add(LOWERCASE);
        }
        if (includeUppercase) {
            selectedTypes.add(UPPERCASE);
        }
        if (includeDigits) {
            selectedTypes.add(DIGITS);
        }
        if (includeSymbols) {
            selectedTypes.add(SYMBOLS);
        }

        if (selectedTypes.isEmpty()) {
            throw new IllegalArgumentException(
                    "Select at least one character type."
            );
        }

        StringBuilder alphabet = new StringBuilder();

        for (String type : selectedTypes) {
            alphabet.append(type);
        }

        char[] password = new char[length];

        do {
            // Choose every position from the entire selected alphabet.
            for (int index = 0; index < password.length; index++) {
                password[index] = alphabet.charAt(
                        secureRandom.nextInt(alphabet.length())
                );
            }

            // Retry if a required character type is missing.
        } while (!containsEverySelectedType(password, selectedTypes));

        return password;
    }

    private static boolean containsEverySelectedType(
            char[] password,
            List<String> selectedTypes
    ) {
        for (String type : selectedTypes) {
            boolean found = false;

            for (char character : password) {
                if (type.indexOf(character) >= 0) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                return false;
            }
        }

        return true;
    }
}

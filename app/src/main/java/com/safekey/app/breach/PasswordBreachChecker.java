package com.safekey.app.breach;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Local password hashing and Pwned Passwords range matching.
 * Blocking: run check() on a worker thread during integration.
 */
public final class PasswordBreachChecker {

    private static final int PREFIX_LENGTH = 5;
    private static final int SUFFIX_LENGTH = 35;
    private static final int MAX_RESPONSE_LENGTH = 1_048_576;
    private static final String HEX = "0123456789ABCDEF";

    private PasswordBreachChecker() {
        // Utility class.
    }

    /**
     * Leaves the caller's password array unchanged.
     * The caller owns that array and must clear it after use.
     * NOT_FOUND means no match in the returned dataset, not guaranteed safety.
     */
    public static PasswordBreachResult check(
            char[] password,
            BreachRangeClient rangeClient
    ) {
        if (password == null || password.length == 0) {
            return PasswordBreachResult.error(
                    PasswordBreachResult.ErrorReason.INVALID_INPUT
            );
        }

        Objects.requireNonNull(rangeClient, "rangeClient");
        char[] fullHash = null;

        try {
            fullHash = hashPassword(password);

            String prefix = new String(
                    fullHash,
                    0,
                    PREFIX_LENGTH
            );

            String response = rangeClient.fetchRange(prefix);

            return matchResponse(fullHash, response);

        } catch (CharacterCodingException exception) {
            return PasswordBreachResult.error(
                    PasswordBreachResult.ErrorReason.INVALID_INPUT
            );

        } catch (BreachRangeException exception) {
            return PasswordBreachResult.error(
                    exception.getErrorReason()
            );

        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "Required SHA-1 digest is unavailable.",
                    exception
            );

        } finally {
            if (fullHash != null) {
                Arrays.fill(fullHash, '\0');
            }
        }
    }

    private static char[] hashPassword(char[] password)
            throws CharacterCodingException, NoSuchAlgorithmException {

        char[] passwordCopy = password.clone();
        ByteBuffer encodedPassword = null;
        byte[] digest = null;

        try {
            encodedPassword = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(passwordCopy));

            // SHA-1 is the HIBP lookup format;
            // it is not used for vault storage.
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

            sha1.update(encodedPassword);
            digest = sha1.digest();

            char[] hash = new char[digest.length * 2];

            for (int index = 0; index < digest.length; index++) {
                int value = digest[index] & 0xFF;

                hash[index * 2] = HEX.charAt(value >>> 4);
                hash[index * 2 + 1] = HEX.charAt(value & 0x0F);
            }

            return hash;

        } finally {
            Arrays.fill(passwordCopy, '\0');

            if (encodedPassword != null && encodedPassword.hasArray()) {
                Arrays.fill(
                        encodedPassword.array(),
                        (byte) 0
                );
            }

            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }

    private static PasswordBreachResult matchResponse(
            char[] fullHash,
            String response
    ) {
        if (response == null
                || response.isEmpty()
                || response.length() > MAX_RESPONSE_LENGTH) {
            return invalidResponse();
        }

        long matchingCount = 0;
        boolean matchingSuffixSeen = false;
        int lineStart = 0;

        // Validate every row before reporting either a match or NOT_FOUND.
        while (lineStart < response.length()) {
            int newline = response.indexOf('\n', lineStart);

            int lineEnd = newline < 0
                    ? response.length()
                    : newline;

            if (newline >= 0
                    && lineEnd > lineStart
                    && response.charAt(lineEnd - 1) == '\r') {
                lineEnd--;
            }

            int countStart = lineStart + SUFFIX_LENGTH + 1;

            if (lineEnd <= countStart
                    || response.charAt(lineStart + SUFFIX_LENGTH) != ':') {
                return invalidResponse();
            }

            boolean matches = true;

            for (int index = 0; index < SUFFIX_LENGTH; index++) {
                char digit = response.charAt(lineStart + index);

                if (!isHexDigit(digit)) {
                    return invalidResponse();
                }

                if (Character.toUpperCase(digit)
                        != fullHash[PREFIX_LENGTH + index]) {
                    matches = false;
                }
            }

            long count = 0;

            for (int index = countStart; index < lineEnd; index++) {
                char digit = response.charAt(index);

                if (digit < '0' || digit > '9') {
                    return invalidResponse();
                }

                int value = digit - '0';

                if (count > (Long.MAX_VALUE - value) / 10) {
                    return invalidResponse();
                }

                count = count * 10 + value;
            }

            if (matches) {
                if (matchingSuffixSeen) {
                    return invalidResponse();
                }

                matchingSuffixSeen = true;
                matchingCount = count;
            }

            lineStart = newline < 0
                    ? response.length()
                    : newline + 1;
        }

        // Padding entries have count zero and are not breach matches.
        return matchingCount > 0
                ? PasswordBreachResult.breached(matchingCount)
                : PasswordBreachResult.notFound();
    }

    private static boolean isHexDigit(char value) {
        return (value >= '0' && value <= '9')
                || (value >= 'A' && value <= 'F')
                || (value >= 'a' && value <= 'f');
    }

    private static PasswordBreachResult invalidResponse() {
        return PasswordBreachResult.error(
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE
        );
    }
}

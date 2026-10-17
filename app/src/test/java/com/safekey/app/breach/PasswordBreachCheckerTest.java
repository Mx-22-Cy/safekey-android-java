package com.safekey.app.breach;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Arrays;
import java.util.Locale;

public class PasswordBreachCheckerTest {

    private static final String PASSWORD_SUFFIX =
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static final String OTHER_SUFFIX =
            "00000000000000000000000000000000000";

    @Test
    public void checkSendsOnlyPrefixAndPreservesCallerPassword() {
        char[] password = "password".toCharArray();
        char[] original = password.clone();
        int[] requests = {0};

        PasswordBreachResult result = PasswordBreachChecker.check(
                password,
                prefix -> {
                    requests[0]++;
                    assertEquals("5BAA6", prefix);
                    assertTrue(prefix.matches("[0-9A-F]{5}"));
                    return PASSWORD_SUFFIX + ":42\r\n";
                }
        );

        assertSuccess(result, PasswordBreachResult.Status.BREACHED, 42);
        assertEquals(1, requests[0]);
        assertArrayEquals(original, password);
    }

    @Test
    public void checkReturnsNotFoundForDifferentSuffix() {
        assertSuccess(
                checkResponse(OTHER_SUFFIX + ":23\r\n"),
                PasswordBreachResult.Status.NOT_FOUND,
                0
        );
    }

    @Test
    public void checkIgnoresZeroCountPadding() {
        assertSuccess(
                checkResponse(PASSWORD_SUFFIX + ":0\n" + OTHER_SUFFIX + ":23\n"),
                PasswordBreachResult.Status.NOT_FOUND,
                0
        );
    }

    @Test
    public void checkSupportsCommonLineEndings() {
        for (String ending : new String[]{"", "\n", "\r\n"}) {
            assertSuccess(
                    checkResponse(PASSWORD_SUFFIX + ":7" + ending),
                    PasswordBreachResult.Status.BREACHED,
                    7
            );
        }
    }

    @Test
    public void checkAcceptsLowercaseHexSuffix() {
        assertSuccess(
                checkResponse(PASSWORD_SUFFIX.toLowerCase(Locale.ROOT) + ":9\n"),
                PasswordBreachResult.Status.BREACHED,
                9
        );
    }

    @Test
    public void checkFindsMatchingRowAmongOtherRows() {
        String response = OTHER_SUFFIX + ":2\r\n"
                + PASSWORD_SUFFIX + ":19\r\n"
                + "11111111111111111111111111111111111:0\r\n";

        assertSuccess(
                checkResponse(response),
                PasswordBreachResult.Status.BREACHED,
                19
        );
    }

    @Test
    public void checkSupportsLargeOccurrenceCounts() {
        for (long count : new long[]{3_000_000_000L, Long.MAX_VALUE}) {
            assertSuccess(
                    checkResponse(PASSWORD_SUFFIX + ":" + count + "\n"),
                    PasswordBreachResult.Status.BREACHED,
                    count
            );
        }
    }

    @Test
    public void checkUsesUtf8ForUnicodePasswords() {
        assertVector(
                "p\u00E4ssw\u00F6rd\uD83D\uDD10 \u0645\u0631\u062D\u0628\u0627",
                "7B604",
                "EA2645AA02C955D1727A681716FBD7897E4"
        );
    }

    @Test
    public void checkPreservesPasswordWhitespace() {
        assertVector(
                " password ",
                "E6EE5",
                "DBAB4167ECE69097D192D7EE8B3B5AA5292"
        );

        assertVector(
                "   ",
                "088FB",
                "1A4AB057F4FCF7D487006499060C7FE5773"
        );
    }

    @Test
    public void checkDoesNotNormalizeUnicodePasswords() {
        assertVector(
                "\u00E9",
                "BF15B",
                "E717AC1B080B4F1C456692825891FF5073D"
        );

        assertVector(
                "e\u0301",
                "7E3FB",
                "CF1B6A69221CD8EEF7442EF3B51A253BB49"
        );
    }

    @Test
    public void checkPreservesPasswordCase() {
        assertVector(
                "Password",
                "8BE3C",
                "943B1609FFFBFC51AAD666D0A04ADF83C9D"
        );
    }

    @Test
    public void checkRejectsNullAndEmptyPasswordsWithoutRequests() {
        for (char[] password : new char[][]{null, new char[0]}) {
            assertInvalidInputWithoutRequest(password);
        }
    }

    @Test
    public void checkRejectsUnpairedSurrogatesWithoutRequests() {
        assertInvalidInputWithoutRequest(new char[]{'\uD800'});
        assertInvalidInputWithoutRequest(new char[]{'\uDC00'});
    }

    @Test
    public void checkRejectsInvalidResponses() {
        String[] invalidResponses = {
                null,
                "",
                "\n",
                " ",
                "<html>server error</html>",
                "short:1",
                "0000000000000000000000000000000000:1",
                "000000000000000000000000000000000000:1",
                "G0000000000000000000000000000000000:1",
                OTHER_SUFFIX + ";1",
                OTHER_SUFFIX + ":",
                OTHER_SUFFIX + ":-1",
                OTHER_SUFFIX + ":+1",
                OTHER_SUFFIX + ":1.5",
                OTHER_SUFFIX + ":1 2",
                OTHER_SUFFIX + ":a",
                OTHER_SUFFIX + ":\u0661",
                OTHER_SUFFIX + ":1:",
                OTHER_SUFFIX + ":9223372036854775808",
                OTHER_SUFFIX + ":1\r",
                OTHER_SUFFIX + ":1\n\n"
        };

        for (String response : invalidResponses) {
            assertError(
                    checkResponse(response),
                    PasswordBreachResult.ErrorReason.INVALID_RESPONSE
            );
        }
    }

    @Test
    public void checkValidatesEntireResponseBeforeReportingMatch() {
        assertError(
                checkResponse(PASSWORD_SUFFIX + ":1\nmalformed"),
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE
        );

        assertError(
                checkResponse("malformed\n" + PASSWORD_SUFFIX + ":1\n"),
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE
        );
    }

    @Test
    public void checkRejectsIncompleteResponseInsteadOfNotFound() {
        assertError(
                checkResponse(OTHER_SUFFIX + ":1\npartial"),
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE
        );
    }

    @Test
    public void checkRejectsDuplicateMatchingSuffix() {
        for (String firstCount : new String[]{"0", "1"}) {
            assertError(
                    checkResponse(PASSWORD_SUFFIX + ":" + firstCount + "\n"
                            + PASSWORD_SUFFIX + ":1\n"),
                    PasswordBreachResult.ErrorReason.INVALID_RESPONSE
            );
        }
    }

    @Test
    public void checkRejectsOversizedResponse() {
        char[] oversized = new char[1_048_577];
        Arrays.fill(oversized, 'X');

        assertError(
                checkResponse(new String(oversized)),
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE
        );
    }

    @Test
    public void checkPreservesConnectionFailureReasons() {
        PasswordBreachResult.ErrorReason[] reasons = {
                PasswordBreachResult.ErrorReason.OFFLINE,
                PasswordBreachResult.ErrorReason.TIMEOUT,
                PasswordBreachResult.ErrorReason.NETWORK_ERROR
        };

        for (PasswordBreachResult.ErrorReason reason : reasons) {
            char[] password = "password".toCharArray();
            char[] original = password.clone();

            PasswordBreachResult result = PasswordBreachChecker.check(
                    password,
                    prefix -> {
                        assertEquals("5BAA6", prefix);
                        throw new BreachRangeException(reason);
                    }
            );

            assertError(result, reason);
            assertArrayEquals(original, password);
        }
    }

    @Test(expected = NullPointerException.class)
    public void checkRequiresClientForValidPassword() {
        PasswordBreachChecker.check("password".toCharArray(), null);
    }

    @Test
    public void notCheckedResultIsNotASuccessfulCheck() {
        PasswordBreachResult result = PasswordBreachResult.notChecked();

        assertEquals(PasswordBreachResult.Status.NOT_CHECKED, result.getStatus());
        assertEquals(0L, result.getOccurrenceCount());
        assertEquals(PasswordBreachResult.ErrorReason.NONE, result.getErrorReason());
        assertFalse(result.isChecked());
    }

    @Test
    public void breachedResultRejectsNonPositiveCounts() {
        for (long count : new long[]{0, -1}) {
            try {
                PasswordBreachResult.breached(count);
                fail("A breached result must have a positive occurrence count.");
            } catch (IllegalArgumentException expected) {
                // Expected.
            }
        }
    }

    @Test
    public void errorResultRequiresAnErrorReason() {
        PasswordBreachResult.ErrorReason[] invalidReasons = {
                null,
                PasswordBreachResult.ErrorReason.NONE
        };

        for (PasswordBreachResult.ErrorReason reason : invalidReasons) {
            try {
                PasswordBreachResult.error(reason);
                fail("An error result must have an error reason.");
            } catch (IllegalArgumentException expected) {
                // Expected.
            }
        }
    }

    @Test
    public void rangeExceptionRejectsNonConnectionReasons() {
        PasswordBreachResult.ErrorReason[] invalidReasons = {
                null,
                PasswordBreachResult.ErrorReason.NONE,
                PasswordBreachResult.ErrorReason.INVALID_INPUT,
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE
        };

        for (PasswordBreachResult.ErrorReason reason : invalidReasons) {
            try {
                new BreachRangeException(reason);
                fail("A range exception must describe a connection failure.");
            } catch (IllegalArgumentException expected) {
                // Expected.
            }
        }
    }

    private static PasswordBreachResult checkResponse(String response) {
        return PasswordBreachChecker.check(
                "password".toCharArray(),
                prefix -> response
        );
    }

    private static void assertVector(
            String password,
            String expectedPrefix,
            String expectedSuffix
    ) {
        PasswordBreachResult result = PasswordBreachChecker.check(
                password.toCharArray(),
                prefix -> {
                    assertEquals(expectedPrefix, prefix);
                    return expectedSuffix + ":9\n";
                }
        );

        assertSuccess(result, PasswordBreachResult.Status.BREACHED, 9);
    }

    private static void assertInvalidInputWithoutRequest(char[] password) {
        int[] requests = {0};

        PasswordBreachResult result = PasswordBreachChecker.check(
                password,
                prefix -> {
                    requests[0]++;
                    return OTHER_SUFFIX + ":1\n";
                }
        );

        assertError(result, PasswordBreachResult.ErrorReason.INVALID_INPUT);
        assertEquals(0, requests[0]);
    }

    private static void assertSuccess(
            PasswordBreachResult result,
            PasswordBreachResult.Status status,
            long count
    ) {
        assertEquals(status, result.getStatus());
        assertEquals(count, result.getOccurrenceCount());
        assertEquals(PasswordBreachResult.ErrorReason.NONE, result.getErrorReason());
        assertTrue(result.isChecked());
    }

    private static void assertError(
            PasswordBreachResult result,
            PasswordBreachResult.ErrorReason reason
    ) {
        assertEquals(PasswordBreachResult.Status.ERROR, result.getStatus());
        assertEquals(0L, result.getOccurrenceCount());
        assertEquals(reason, result.getErrorReason());
        assertFalse(result.isChecked());
    }
}

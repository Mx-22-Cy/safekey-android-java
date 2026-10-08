package com.safekey.app.breach;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class PreparedPasswordBreachCheckTest {

    private static final String MATCH =
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\n";

    private static final String OTHER =
            "00000000000000000000000000000000000:1\n";

    @Test
    public void prepareExposesOnlyPrefixAndDoesNotRetainCallerArray() {
        char[] password = "password".toCharArray();
        char[] original = password.clone();

        try (PreparedPasswordBreachCheck check =
                     PasswordBreachChecker.prepare(password)) {
            assertEquals("5BAA6", check.getHashPrefix());
            assertArrayEquals(original, password);

            Arrays.fill(password, '\0');

            assertEquals(
                    PasswordBreachResult.Status.BREACHED,
                    check.complete(MATCH).getStatus()
            );
        }
    }

    @Test
    public void completionReturnsMatchAndClosesState() {
        PreparedPasswordBreachCheck check = prepare();
        PasswordBreachResult result = check.complete(MATCH);

        assertEquals(PasswordBreachResult.Status.BREACHED, result.getStatus());
        assertEquals(7L, result.getOccurrenceCount());
        assertTrue(check.isClosed());
    }

    @Test
    public void noMatchClosesState() {
        PreparedPasswordBreachCheck check = prepare();

        assertEquals(
                PasswordBreachResult.Status.NOT_FOUND,
                check.complete(OTHER).getStatus()
        );

        assertTrue(check.isClosed());
    }

    @Test
    public void invalidResponseClosesState() {
        PreparedPasswordBreachCheck check = prepare();
        PasswordBreachResult result = check.complete(MATCH + "partial");

        assertEquals(PasswordBreachResult.Status.ERROR, result.getStatus());
        assertEquals(
                PasswordBreachResult.ErrorReason.INVALID_RESPONSE,
                result.getErrorReason()
        );
        assertFalse(result.isChecked());
        assertTrue(check.isClosed());
    }

    @Test
    public void failurePreservesReasonAndClosesState() {
        PasswordBreachResult.ErrorReason[] reasons = {
                PasswordBreachResult.ErrorReason.OFFLINE,
                PasswordBreachResult.ErrorReason.TIMEOUT,
                PasswordBreachResult.ErrorReason.NETWORK_ERROR
        };

        for (PasswordBreachResult.ErrorReason reason : reasons) {
            PreparedPasswordBreachCheck check = prepare();
            PasswordBreachResult result = check.fail(reason);

            assertEquals(PasswordBreachResult.Status.ERROR, result.getStatus());
            assertEquals(reason, result.getErrorReason());
            assertFalse(result.isChecked());
            assertTrue(check.isClosed());
        }
    }

    @Test
    public void cancellationDiscardsLateSuccessAndFailure() {
        PreparedPasswordBreachCheck check = prepare();
        check.close();

        assertNotChecked(check.complete(MATCH));
        assertNotChecked(check.fail(PasswordBreachResult.ErrorReason.TIMEOUT));
        assertTrue(check.isClosed());
    }

    @Test
    public void completionIsOneShot() {
        PreparedPasswordBreachCheck check = prepare();

        assertEquals(
                PasswordBreachResult.Status.BREACHED,
                check.complete(MATCH).getStatus()
        );

        assertNotChecked(check.complete(OTHER));
        assertNotChecked(
                check.fail(PasswordBreachResult.ErrorReason.NETWORK_ERROR)
        );
    }

    @Test
    public void closeIsIdempotent() {
        PreparedPasswordBreachCheck check = prepare();

        check.close();
        check.close();

        assertTrue(check.isClosed());
        assertNotChecked(check.complete(MATCH));
    }

    @Test
    public void prepareSupportsUtf8() {
        char[] password = "\u00E9".toCharArray();

        try (PreparedPasswordBreachCheck check =
                     PasswordBreachChecker.prepare(password)) {
            assertEquals("BF15B", check.getHashPrefix());

            assertEquals(
                    PasswordBreachResult.Status.BREACHED,
                    check.complete(
                            "E717AC1B080B4F1C456692825891FF5073D:1\n"
                    ).getStatus()
            );
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void prepareRejectsNullPassword() {
        PasswordBreachChecker.prepare(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void prepareRejectsEmptyPassword() {
        PasswordBreachChecker.prepare(new char[0]);
    }

    @Test
    public void prepareRejectsInvalidUnicode() {
        for (char value : new char[]{'\uD800', '\uDC00'}) {
            try (PreparedPasswordBreachCheck check =
                         PasswordBreachChecker.prepare(new char[]{value})) {
                fail(
                        "Invalid Unicode was accepted as prefix "
                                + check.getHashPrefix()
                );
            } catch (IllegalArgumentException expected) {
                // Expected.
            }
        }
    }

    @Test
    public void invalidFailureReasonStillClosesState() {
        PreparedPasswordBreachCheck check = prepare();

        try {
            check.fail(PasswordBreachResult.ErrorReason.NONE);
            fail("An error reason is required.");
        } catch (IllegalArgumentException expected) {
            assertTrue(check.isClosed());
        }
    }

    @Test
    public void cancellationAndCompletionDoNotProduceFalseNotFound()
            throws Exception {

        ExecutorService workers = Executors.newFixedThreadPool(2);

        try {
            for (int iteration = 0; iteration < 25; iteration++) {
                PreparedPasswordBreachCheck check = prepare();
                CountDownLatch start = new CountDownLatch(1);

                Future<PasswordBreachResult> completion =
                        workers.submit(() -> {
                            start.await();
                            return check.complete(MATCH);
                        });

                Future<?> cancellation = workers.submit(() -> {
                    start.await();
                    check.close();
                    return null;
                });

                start.countDown();

                PasswordBreachResult result =
                        completion.get(5, TimeUnit.SECONDS);

                cancellation.get(5, TimeUnit.SECONDS);

                assertTrue(
                        result.getStatus()
                                == PasswordBreachResult.Status.BREACHED
                                || result.getStatus()
                                == PasswordBreachResult.Status.NOT_CHECKED
                );

                assertTrue(check.isClosed());
            }
        } finally {
            workers.shutdownNow();
        }
    }

    private static PreparedPasswordBreachCheck prepare() {
        return PasswordBreachChecker.prepare("password".toCharArray());
    }

    private static void assertNotChecked(PasswordBreachResult result) {
        assertEquals(PasswordBreachResult.Status.NOT_CHECKED, result.getStatus());
        assertEquals(0L, result.getOccurrenceCount());
        assertEquals(PasswordBreachResult.ErrorReason.NONE, result.getErrorReason());
        assertFalse(result.isChecked());
    }
}

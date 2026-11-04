package com.safekey.app.autofill;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.view.View;
import android.view.autofill.AutofillId;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.safekey.app.session.SafeKeySession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class AutofillRequestTrackerInstrumentedTest {

    /**
     * Start each test with an authenticated test session.
     *
     * This does not open or decrypt the actual SafeKey vault.
     * It only prepares the shared session manager for testing.
     */
    @Before
    public void setUp() {
        SafeKeySession.lock();
        SafeKeySession.unlockAfterAuthentication();
    }

    /**
     * Lock the test session after every test.
     */
    @After
    public void tearDown() {
        SafeKeySession.lock();
    }

    /**
     * Creates an Android Autofill field identifier for testing.
     */
    private static AutofillId newAutofillId() {
        return new View(
                ApplicationProvider.getApplicationContext()
        ).getAutofillId();
    }

    /**
     * Creates request metadata for the security tests.
     */
    private static AutofillRequestMetadata metadata(
            String packageName,
            String website,
            AutofillId usernameId,
            AutofillId passwordId
    ) {
        AutofillLoginFields.Fields fields =
                AutofillLoginFields.Fields.forTesting(
                        usernameId,
                        passwordId
                );

        return AutofillRequestMetadata.forTesting(
                packageName,
                website,
                fields
        );
    }

    // ---------------------------------------------------------
    // TEST 1 — Reject null metadata
    // ---------------------------------------------------------

    @Test
    public void registrationRejectsNullMetadata() {
        assertNull(
                AutofillRequestTracker.register(null)
        );
    }

    // ---------------------------------------------------------
    // TEST 2 — Reject missing token
    // ---------------------------------------------------------

    @Test
    public void missingTokenIsRejected() {
        assertFalse(
                AutofillRequestTracker.consume(null, null)
        );
    }

    // ---------------------------------------------------------
    // TEST 3 — Reject fabricated token
    // ---------------------------------------------------------

    @Test
    public void fabricatedTokenIsRejected() {
        assertFalse(
                AutofillRequestTracker.consume(
                        "invalid-autofill-token",
                        null
                )
        );
    }

    // ---------------------------------------------------------
    // TEST 4 — Reject empty token
    // ---------------------------------------------------------

    @Test
    public void emptyTokenIsRejected() {
        assertFalse(
                AutofillRequestTracker.consume("", null)
        );
    }

    // ---------------------------------------------------------
    // TEST 5 — Valid token can be consumed only once
    // ---------------------------------------------------------

    @Test
    public void validTokenCanBeConsumedOnlyOnce() {

        AutofillRequestMetadata request = metadata(
                "com.example.login",
                "example.com",
                newAutofillId(),
                newAutofillId()
        );

        String token =
                AutofillRequestTracker.register(request);

        assertNotNull(token);

        // The first attempt must succeed.
        assertTrue(
                AutofillRequestTracker.consume(token, request)
        );

        // Reusing the same token must fail.
        assertFalse(
                AutofillRequestTracker.consume(token, request)
        );
    }

    // ---------------------------------------------------------
    // TEST 6 — Cancelled tokens cannot be consumed
    // ---------------------------------------------------------

    @Test
    public void cancelledTokenCannotBeConsumed() {

        AutofillRequestMetadata request = metadata(
                "com.example.login",
                "example.com",
                newAutofillId(),
                newAutofillId()
        );

        String token =
                AutofillRequestTracker.register(request);

        assertNotNull(token);

        AutofillRequestTracker.cancel(token);

        assertFalse(
                AutofillRequestTracker.consume(token, request)
        );
    }

    // ---------------------------------------------------------
    // TEST 7 — Reject different application package
    // ---------------------------------------------------------

    @Test
    public void differentPackageIsRejected() {

        AutofillId usernameId = newAutofillId();
        AutofillId passwordId = newAutofillId();

        AutofillRequestMetadata original = metadata(
                "com.example.login",
                "example.com",
                usernameId,
                passwordId
        );

        AutofillRequestMetadata changed = metadata(
                "com.example.attacker",
                "example.com",
                usernameId,
                passwordId
        );

        String token =
                AutofillRequestTracker.register(original);

        assertNotNull(token);

        assertFalse(
                AutofillRequestTracker.consume(token, changed)
        );

        // Failed validation must also consume the token.
        assertFalse(
                AutofillRequestTracker.consume(token, original)
        );
    }

    // ---------------------------------------------------------
    // TEST 8 — Reject different website
    // ---------------------------------------------------------

    @Test
    public void differentWebsiteIsRejected() {

        AutofillId usernameId = newAutofillId();
        AutofillId passwordId = newAutofillId();

        AutofillRequestMetadata original = metadata(
                "com.example.login",
                "example.com",
                usernameId,
                passwordId
        );

        AutofillRequestMetadata changed = metadata(
                "com.example.login",
                "attacker.example",
                usernameId,
                passwordId
        );

        String token =
                AutofillRequestTracker.register(original);

        assertNotNull(token);

        assertFalse(
                AutofillRequestTracker.consume(token, changed)
        );

        assertFalse(
                AutofillRequestTracker.consume(token, original)
        );
    }

    // ---------------------------------------------------------
    // TEST 9 — Reject different username field
    // ---------------------------------------------------------

    @Test
    public void differentUsernameFieldIsRejected() {

        AutofillId originalUsername = newAutofillId();
        AutofillId passwordId = newAutofillId();

        AutofillRequestMetadata original = metadata(
                "com.example.login",
                "example.com",
                originalUsername,
                passwordId
        );

        AutofillRequestMetadata changed = metadata(
                "com.example.login",
                "example.com",
                newAutofillId(),
                passwordId
        );

        String token =
                AutofillRequestTracker.register(original);

        assertNotNull(token);

        assertFalse(
                AutofillRequestTracker.consume(token, changed)
        );
    }

    // ---------------------------------------------------------
    // TEST 10 — Reject different password field
    // ---------------------------------------------------------

    @Test
    public void differentPasswordFieldIsRejected() {

        AutofillId usernameId = newAutofillId();
        AutofillId originalPassword = newAutofillId();

        AutofillRequestMetadata original = metadata(
                "com.example.login",
                "example.com",
                usernameId,
                originalPassword
        );

        AutofillRequestMetadata changed = metadata(
                "com.example.login",
                "example.com",
                usernameId,
                newAutofillId()
        );

        String token =
                AutofillRequestTracker.register(original);

        assertNotNull(token);

        assertFalse(
                AutofillRequestTracker.consume(token, changed)
        );
    }

    // ---------------------------------------------------------
    // TEST 11 — Locked vault rejects new requests
    // ---------------------------------------------------------

    @Test
    public void lockedVaultRejectsNewRequests() {

        // Lock the session before attempting registration.
        SafeKeySession.lock();

        AutofillRequestMetadata request = metadata(
                "com.example.login",
                "example.com",
                newAutofillId(),
                newAutofillId()
        );

        // Registration must fail while the session is locked.
        assertNull(
                AutofillRequestTracker.register(request)
        );
    }

    // ---------------------------------------------------------
    // TEST 12 — Old token rejected after reauthentication
    // ---------------------------------------------------------

    @Test
    public void oldTokenRejectedAfterReauthentication() {

        AutofillRequestMetadata request = metadata(
                "com.example.login",
                "example.com",
                newAutofillId(),
                newAutofillId()
        );

        // Register during the current authenticated session.
        String token =
                AutofillRequestTracker.register(request);

        assertNotNull(token);

        // Simulate locking and authenticating again.
        SafeKeySession.lock();
        SafeKeySession.unlockAfterAuthentication();

        // The original token must no longer be valid.
        assertFalse(
                AutofillRequestTracker.consume(token, request)
        );
    }
}

package com.safekey.app.autofill;

import static org.junit.Assert.assertEquals;
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
public class AutofillOriginSecurityInstrumentedTest {

    @Before
    public void setUp() {
        SafeKeySession.lock();
        SafeKeySession.unlockAfterAuthentication();
    }

    @After
    public void tearDown() {
        SafeKeySession.lock();
    }

    private static AutofillId newId() {
        return new View(
                ApplicationProvider.getApplicationContext()
        ).getAutofillId();
    }

    private static AutofillRequestMetadata metadata(
            String scheme,
            String host,
            AutofillId usernameId,
            AutofillId passwordId
    ) {
        return AutofillRequestMetadata.forTesting(
                "com.example.login",
                scheme,
                host,
                AutofillLoginFields.Fields.forTesting(
                        usernameId,
                        passwordId
                )
        );
    }

    @Test
    public void httpsOriginIsCanonicalized() {
        assertEquals(
                "https://example.com",
                AutofillRequestMetadata.canonicalHttpsOrigin(
                        "HTTPS",
                        "EXAMPLE.COM"
                )
        );
    }

    @Test
    public void httpAndUnsupportedSchemesAreRejected() {
        assertNull(
                AutofillRequestMetadata.canonicalHttpsOrigin(
                        "http",
                        "example.com"
                )
        );

        assertNull(
                AutofillRequestMetadata.canonicalHttpsOrigin(
                        "ftp",
                        "example.com"
                )
        );

        assertNull(
                AutofillRequestMetadata.canonicalHttpsOrigin(
                        "file",
                        "example.com"
                )
        );
    }

    @Test
    public void missingSchemeOrHostIsRejected() {
        assertNull(
                AutofillRequestMetadata.canonicalHttpsOrigin(
                        null,
                        "example.com"
                )
        );

        assertNull(
                AutofillRequestMetadata.canonicalHttpsOrigin(
                        "",
                        "example.com"
                )
        );

        assertNull(
                AutofillRequestMetadata.canonicalHttpsOrigin(
                        "https",
                        null
                )
        );
    }

    @Test
    public void httpRequestCannotRegister() {
        AutofillRequestMetadata request = metadata(
                "http",
                "example.com",
                newId(),
                newId()
        );

        assertNull(
                AutofillRequestTracker.register(request)
        );
    }

    @Test
    public void missingSchemeCannotRegister() {
        AutofillRequestMetadata request = metadata(
                null,
                "example.com",
                newId(),
                newId()
        );

        assertNull(
                AutofillRequestTracker.register(request)
        );
    }

    @Test
    public void httpCannotConsumeHttpsRequestToken() {
        AutofillId username = newId();
        AutofillId password = newId();

        AutofillRequestMetadata secure = metadata(
                "https",
                "example.com",
                username,
                password
        );

        AutofillRequestMetadata insecure = metadata(
                "http",
                "example.com",
                username,
                password
        );

        String token = AutofillRequestTracker.register(secure);
        assertNotNull(token);

        assertFalse(
                AutofillRequestTracker.consume(token, insecure)
        );

        // An unsuccessful validation still consumes the token.
        assertFalse(
                AutofillRequestTracker.consume(token, secure)
        );
    }

    @Test
    public void differentHttpsHostCannotConsumeToken() {
        AutofillId username = newId();
        AutofillId password = newId();

        AutofillRequestMetadata original = metadata(
                "https",
                "example.com",
                username,
                password
        );

        AutofillRequestMetadata changed = metadata(
                "https",
                "attacker.example",
                username,
                password
        );

        String token = AutofillRequestTracker.register(original);
        assertNotNull(token);

        assertFalse(
                AutofillRequestTracker.consume(token, changed)
        );
    }

    @Test
    public void sameHttpsOriginCanConsumeTokenOnlyOnce() {
        AutofillId username = newId();
        AutofillId password = newId();

        AutofillRequestMetadata original = metadata(
                "https",
                "example.com",
                username,
                password
        );

        AutofillRequestMetadata equivalent = metadata(
                "HTTPS",
                "EXAMPLE.COM",
                username,
                password
        );

        String token = AutofillRequestTracker.register(original);
        assertNotNull(token);

        assertTrue(
                AutofillRequestTracker.consume(token, equivalent)
        );

        assertFalse(
                AutofillRequestTracker.consume(token, equivalent)
        );
    }
}

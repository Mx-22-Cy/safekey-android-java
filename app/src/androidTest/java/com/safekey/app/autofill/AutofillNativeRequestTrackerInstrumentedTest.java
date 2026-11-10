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
public class AutofillNativeRequestTrackerInstrumentedTest {

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

    private static AutofillLoginFields.Fields fields(
            AutofillId username,
            AutofillId password
    ) {
        return AutofillLoginFields.Fields.forTesting(
                username,
                password
        );
    }

    private static AutofillRequestMetadata nativeRequest(
            String packageName,
            AutofillId username,
            AutofillId password
    ) {
        return AutofillRequestMetadata.forTestingNative(
                packageName,
                fields(username, password)
        );
    }

    private static AutofillRequestMetadata websiteRequest(
            String packageName,
            AutofillId username,
            AutofillId password
    ) {
        return AutofillRequestMetadata.forTesting(
                packageName,
                "https",
                "example.com",
                fields(username, password)
        );
    }

    @Test
    public void validNativeTokenCanBeConsumedOnce() {
        AutofillRequestMetadata request = nativeRequest(
                "com.example.login",
                newId(),
                newId()
        );

        String token = AutofillRequestTracker.register(request);

        assertNotNull(token);
        assertTrue(AutofillRequestTracker.consume(token, request));
        assertFalse(AutofillRequestTracker.consume(token, request));
    }

    @Test
    public void differentNativePackageIsRejected() {
        AutofillId username = newId();
        AutofillId password = newId();

        AutofillRequestMetadata original = nativeRequest(
                "com.example.login",
                username,
                password
        );

        AutofillRequestMetadata changed = nativeRequest(
                "com.example.attacker",
                username,
                password
        );

        String token = AutofillRequestTracker.register(original);

        assertNotNull(token);
        assertFalse(AutofillRequestTracker.consume(token, changed));
        assertFalse(AutofillRequestTracker.consume(token, original));
    }

    @Test
    public void nativeTokenCannotBecomeWebsiteToken() {
        AutofillId username = newId();
        AutofillId password = newId();

        AutofillRequestMetadata nativeMetadata = nativeRequest(
                "com.example.login",
                username,
                password
        );

        AutofillRequestMetadata webMetadata = websiteRequest(
                "com.example.login",
                username,
                password
        );

        String token = AutofillRequestTracker.register(nativeMetadata);

        assertNotNull(token);
        assertFalse(AutofillRequestTracker.consume(token, webMetadata));
        assertFalse(AutofillRequestTracker.consume(token, nativeMetadata));
    }

    @Test
    public void websiteTokenCannotBecomeNativeToken() {
        AutofillId username = newId();
        AutofillId password = newId();

        AutofillRequestMetadata webMetadata = websiteRequest(
                "com.example.login",
                username,
                password
        );

        AutofillRequestMetadata nativeMetadata = nativeRequest(
                "com.example.login",
                username,
                password
        );

        String token = AutofillRequestTracker.register(webMetadata);

        assertNotNull(token);
        assertFalse(AutofillRequestTracker.consume(token, nativeMetadata));
        assertFalse(AutofillRequestTracker.consume(token, webMetadata));
    }

    @Test
    public void changedNativeFieldIsRejected() {
        AutofillId username = newId();
        AutofillId password = newId();

        AutofillRequestMetadata original = nativeRequest(
                "com.example.login",
                username,
                password
        );

        AutofillRequestMetadata changed = nativeRequest(
                "com.example.login",
                username,
                newId()
        );

        String token = AutofillRequestTracker.register(original);

        assertNotNull(token);
        assertFalse(AutofillRequestTracker.consume(token, changed));
    }

    @Test
    public void lockedSessionRejectsNativeRegistration() {
        SafeKeySession.lock();

        AutofillRequestMetadata request = nativeRequest(
                "com.example.login",
                newId(),
                newId()
        );

        assertNull(AutofillRequestTracker.register(request));
    }

    @Test
    public void missingPackageRejectsNativeRegistration() {
        AutofillRequestMetadata request = nativeRequest(
                null,
                newId(),
                newId()
        );

        assertNull(AutofillRequestTracker.register(request));
    }

    @Test
    public void nativeTokenExpiresAfterReauthentication() {
        AutofillRequestMetadata request = nativeRequest(
                "com.example.login",
                newId(),
                newId()
        );

        String token = AutofillRequestTracker.register(request);

        assertNotNull(token);

        SafeKeySession.lock();
        SafeKeySession.unlockAfterAuthentication();

        assertFalse(AutofillRequestTracker.consume(token, request));
    }
}

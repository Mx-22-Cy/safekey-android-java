package com.safekey.app.autofill;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class AutofillWebsiteMatcherInstrumentedTest {

    @Test
    public void exactHttpsWebsiteMatches() {
        assertTrue(
                AutofillWebsiteMatcher.matches(
                        "https://example.com/login",
                        "example.com"
                )
        );
    }

    @Test
    public void websiteWithoutSchemeMatches() {
        assertTrue(
                AutofillWebsiteMatcher.matches(
                        "example.com",
                        "example.com"
                )
        );
    }

    @Test
    public void differentWebsiteIsRejected() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        "https://example.com",
                        "attacker.com"
                )
        );
    }

    @Test
    public void insecureHttpWebsiteIsRejected() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        "http://example.com",
                        "example.com"
                )
        );
    }

    @Test
    public void subdomainIsNotAutomaticallyTrusted() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        "https://login.example.com",
                        "example.com"
                )
        );
    }

    @Test
    public void phishingLookalikeIsRejected() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        "https://example.com.attacker.com",
                        "example.com"
                )
        );
    }

    @Test
    public void differentPortIsRejected() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        "https://example.com:8080",
                        "example.com"
                )
        );
    }

    @Test
    public void standardHttpsPortIsAccepted() {
        assertTrue(
                AutofillWebsiteMatcher.matches(
                        "https://example.com:443/login",
                        "example.com"
                )
        );
    }

    @Test
    public void uppercaseHostnameMatches() {
        assertTrue(
                AutofillWebsiteMatcher.matches(
                        "https://EXAMPLE.COM",
                        "example.com"
                )
        );
    }

    @Test
    public void missingWebsiteIsRejected() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        null,
                        "example.com"
                )
        );
    }

    @Test
    public void invalidHostnameIsRejected() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        "https://example.com",
                        "invalid host"
                )
        );
    }

    @Test
    public void embeddedUsernameIsRejected() {
        assertFalse(
                AutofillWebsiteMatcher.matches(
                        "https://user@example.com",
                        "example.com"
                )
        );
    }
}

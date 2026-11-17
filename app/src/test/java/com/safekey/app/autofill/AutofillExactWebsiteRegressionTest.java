package com.safekey.app.autofill;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Keep website matching strict while improving browser diagnostics. */
public final class AutofillExactWebsiteRegressionTest {

    @Test public void googleExactHttpsHostMatches() {
        assertTrue(AutofillWebsiteMatcher.matches(
                "https://accounts.google.com", "accounts.google.com"));
    }

    @Test public void w3SchoolsExactHttpsHostMatches() {
        assertTrue(AutofillWebsiteMatcher.matches(
                "https://app.w3schools.com", "app.w3schools.com"));
    }

    @Test public void differentSubdomainIsNotAutomaticMatch() {
        assertFalse(AutofillWebsiteMatcher.matches(
                "https://app.w3schools.com", "profile.w3schools.com"));
    }

    @Test public void phishingLookalikeIsRejected() {
        assertFalse(AutofillWebsiteMatcher.matches(
                "https://accounts.google.com", "accounts.google.com.evil.example"));
    }

    @Test public void httpStoredCredentialCannotMatch() {
        assertFalse(AutofillWebsiteMatcher.matches(
                "http://app.w3schools.com", "app.w3schools.com"));
    }
}

package com.safekey.app.autofill;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.safekey.app.data.model.Credential;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@RunWith(AndroidJUnit4.class)
public class AutofillCredentialMatcherInstrumentedTest {

    private Credential credential(
            String username,
            String password,
            String website
    ) {
        return new Credential(
                "Test Credential",
                username,
                password,
                website,
                "Login",
                ""
        );
    }

    @Test
    public void exactWebsiteReturnsCredential() {

        Credential saved = credential(
                "student@example.com",
                "dummy-password-123",
                "https://example.com/login"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertEquals(1, matches.size());
        assertEquals(saved, matches.get(0));
    }

    @Test
    public void differentWebsiteReturnsNoCredentials() {

        Credential saved = credential(
                "student@example.com",
                "dummy-password-123",
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "attacker.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void phishingWebsiteIsRejected() {

        Credential saved = credential(
                "student@example.com",
                "dummy-password-123",
                "https://example.com.attacker.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void missingUsernameIsRejected() {

        Credential saved = credential(
                null,
                "dummy-password-123",
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void emptyUsernameIsRejected() {

        Credential saved = credential(
                "   ",
                "dummy-password-123",
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void missingPasswordIsRejected() {

        Credential saved = credential(
                "student@example.com",
                null,
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void emptyPasswordIsRejected() {

        Credential saved = credential(
                "student@example.com",
                "",
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void insecureHttpWebsiteIsRejected() {

        Credential saved = credential(
                "student@example.com",
                "dummy-password-123",
                "http://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void onlyMatchingCredentialsAreReturned() {

        Credential first = credential(
                "first@example.com",
                "dummy-password-111",
                "https://example.com"
        );

        Credential second = credential(
                "second@other.com",
                "dummy-password-222",
                "https://other.com"
        );

        Credential third = credential(
                "third@example.com",
                "dummy-password-333",
                "https://example.com/login"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Arrays.asList(first, second, third),
                        "example.com"
                );

        assertEquals(2, matches.size());
        assertEquals(first, matches.get(0));
        assertEquals(third, matches.get(1));
    }

    @Test
    public void emptyCredentialListReturnsNoMatches() {

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.emptyList(),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void nullCredentialListReturnsNoMatches() {

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        null,
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void invalidVerifiedHostReturnsNoMatches() {

        Credential saved = credential(
                "student@example.com",
                "dummy-password-123",
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "invalid host"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void nullCredentialEntriesAreIgnored() {

        Credential valid = credential(
                "student@example.com",
                "dummy-password-123",
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Arrays.asList(null, valid),
                        "example.com"
                );

        assertEquals(1, matches.size());
        assertEquals(valid, matches.get(0));
    }

    @Test
    public void subdomainDoesNotAutomaticallyMatch() {

        Credential saved = credential(
                "student@example.com",
                "dummy-password-123",
                "https://login.example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        assertTrue(matches.isEmpty());
    }

    @Test
    public void matchingResultsCannotBeModified() {

        Credential saved = credential(
                "student@example.com",
                "dummy-password-123",
                "https://example.com"
        );

        List<Credential> matches =
                AutofillCredentialMatcher.findMatches(
                        Collections.singletonList(saved),
                        "example.com"
                );

        boolean modificationRejected = false;

        try {
            matches.clear();
        } catch (UnsupportedOperationException exception) {
            modificationRejected = true;
        }

        assertTrue(modificationRejected);
        assertFalse(matches.isEmpty());
    }
}

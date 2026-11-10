package com.safekey.app.autofill;

import com.safekey.app.data.model.Credential;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Filters vault credentials for an already verified website.
 *
 * SECURITY:
 * This class does not authenticate a requesting application.
 * The caller must verify the request identity and active vault
 * session before obtaining or passing credentials here.
 *
 * Never log credentials or cache matching results.
 */
public final class AutofillCredentialMatcher {

    private AutofillCredentialMatcher() {
    }

    public static List<Credential> findMatches(
            List<Credential> credentials,
            String verifiedHost
    ) {
        if (credentials == null || credentials.isEmpty()) {
            return Collections.emptyList();
        }

        String normalizedHost =
                AutofillWebsiteMatcher.normalizeHost(verifiedHost);

        if (normalizedHost == null) {
            return Collections.emptyList();
        }

        List<Credential> matches = new ArrayList<>();

        for (Credential credential : credentials) {
            if (credential == null) {
                continue;
            }

            String username = credential.getUsername();
            String password = credential.getPassword();
            String website = credential.getWebsite();

            if (username == null || username.trim().isEmpty()) {
                continue;
            }

            if (password == null || password.isEmpty()) {
                continue;
            }

            if (!AutofillWebsiteMatcher.matches(
                    website,
                    normalizedHost
            )) {
                continue;
            }

            matches.add(credential);
        }

        return Collections.unmodifiableList(matches);
    }
}
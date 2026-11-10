package com.safekey.app.autofill;

import java.net.IDN;
import java.net.URI;
import java.util.Locale;

/**
 * Conservative website matcher for SafeKey Autofill.
 *
 * IMPORTANT:
 * This class only compares domains.
 * It does not establish that the requesting app or
 * website is trusted. The caller must verify that
 * identity separately before using this matcher.
 */
public final class AutofillWebsiteMatcher {

    private AutofillWebsiteMatcher() {
    }

    public static boolean matches(
            String savedWebsite,
            String verifiedHost
    ) {
        String savedHost = hostFromSavedWebsite(savedWebsite);
        String requestingHost = normalizeHost(verifiedHost);

        return savedHost != null
                && requestingHost != null
                && savedHost.equals(requestingHost);
    }

    static String hostFromSavedWebsite(String website) {
        if (website == null) {
            return null;
        }

        String input = website.trim();

        if (input.isEmpty()) {
            return null;
        }

        if (!input.contains("://")) {
            input = "https://" + input;
        }

        try {
            URI uri = new URI(input);

            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                return null;
            }

            if (uri.getRawUserInfo() != null) {
                return null;
            }

            int port = uri.getPort();

            if (port != -1 && port != 443) {
                return null;
            }

            return normalizeHost(uri.getHost());

        } catch (Exception exception) {
            return null;
        }
    }

    static String normalizeHost(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }

        if (!host.equals(host.trim())) {
            return null;
        }

        try {
            String ascii = IDN.toASCII(
                    host,
                    IDN.USE_STD3_ASCII_RULES
            ).toLowerCase(Locale.ROOT);

            if (ascii.length() > 253
                    || !ascii.contains(".")
                    || ascii.startsWith(".")
                    || ascii.endsWith(".")
                    || ascii.contains("..")) {
                return null;
            }

            String[] labels = ascii.split("\\.");

            for (String label : labels) {
                if (label.isEmpty()
                        || label.length() > 63
                        || !label.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) {
                    return null;
                }
            }

            String lastLabel = labels[labels.length - 1];

            if (lastLabel.length() < 2
                    || lastLabel.matches("[0-9]+")) {
                return null;
            }

            return ascii;

        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
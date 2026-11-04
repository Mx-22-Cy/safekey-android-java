package com.safekey.app.autofill;

import android.os.SystemClock;
import android.view.autofill.AutofillId;

import com.safekey.app.session.SafeKeySession;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Tracks pending Android Autofill authentication requests.
 *
 * Security protections:
 * - Cryptographically random request tokens.
 * - One-time token consumption.
 * - Request expiration.
 * - Application and website matching.
 * - Username and password field matching.
 * - Authentication-session binding.
 *
 * No usernames or passwords are stored here.
 */
public final class AutofillRequestTracker {

    private static final long REQUEST_TIMEOUT_MS = 60_000L;

    private static final int MAX_REQUESTS = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Map<String, RequestRecord> REQUESTS =
            new HashMap<>();

    private AutofillRequestTracker() {
        // Utility class.
    }

    /**
     * Registers a new Autofill request.
     *
     * Returns null if the request is invalid, the vault is locked,
     * or the request limit has been reached.
     */
    public static synchronized String register(
            AutofillRequestMetadata metadata
    ) {
        if (metadata == null || metadata.getFields() == null) {
            return null;
        }

        AutofillId usernameId =
                metadata.getFields().getUsernameId();

        AutofillId passwordId =
                metadata.getFields().getPasswordId();

        String packageName = metadata.getPackageName();
        String website = metadata.getClaimedWebHost();

        if (usernameId == null
                || passwordId == null
                || packageName == null
                || packageName.isEmpty()
                || website == null
                || website.isEmpty()) {
            return null;
        }

        long now = SystemClock.elapsedRealtime();

        // Bind the request to the current authentication session.
        long authenticationGeneration =
                SafeKeySession.getManager()
                        .getAuthenticationGeneration();

        // Never register requests for locked or expired sessions.
        if (authenticationGeneration < 0) {
            return null;
        }

        removeExpired(now);

        if (REQUESTS.size() >= MAX_REQUESTS) {
            return null;
        }

        // Generate a cryptographically random 256-bit token.
        byte[] randomBytes = new byte[32];
        RANDOM.nextBytes(randomBytes);

        StringBuilder token = new StringBuilder();

        for (byte value : randomBytes) {
            token.append(String.format(
                    Locale.ROOT,
                    "%02x",
                    value & 0xFF
            ));
        }

        String requestToken = token.toString();

        REQUESTS.put(
                requestToken,
                new RequestRecord(
                        packageName,
                        website,
                        usernameId,
                        passwordId,
                        now,
                        authenticationGeneration
                )
        );

        return requestToken;
    }

    /**
     * Consumes a request token exactly once.
     *
     * The token is removed before validation so that even a failed
     * validation attempt cannot reuse it.
     *
     * Returns true only if the original request and authentication
     * session still match.
     */
    public static synchronized boolean consume(
            String token,
            AutofillRequestMetadata metadata
    ) {
        if (token == null
                || metadata == null
                || metadata.getFields() == null) {
            return false;
        }

        long now = SystemClock.elapsedRealtime();

        removeExpired(now);

        // Remove before validating to prevent replay.
        RequestRecord record = REQUESTS.remove(token);

        if (record == null) {
            return false;
        }

        // Verify that the original authentication session is still active.
        long currentGeneration =
                SafeKeySession.getManager()
                        .getAuthenticationGeneration();

        if (currentGeneration < 0
                || currentGeneration != record.authenticationGeneration) {
            return false;
        }

        // Verify the requesting application and website.
        boolean identityMatches =
                Objects.equals(
                        record.packageName,
                        metadata.getPackageName()
                )
                        && Objects.equals(
                        record.website,
                        metadata.getClaimedWebHost()
                );

        if (!identityMatches) {
            return false;
        }

        // Verify the exact username and password field identifiers.
        boolean fieldsMatch =
                Objects.equals(
                        record.usernameId,
                        metadata.getFields().getUsernameId()
                )
                        && Objects.equals(
                        record.passwordId,
                        metadata.getFields().getPasswordId()
                );

        return fieldsMatch;
    }

    /**
     * Cancels a pending request.
     */
    public static synchronized void cancel(String token) {
        if (token != null) {
            REQUESTS.remove(token);
        }
    }

    /**
     * Removes requests that are older than the allowed lifetime.
     */
    private static void removeExpired(long now) {
        REQUESTS.entrySet().removeIf(entry ->
                now - entry.getValue().createdAtMillis
                        >= REQUEST_TIMEOUT_MS
        );
    }

    /**
     * Stores the original request context without storing credentials.
     */
    private static final class RequestRecord {

        final String packageName;
        final String website;

        final AutofillId usernameId;
        final AutofillId passwordId;

        final long createdAtMillis;

        // Session generation when this request was registered.
        final long authenticationGeneration;

        RequestRecord(
                String packageName,
                String website,
                AutofillId usernameId,
                AutofillId passwordId,
                long createdAtMillis,
                long authenticationGeneration
        ) {
            this.packageName = packageName;
            this.website = website;
            this.usernameId = usernameId;
            this.passwordId = passwordId;
            this.createdAtMillis = createdAtMillis;
            this.authenticationGeneration = authenticationGeneration;
        }
    }
}

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
 * Tracks pending Autofill authentication requests.
 *
 * Supports HTTPS website and native Android request types.
 *
 * Security:
 * - Random 256-bit request tokens.
 * - One-time token consumption.
 * - 60-second expiration.
 * - Application package binding.
 * - Request-type binding.
 * - HTTPS origin binding for website requests.
 * - Exact Autofill field identifier matching.
 * - Authentication-session generation binding.
 *
 * IMPORTANT:
 * Native request registration does NOT establish trust.
 * The installed application's signing identity and its
 * authorization for each website credential must be
 * verified before any credentials are returned.
 *
 * No usernames or passwords are stored here.
 */
public final class AutofillRequestTracker {

    private static final long REQUEST_TIMEOUT_MS = 60_000L;

    private static final int MAX_REQUESTS = 32;

    private static final SecureRandom RANDOM =
            new SecureRandom();

    private static final Map<String, RequestRecord> REQUESTS =
            new HashMap<>();

    private AutofillRequestTracker() {
    }

    /**
     * Registers one pending authentication request.
     */
    public static synchronized String register(
            AutofillRequestMetadata metadata
    ) {
        return registerInternal(metadata, false);
    }

    static synchronized String registerForAuthentication(
            AutofillRequestMetadata metadata
    ) {
        return registerInternal(metadata, true);
    }

    private static String registerInternal(
            AutofillRequestMetadata metadata,
            boolean allowLockedAuthentication
    ) {
        if (SafeKeySession.getState()
                != com.safekey.app.session.logic.SessionState.UNLOCKED
                && (!allowLockedAuthentication
                || SafeKeySession.getState()
                != com.safekey.app.session.logic.SessionState.LOCKED)) {
            return null;
        }
        if (metadata == null || metadata.getFields() == null) {
            return null;
        }

        AutofillId usernameId =
                metadata.getFields().getUsernameId();

        AutofillId passwordId =
                metadata.getFields().getPasswordId();

        String packageName = metadata.getPackageName();

        if ((usernameId == null && passwordId == null)
                || (usernameId != null && usernameId.equals(passwordId))
                || packageName == null
                || packageName.isEmpty()
                || !packageName.equals(packageName.trim())) {
            return null;
        }

        boolean nativeApp = metadata.isNativeApp();

        String webOrigin = metadata.getClaimedWebOrigin();

        /*
         * The native and HTTPS request modes are exclusive.
         *
         * Native requests have no claimed web origin.
         * Website requests must have a valid HTTPS origin.
         */
        if (nativeApp) {
            if (metadata.getClaimedWebScheme() != null
                    || metadata.getClaimedWebHost() != null
                    || webOrigin != null) {
                return null;
            }
        } else if (webOrigin == null) {
            return null;
        }

        long now = SystemClock.elapsedRealtime();

        long authenticationGeneration =
                SafeKeySession.getManager()
                        .getAuthenticationGeneration();

        /*
         * A locked vault may register a request for authentication.
         * A negative generation never authorizes credential access.
         * It only records that authentication is still required.
         */
        if (authenticationGeneration < 0
                && SafeKeySession.getState()
                != com.safekey.app.session.logic.SessionState.LOCKED) {
            return null;
        }

        removeExpired(now);

        if (REQUESTS.size() >= MAX_REQUESTS) {
            return null;
        }

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
                        nativeApp,
                        webOrigin,
                        usernameId,
                        passwordId,
                        now,
                        authenticationGeneration
                )
        );

        return requestToken;
    }

    /**
     * Consumes an authentication request exactly once.
     *
     * A failed validation also invalidates the token.
     */
    public static synchronized boolean consume(
            String token,
            AutofillRequestMetadata metadata
    ) {
        return consumeInternal(token, metadata, false);
    }

    /**
     * Claims a request for an authentication flow.
     *
     * This method does NOT authorize vault access.
     * The caller must complete authentication, verify
     * the requesting application, and recheck the
     * active vault before returning credentials.
     *
     * The request token is invalidated immediately,
     * including when validation fails.
     */
    public static synchronized boolean takeForAuthentication(
            String token,
            AutofillRequestMetadata metadata
    ) {
        return consumeInternal(token, metadata, true);
    }

    private static boolean consumeInternal(
            String token,
            AutofillRequestMetadata metadata,
            boolean allowLockedAuthentication
    ) {
        if (token == null
                || metadata == null
                || metadata.getFields() == null) {
            return false;
        }

        long now = SystemClock.elapsedRealtime();

        removeExpired(now);

        // Remove first to prevent replay after any validation failure.
        RequestRecord record = REQUESTS.remove(token);

        if (record == null) {
            return false;
        }

        long currentGeneration =
                SafeKeySession.getManager()
                        .getAuthenticationGeneration();

        /*
         * Requests registered while unlocked must remain bound
         * to that exact authentication generation.
         *
         * Requests registered while locked can be claimed
         * before authentication, but this does not authorize
         * access to credentials.
         */
        if (record.authenticationGeneration >= 0) {
            if (currentGeneration != record.authenticationGeneration) {
                return false;
            }
        } else if (!allowLockedAuthentication) {
            // Locked-issued tokens require the authentication claim path.
            return false;
        }

        // The original Android package must remain identical.
        if (!Objects.equals(
                record.packageName,
                metadata.getPackageName()
        )) {
            return false;
        }

        // A website token must never become a native token.
        if (record.nativeApp != metadata.isNativeApp()) {
            return false;
        }

        if (record.nativeApp) {

            // Native requests must not acquire a claimed web origin.
            if (metadata.getClaimedWebScheme() != null
                    || metadata.getClaimedWebHost() != null
                    || metadata.getClaimedWebOrigin() != null) {
                return false;
            }

        } else {

            String requestOrigin =
                    metadata.getClaimedWebOrigin();

            if (requestOrigin == null
                    || !Objects.equals(
                            record.webOrigin,
                            requestOrigin
                    )) {
                return false;
            }
        }

        // Exact username and password field IDs must match.
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
     * Cancels an unused request.
     */
    public static synchronized void cancel(String token) {
        if (token != null) {
            REQUESTS.remove(token);
        }
    }

    /**
     * Removes expired requests.
     */
    private static void removeExpired(long now) {
        REQUESTS.entrySet().removeIf(entry ->
                now - entry.getValue().createdAtMillis
                        >= REQUEST_TIMEOUT_MS
        );
    }

    /**
     * Holds authentication request context only.
     * Does not store vault credentials.
     */
    private static final class RequestRecord {

        final String packageName;
        final boolean nativeApp;
        final String webOrigin;

        final AutofillId usernameId;
        final AutofillId passwordId;

        final long createdAtMillis;
        final long authenticationGeneration;

        RequestRecord(
                String packageName,
                boolean nativeApp,
                String webOrigin,
                AutofillId usernameId,
                AutofillId passwordId,
                long createdAtMillis,
                long authenticationGeneration
        ) {
            this.packageName = packageName;
            this.nativeApp = nativeApp;
            this.webOrigin = webOrigin;
            this.usernameId = usernameId;
            this.passwordId = passwordId;
            this.createdAtMillis = createdAtMillis;
            this.authenticationGeneration =
                    authenticationGeneration;
        }
    }
}

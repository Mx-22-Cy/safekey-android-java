package com.safekey.app.autofill;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.verify.domain.DomainVerificationManager;
import android.content.pm.verify.domain.DomainVerificationUserState;
import android.os.Build;

import com.safekey.app.data.model.Credential;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

/**
 * Verifies associations between Android applications and websites.
 *
 * SECURITY:
 * - Uses installed application signing certificates.
 * - Requires Digital Asset Links credential-sharing permission.
 * - Uses HTTPS with certificate validation.
 * - Never follows HTTP redirects.
 * - Fails closed when verification is unavailable.
 * - Does not transmit usernames or passwords.
 *
 * Native matching additionally requires Android-verified
 * App Links. It is currently supported on API 31+.
 *
 * Network verification must run on a background thread.
 */
public final class AutofillAssociationVerifier {

    private static final String LOGIN_RELATION =
            "delegate_permission/common.get_login_creds";

    private static final int MAX_RESPONSE_BYTES = 65536;
    private static final int TIMEOUT_MS = 3000;

    private static final int MAX_NATIVE_HOST_CHECKS = 16;

    private AutofillAssociationVerifier() {
    }

    /**
     * Verifies a website Autofill request.
     *
     * Native requests must use findNativeMatches().
     */
    public static boolean isAssociated(
            Context context,
            AutofillRequestMetadata metadata
    ) {
        if (context == null
                || metadata == null
                || metadata.isNativeApp()
                || metadata.getClaimedWebOrigin() == null) {
            return false;
        }

        String host = AutofillWebsiteMatcher.normalizeHost(
                metadata.getClaimedWebHost()
        );

        String packageName = metadata.getPackageName();

        if (host == null
                || packageName == null
                || packageName.isEmpty()) {
            return false;
        }

        try {
            Set<String> installedFingerprints =
                    getInstalledFingerprints(
                            context,
                            packageName
                    );

            if (installedFingerprints.isEmpty()) {
                return false;
            }

            String statements = fetchAssetLinks(host);

            if (statements == null) {
                return false;
            }

            return containsAssociation(
                    statements,
                    packageName,
                    installedFingerprints
            );

        } catch (Exception exception) {
            return false;
        }
    }

    /**
     * Returns only credentials whose website is authorized
     * to share login credentials with the requesting native app.
     *
     * Requirements:
     * 1. Native request metadata.
     * 2. Android-verified App Link domain.
     * 3. Installed package signing certificate.
     * 4. Valid website Digital Asset Links credential relation.
     * 5. Exact credential website matching.
     *
     * This method must run on a background thread.
     *
     * It does not unlock the vault or bypass the existing
     * authentication and real/decoy session checks.
     *
     * On API 26-30, native matching fails closed because this
     * implementation has no trusted local domain candidate
     * source for those platform versions.
     */
    public static List<Credential> findNativeMatches(
            Context context,
            AutofillRequestMetadata metadata,
            List<Credential> credentials
    ) {
        if (context == null
                || metadata == null
                || !metadata.isNativeApp()
                || metadata.getClaimedWebScheme() != null
                || metadata.getClaimedWebHost() != null
                || metadata.getClaimedWebOrigin() != null
                || credentials == null
                || credentials.isEmpty()
                || Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Collections.emptyList();
        }

        String packageName = metadata.getPackageName();

        if (packageName == null
                || packageName.isEmpty()
                || !packageName.equals(packageName.trim())) {
            return Collections.emptyList();
        }

        try {
            /*
             * First identify candidate domains already verified
             * by Android for this installed application.
             *
             * Do not query every website stored in the vault.
             */
            Set<String> verifiedHosts =
                    getVerifiedAppLinkHosts(
                            context,
                            packageName
                    );

            if (verifiedHosts.isEmpty()) {
                return Collections.emptyList();
            }

            Set<String> installedFingerprints =
                    getInstalledFingerprints(
                            context,
                            packageName
                    );

            if (installedFingerprints.isEmpty()) {
                return Collections.emptyList();
            }

            List<Credential> matches = new ArrayList<>();

            /*
             * Cache authorization outcomes only for this
             * verification operation, not across sessions.
             */
            Map<String, Boolean> checkedHosts =
                    new HashMap<>();

            for (Credential credential : credentials) {
                if (credential == null) {
                    continue;
                }

                String username = credential.getUsername();
                String password = credential.getPassword();
                String website = credential.getWebsite();

                if (username == null
                        || username.trim().isEmpty()
                        || password == null
                        || password.isEmpty()) {
                    continue;
                }

                String host = nativeHostForSavedWebsite(
                        website
                );

                if (host == null
                        || !verifiedHosts.contains(host)) {
                    continue;
                }

                /*
                 * Preserve the existing strict website matcher.
                 * No automatic subdomain sharing.
                 */
                if (!AutofillWebsiteMatcher.matches(
                        website,
                        host
                )) {
                    continue;
                }

                Boolean authorized = checkedHosts.get(host);

                if (authorized == null) {
                    /*
                     * Limit network checks and fail closed
                     * rather than scanning the user's vault.
                     */
                    if (checkedHosts.size()
                            >= MAX_NATIVE_HOST_CHECKS) {
                        return Collections.emptyList();
                    }

                    String statements = fetchAssetLinks(host);

                    authorized = statements != null
                            && containsAssociation(
                                    statements,
                                    packageName,
                                    installedFingerprints
                            );

                    checkedHosts.put(host, authorized);
                }

                if (authorized) {
                    matches.add(credential);
                }
            }

            return Collections.unmodifiableList(matches);

        } catch (Exception exception) {
            return Collections.emptyList();
        }
    }

    /**
     * Extracts a candidate HTTPS hostname from a saved
     * credential website.
     *
     * This method does not establish authorization.
     * The result must pass all native-app checks.
     *
     * Package-private for regression tests.
     */
    static String nativeHostForSavedWebsite(String website) {
        if (website == null) {
            return null;
        }

        String value = website.trim();

        if (value.isEmpty()
                || value.indexOf('\\') >= 0) {
            return null;
        }

        try {
            String candidate;

            if (value.contains("://")) {
                candidate = value;
            } else {
                candidate = "https://" + value;
            }

            URI uri = new URI(candidate);

            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null
                    || uri.getRawUserInfo() != null
                    || uri.getPort() != -1) {
                return null;
            }

            String host =
                    AutofillWebsiteMatcher.normalizeHost(
                            uri.getHost()
                    );

            if (host == null
                    || !AutofillWebsiteMatcher.matches(
                            website,
                            host
                    )) {
                return null;
            }

            return host;

        } catch (Exception exception) {
            return null;
        }
    }

    /**
     * Returns only domains Android has actually verified
     * for the requesting application's App Links.
     *
     * User-selected links are not treated as verified.
     */
    private static Set<String> getVerifiedAppLinkHosts(
            Context context,
            String packageName
    ) throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Collections.emptySet();
        }

        DomainVerificationManager manager =
                context.getSystemService(
                        DomainVerificationManager.class
                );

        if (manager == null) {
            return Collections.emptySet();
        }

        DomainVerificationUserState state =
                manager.getDomainVerificationUserState(
                        packageName
                );

        if (state == null) {
            return Collections.emptySet();
        }

        Set<String> verified = new HashSet<>();

        for (Map.Entry<String, Integer> entry :
                state.getHostToStateMap().entrySet()) {

            if (entry.getValue() == null
                    || entry.getValue()
                    != DomainVerificationUserState
                    .DOMAIN_STATE_VERIFIED) {
                continue;
            }

            String host =
                    AutofillWebsiteMatcher.normalizeHost(
                            entry.getKey()
                    );

            if (host != null) {
                verified.add(host);
            }
        }

        return verified;
    }

    /**
     * Gets the actual installed application's signing
     * certificates from Android PackageManager.
     */
    @SuppressWarnings("deprecation")
    private static Set<String> getInstalledFingerprints(
            Context context,
            String packageName
    ) throws Exception {

        PackageManager manager = context.getPackageManager();

        Signature[] signatures;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo info = manager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
            );

            if (info.signingInfo == null) {
                return new HashSet<>();
            }

            signatures =
                    info.signingInfo.getApkContentsSigners();

        } else {
            PackageInfo info = manager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
            );

            signatures = info.signatures;
        }

        Set<String> fingerprints = new HashSet<>();

        if (signatures == null || signatures.length == 0) {
            return fingerprints;
        }

        for (Signature signature : signatures) {
            if (signature == null) {
                return new HashSet<>();
            }

            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash =
                    digest.digest(signature.toByteArray());

            StringBuilder result = new StringBuilder();

            for (byte value : hash) {
                if (result.length() > 0) {
                    result.append(':');
                }

                result.append(String.format(
                        Locale.ROOT,
                        "%02X",
                        value & 0xFF
                ));
            }

            fingerprints.add(result.toString());
        }

        return fingerprints;
    }

    /**
     * Retrieves Digital Asset Links exclusively over HTTPS.
     */
    private static String fetchAssetLinks(String host) {
        HttpsURLConnection connection = null;

        try {
            URL url = new URL(
                    "https://" + host
                            + "/.well-known/assetlinks.json"
            );

            connection =
                    (HttpsURLConnection) url.openConnection();

            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty(
                    "Accept",
                    "application/json"
            );

            if (connection.getResponseCode() != 200) {
                return null;
            }

            String contentType = connection.getContentType();

            if (contentType == null
                    || !contentType.toLowerCase(Locale.ROOT)
                    .startsWith("application/json")) {
                return null;
            }

            try (InputStream input =
                         connection.getInputStream();
                 ByteArrayOutputStream output =
                         new ByteArrayOutputStream()) {

                byte[] buffer = new byte[4096];
                int total = 0;
                int count;

                while ((count = input.read(buffer)) != -1) {
                    total += count;

                    if (total > MAX_RESPONSE_BYTES) {
                        return null;
                    }

                    output.write(buffer, 0, count);
                }

                return new String(
                        output.toByteArray(),
                        StandardCharsets.UTF_8
                );
            }

        } catch (Exception exception) {
            return null;

        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Checks the exact application package and all current
     * installed signing certificates against the site's
     * credential-sharing Digital Asset Links statement.
     */
    static boolean containsAssociation(
            String json,
            String packageName,
            Set<String> installedFingerprints
    ) {
        if (json == null
                || packageName == null
                || installedFingerprints == null
                || installedFingerprints.isEmpty()) {
            return false;
        }

        try {
            JSONArray statements = new JSONArray(json);

            for (int i = 0; i < statements.length(); i++) {
                JSONObject statement =
                        statements.optJSONObject(i);

                if (statement == null) {
                    continue;
                }

                JSONArray relations =
                        statement.optJSONArray("relation");

                if (!hasLoginRelation(relations)) {
                    continue;
                }

                JSONObject target =
                        statement.optJSONObject("target");

                if (target == null
                        || !"android_app".equals(
                                target.optString("namespace"))
                        || !packageName.equals(
                                target.optString("package_name"))) {
                    continue;
                }

                JSONArray certificates =
                        target.optJSONArray(
                                "sha256_cert_fingerprints"
                        );

                if (certificates == null) {
                    continue;
                }

                Set<String> declared = new HashSet<>();

                for (int j = 0; j < certificates.length(); j++) {
                    String fingerprint =
                            certificates.optString(j, "")
                                    .toUpperCase(Locale.ROOT);

                    declared.add(fingerprint);
                }

                if (declared.containsAll(installedFingerprints)) {
                    return true;
                }
            }

        } catch (Exception exception) {
            return false;
        }

        return false;
    }

    private static boolean hasLoginRelation(
            JSONArray relations
    ) {
        if (relations == null) {
            return false;
        }

        for (int i = 0; i < relations.length(); i++) {
            if (LOGIN_RELATION.equals(
                    relations.optString(i)
            )) {
                return true;
            }
        }

        return false;
    }
}

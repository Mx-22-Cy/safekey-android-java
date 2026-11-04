package com.safekey.app.autofill;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

/**
 * Verifies an Android app's association with a website.
 *
 * Must run on a background thread.
 *
 * No credentials are read or transmitted by this class.
 * Failed verification always returns false.
 */
public final class AutofillAssociationVerifier {

    private static final String LOGIN_RELATION =
            "delegate_permission/common.get_login_creds";

    private static final int MAX_RESPONSE_BYTES = 65536;
    private static final int TIMEOUT_MS = 3000;

    private AutofillAssociationVerifier() {
    }

    public static boolean isAssociated(
            Context context,
            AutofillRequestMetadata metadata
    ) {
        if (context == null || metadata == null) {
            return false;
        }

        String host = AutofillWebsiteMatcher.normalizeHost(
                metadata.getClaimedWebHost()
        );

        String packageName = metadata.getPackageName();

        if (host == null || packageName == null
                || packageName.isEmpty()) {
            return false;
        }

        try {
            Set<String> installedFingerprints =
                    getInstalledFingerprints(context, packageName);

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
            // Fail closed. Never expose security details or passwords.
            return false;
        }
    }

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

            signatures = info.signingInfo.getApkContentsSigners();

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

            byte[] hash = digest.digest(signature.toByteArray());

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

    private static String fetchAssetLinks(String host) {
        HttpsURLConnection connection = null;

        try {
            URL url = new URL(
                    "https://" + host + "/.well-known/assetlinks.json"
            );

            connection = (HttpsURLConnection) url.openConnection();

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

            try (InputStream input = connection.getInputStream();
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

    static boolean containsAssociation(
            String json,
            String packageName,
            Set<String> installedFingerprints
    ) {
        if (json == null || packageName == null
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

    private static boolean hasLoginRelation(JSONArray relations) {
        if (relations == null) {
            return false;
        }

        for (int i = 0; i < relations.length(); i++) {
            if (LOGIN_RELATION.equals(relations.optString(i))) {
                return true;
            }
        }

        return false;
    }
}
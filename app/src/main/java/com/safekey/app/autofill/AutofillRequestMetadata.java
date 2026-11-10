package com.safekey.app.autofill;

import android.app.assist.AssistStructure;
import android.content.ComponentName;
import android.os.Build;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Extracts metadata about an Android Autofill request.
 *
 * Supports two request types:
 *
 * 1. HTTPS website requests.
 * 2. Native Android application requests.
 *
 * Recognition does not establish authorization.
 *
 * The requesting application's signing identity and its
 * authorization to receive a particular credential must
 * be verified separately before returning credentials.
 */
public final class AutofillRequestMetadata {

    private static final int MAX_NODES = 4096;

    private static final String SECURE_SCHEME = "https";
    private static final String SECURE_PREFIX = "https://";

    private final String packageName;
    private final String claimedWebScheme;
    private final String claimedWebHost;
    private final AutofillLoginFields.Fields fields;
    private final boolean nativeApp;

    private AutofillRequestMetadata(
            String packageName,
            String claimedWebScheme,
            String claimedWebHost,
            AutofillLoginFields.Fields fields,
            boolean nativeApp
    ) {
        this.packageName = packageName;
        this.claimedWebScheme = claimedWebScheme;
        this.claimedWebHost = claimedWebHost;
        this.fields = fields;
        this.nativeApp = nativeApp;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getClaimedWebScheme() {
        return claimedWebScheme;
    }

    public String getClaimedWebHost() {
        return claimedWebHost;
    }

    public AutofillLoginFields.Fields getFields() {
        return fields;
    }

    /**
     * True only for a request classified as a native
     * Android login form.
     *
     * This does not mean the application is trusted.
     */
    public boolean isNativeApp() {
        return nativeApp;
    }

    /**
     * Returns the canonical HTTPS origin for web requests.
     *
     * Native-app requests have no claimed website origin.
     */
    public String getClaimedWebOrigin() {
        if (nativeApp) {
            return null;
        }

        return canonicalHttpsOrigin(
                claimedWebScheme,
                claimedWebHost
        );
    }

    /**
     * Rejects HTTP and unsupported schemes.
     */
    static String canonicalHttpsOrigin(
            String scheme,
            String host
    ) {
        if (!SECURE_SCHEME.equalsIgnoreCase(scheme)) {
            return null;
        }

        String normalizedHost =
                AutofillWebsiteMatcher.normalizeHost(host);

        if (normalizedHost == null) {
            return null;
        }

        return SECURE_PREFIX + normalizedHost;
    }

    public static AutofillRequestMetadata extract(
            AssistStructure structure
    ) {
        if (structure == null) {
            return null;
        }

        ComponentName activity =
                structure.getActivityComponent();

        if (activity == null) {
            return null;
        }

        String packageName = activity.getPackageName();

        if (packageName == null || packageName.isEmpty()) {
            return null;
        }

        AutofillLoginFields.Fields fields =
                AutofillLoginFields.find(structure);

        if (fields == null) {
            return null;
        }

        Deque<AssistStructure.ViewNode> pending =
                new ArrayDeque<>();

        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            AssistStructure.ViewNode root =
                    structure.getWindowNodeAt(i).getRootViewNode();

            if (root != null) {
                pending.push(root);
            }
        }

        String claimedOrigin = null;
        boolean containsWebContent = false;
        int visited = 0;

        while (!pending.isEmpty()) {
            if (++visited > MAX_NODES) {
                return null;
            }

            AssistStructure.ViewNode node = pending.pop();

            String className = node.getClassName();

            /*
             * Web-like structures must never silently fall back
             * to native-app matching when website information
             * is missing.
             *
             * This is a conservative detection measure, not
             * proof that every possible WebView is detected.
             */
            if (className != null
                    && className.contains("WebView")) {
                containsWebContent = true;
            }

            if (node.getHtmlInfo() != null) {
                containsWebContent = true;
            }

            String domain = node.getWebDomain();

            String scheme = null;

            /*
             * getWebScheme() requires API 28.
             * Android 8 may still process native-app requests.
             */
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                scheme = node.getWebScheme();
            }

            if (domain != null || scheme != null) {

                containsWebContent = true;

                /*
                 * On API 26-27, the requesting web scheme
                 * cannot be verified.
                 *
                 * Never assume an unknown scheme is HTTPS.
                 */
                if (Build.VERSION.SDK_INT
                        < Build.VERSION_CODES.P) {
                    return null;
                }

                String origin = canonicalHttpsOrigin(
                        scheme,
                        domain
                );

                if (origin == null) {
                    return null;
                }

                if (claimedOrigin != null
                        && !claimedOrigin.equals(origin)) {
                    return null;
                }

                claimedOrigin = origin;
            }

            for (int i = node.getChildCount() - 1; i >= 0; i--) {
                AssistStructure.ViewNode child =
                        node.getChildAt(i);

                if (child != null) {
                    pending.push(child);
                }
            }
        }

        /*
         * A claimed website origin takes the existing
         * HTTPS verification path.
         */
        if (claimedOrigin != null) {

            String claimedHost = claimedOrigin.substring(
                    SECURE_PREFIX.length()
            );

            return new AutofillRequestMetadata(
                    packageName,
                    SECURE_SCHEME,
                    claimedHost,
                    fields,
                    false
            );
        }

        /*
         * Do not interpret a WebView lacking a valid origin
         * as a trusted native login form.
         */
        if (containsWebContent) {
            return null;
        }

        /*
         * Native login form:
         *
         * The package is a request identifier only.
         * No credentials may be returned until installed
         * signing certificates and website associations
         * are verified separately.
         */
        return new AutofillRequestMetadata(
                packageName,
                null,
                null,
                fields,
                true
        );
    }

    /**
     * Legacy website test helper.
     *
     * Production handling must use extract().
     */
    static AutofillRequestMetadata forTesting(
            String packageName,
            String claimedWebHost,
            AutofillLoginFields.Fields fields
    ) {
        return forTesting(
                packageName,
                SECURE_SCHEME,
                claimedWebHost,
                fields
        );
    }

    /**
     * Website test helper with explicit scheme.
     */
    static AutofillRequestMetadata forTesting(
            String packageName,
            String claimedWebScheme,
            String claimedWebHost,
            AutofillLoginFields.Fields fields
    ) {
        return new AutofillRequestMetadata(
                packageName,
                claimedWebScheme,
                claimedWebHost,
                fields,
                false
        );
    }

    /**
     * Native-app security test helper.
     *
     * Does not bypass application verification.
     */
    static AutofillRequestMetadata forTestingNative(
            String packageName,
            AutofillLoginFields.Fields fields
    ) {
        return new AutofillRequestMetadata(
                packageName,
                null,
                null,
                fields,
                true
        );
    }
}

package com.safekey.app.autofill;

import android.app.assist.AssistStructure;
import android.content.ComponentName;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Extracts metadata about an Android Autofill request.
 *
 * WARNING:
 * The reported web domain is not proof of ownership.
 * Callers must verify the app-to-domain relationship
 * before retrieving or returning any credentials.
 */
public final class AutofillRequestMetadata {

    private static final int MAX_NODES = 4096;

    private final String packageName;
    private final String claimedWebHost;
    private final AutofillLoginFields.Fields fields;

    private AutofillRequestMetadata(
            String packageName,
            String claimedWebHost,
            AutofillLoginFields.Fields fields
    ) {
        this.packageName = packageName;
        this.claimedWebHost = claimedWebHost;
        this.fields = fields;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getClaimedWebHost() {
        return claimedWebHost;
    }

    public AutofillLoginFields.Fields getFields() {
        return fields;
    }

    public static AutofillRequestMetadata extract(
            AssistStructure structure
    ) {
        if (structure == null) {
            return null;
        }

        ComponentName activity = structure.getActivityComponent();

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

        String claimedHost = null;

        Deque<AssistStructure.ViewNode> pending =
                new ArrayDeque<>();

        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            AssistStructure.ViewNode root =
                    structure.getWindowNodeAt(i).getRootViewNode();

            if (root != null) {
                pending.push(root);
            }
        }

        int visited = 0;

        while (!pending.isEmpty()) {
            if (++visited > MAX_NODES) {
                return null;
            }

            AssistStructure.ViewNode node = pending.pop();

            String domain = node.getWebDomain();

            if (domain != null && !domain.isEmpty()) {
                String normalized =
                        AutofillWebsiteMatcher.normalizeHost(domain);

                if (normalized == null) {
                    return null;
                }

                if (claimedHost != null
                        && !claimedHost.equals(normalized)) {
                    // Multiple domains: reject ambiguous forms.
                    return null;
                }

                claimedHost = normalized;
            }

            for (int i = node.getChildCount() - 1; i >= 0; i--) {
                AssistStructure.ViewNode child = node.getChildAt(i);

                if (child != null) {
                    pending.push(child);
                }
            }
        }

        if (claimedHost == null) {
            return null;
        }

        return new AutofillRequestMetadata(
                packageName,
                claimedHost,
                fields
        );
    }
}
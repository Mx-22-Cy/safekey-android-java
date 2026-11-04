package com.safekey.app.autofill;

import android.app.assist.AssistStructure;
import android.view.View;
import android.view.autofill.AutofillId;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Identifies username and password fields in an Android Autofill structure.
 *
 * This class does not retrieve or expose credentials.
 * The AutofillService must independently verify the requesting
 * app or website and the active vault session.
 */
public final class AutofillLoginFields {

    private static final int MAX_NODES = 4096;

    private AutofillLoginFields() {
    }

    public static final class Fields {

        private final AutofillId usernameId;
        private final AutofillId passwordId;

        private Fields(AutofillId usernameId, AutofillId passwordId) {
            this.usernameId = usernameId;
            this.passwordId = passwordId;
        }

        public AutofillId getUsernameId() {
            return usernameId;
        }

        public AutofillId getPasswordId() {
            return passwordId;
        }
    }

    public static Fields find(AssistStructure structure) {
        if (structure == null) {
            return null;
        }

        Deque<AssistStructure.ViewNode> pending = new ArrayDeque<>();

        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            AssistStructure.ViewNode root =
                    structure.getWindowNodeAt(i).getRootViewNode();

            if (root != null) {
                pending.push(root);
            }
        }

        AutofillId usernameId = null;
        AutofillId passwordId = null;

        int usernameCount = 0;
        int passwordCount = 0;
        int visited = 0;

        while (!pending.isEmpty()) {
            if (++visited > MAX_NODES) {
                return null;
            }

            AssistStructure.ViewNode node = pending.pop();

            if (node.getAutofillType() == View.AUTOFILL_TYPE_TEXT) {
                String[] hints = node.getAutofillHints();

                boolean username = hasHint(
                        hints,
                        View.AUTOFILL_HINT_USERNAME
                ) || hasHint(
                        hints,
                        View.AUTOFILL_HINT_EMAIL_ADDRESS
                );

                boolean password = hasHint(
                        hints,
                        View.AUTOFILL_HINT_PASSWORD
                );

                if (username && password) {
                    return null;
                }

                if (username || password) {
                    AutofillId id = node.getAutofillId();

                    if (id == null) {
                        return null;
                    }

                    if (username) {
                        usernameCount++;
                        usernameId = id;
                    }

                    if (password) {
                        passwordCount++;
                        passwordId = id;
                    }

                    if (usernameCount > 1 || passwordCount > 1) {
                        return null;
                    }
                }
            }

            for (int i = node.getChildCount() - 1; i >= 0; i--) {
                AssistStructure.ViewNode child = node.getChildAt(i);

                if (child != null) {
                    pending.push(child);
                }
            }
        }

        if (usernameCount != 1 || passwordCount != 1) {
            return null;
        }

        return new Fields(usernameId, passwordId);
    }

    private static boolean hasHint(String[] hints, String expected) {
        if (hints == null) {
            return false;
        }

        for (String hint : hints) {
            if (expected.equalsIgnoreCase(hint)) {
                return true;
            }
        }

        return false;
    }
}
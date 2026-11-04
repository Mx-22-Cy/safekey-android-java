package com.safekey.app.autofill;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@RunWith(AndroidJUnit4.class)
public class AutofillAssociationVerifierInstrumentedTest {

    private static final String PACKAGE_NAME =
            "com.safekey.autofilltestclient";

    private static final String FINGERPRINT =
            "AA:BB:CC:DD:EE:FF";

    private static Set<String> trustedFingerprints() {
        return Collections.singleton(FINGERPRINT);
    }

    private static String validAssetLinks() {
        return "[{"
                + "\"relation\":["
                + "\"delegate_permission/common.get_login_creds\""
                + "],"
                + "\"target\":{"
                + "\"namespace\":\"android_app\","
                + "\"package_name\":\"" + PACKAGE_NAME + "\","
                + "\"sha256_cert_fingerprints\":["
                + "\"" + FINGERPRINT + "\""
                + "]"
                + "}"
                + "}]";
    }

    @Test
    public void validAssociationIsAccepted() {

        assertTrue(
                AutofillAssociationVerifier.containsAssociation(
                        validAssetLinks(),
                        PACKAGE_NAME,
                        trustedFingerprints()
                )
        );
    }

    @Test
    public void differentPackageIsRejected() {

        assertFalse(
                AutofillAssociationVerifier.containsAssociation(
                        validAssetLinks(),
                        "com.example.attacker",
                        trustedFingerprints()
                )
        );
    }

    @Test
    public void differentCertificateIsRejected() {

        Set<String> wrongFingerprints =
                new HashSet<>();

        wrongFingerprints.add(
                "11:22:33:44:55:66"
        );

        assertFalse(
                AutofillAssociationVerifier.containsAssociation(
                        validAssetLinks(),
                        PACKAGE_NAME,
                        wrongFingerprints
                )
        );
    }

    @Test
    public void missingLoginRelationIsRejected() {

        String json = "[{"
                + "\"relation\":["
                + "\"delegate_permission/common.handle_all_urls\""
                + "],"
                + "\"target\":{"
                + "\"namespace\":\"android_app\","
                + "\"package_name\":\"" + PACKAGE_NAME + "\","
                + "\"sha256_cert_fingerprints\":["
                + "\"" + FINGERPRINT + "\""
                + "]"
                + "}"
                + "}]";

        assertFalse(
                AutofillAssociationVerifier.containsAssociation(
                        json,
                        PACKAGE_NAME,
                        trustedFingerprints()
                )
        );
    }

    @Test
    public void malformedJsonIsRejected() {

        assertFalse(
                AutofillAssociationVerifier.containsAssociation(
                        "{invalid-json",
                        PACKAGE_NAME,
                        trustedFingerprints()
                )
        );
    }

    @Test
    public void emptyFingerprintsAreRejected() {

        assertFalse(
                AutofillAssociationVerifier.containsAssociation(
                        validAssetLinks(),
                        PACKAGE_NAME,
                        Collections.emptySet()
                )
        );
    }

    @Test
    public void missingStatementsAreRejected() {

        assertFalse(
                AutofillAssociationVerifier.containsAssociation(
                        "[]",
                        PACKAGE_NAME,
                        trustedFingerprints()
                )
        );
    }
}

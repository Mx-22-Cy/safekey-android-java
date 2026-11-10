package com.safekey.app.autofill;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.view.View;
import android.view.autofill.AutofillId;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.safekey.app.data.model.Credential;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;

@RunWith(AndroidJUnit4.class)
public class AutofillNativeAssociationInstrumentedTest {

    private static Context context() {
        return ApplicationProvider.getApplicationContext();
    }

    private static AutofillId newId() {
        return new View(context()).getAutofillId();
    }

    private static AutofillLoginFields.Fields fields() {
        return AutofillLoginFields.Fields.forTesting(
                newId(),
                newId()
        );
    }

    private static Credential credential(String website) {
        return new Credential(
                "Test",
                "test@example.com",
                "dummy-password",
                website,
                "Login",
                ""
        );
    }

    @Test
    public void validHttpsWebsiteProducesExactHost() {
        assertEquals(
                "example.com",
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "https://example.com/login"
                )
        );
    }

    @Test
    public void schemelessWebsiteProducesHost() {
        assertEquals(
                "example.com",
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "example.com/login"
                )
        );
    }

    @Test
    public void insecureHttpWebsiteIsRejected() {
        assertNull(
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "http://example.com"
                )
        );
    }

    @Test
    public void nonDefaultPortIsRejected() {
        assertNull(
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "https://example.com:8443/login"
                )
        );
    }

    @Test
    public void embeddedUserInformationIsRejected() {
        assertNull(
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "https://user:password@example.com"
                )
        );
    }

    @Test
    public void backslashWebsiteIsRejected() {
        assertNull(
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "https://example.com\\@attacker.com"
                )
        );
    }

    @Test
    public void invalidHostnameIsRejected() {
        assertNull(
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "https://invalid host/login"
                )
        );
    }

    @Test
    public void nullWebsiteIsRejected() {
        assertNull(
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        null
                )
        );
    }

    @Test
    public void subdomainRemainsDistinct() {
        assertEquals(
                "login.example.com",
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "https://login.example.com"
                )
        );
    }

    @Test
    public void phishingSuffixIsNotConvertedToTrustedDomain() {
        assertEquals(
                "example.com.attacker.com",
                AutofillAssociationVerifier.nativeHostForSavedWebsite(
                        "https://example.com.attacker.com"
                )
        );
    }

    @Test
    public void websiteRequestCannotUseNativeAuthorization() {
        AutofillRequestMetadata webRequest =
                AutofillRequestMetadata.forTesting(
                        "com.example.client",
                        "https",
                        "example.com",
                        fields()
                );

        assertTrue(
                AutofillAssociationVerifier.findNativeMatches(
                        context(),
                        webRequest,
                        Collections.singletonList(
                                credential("https://example.com")
                        )
                ).isEmpty()
        );
    }

    @Test
    public void emptyCredentialListProducesNoNativeMatches() {
        AutofillRequestMetadata nativeRequest =
                AutofillRequestMetadata.forTestingNative(
                        "com.example.client",
                        fields()
                );

        assertTrue(
                AutofillAssociationVerifier.findNativeMatches(
                        context(),
                        nativeRequest,
                        Collections.emptyList()
                ).isEmpty()
        );
    }

    @Test
    public void unknownNativeApplicationIsRejected() {
        AutofillRequestMetadata nativeRequest =
                AutofillRequestMetadata.forTestingNative(
                        "com.safekey.nonexistent.test.client",
                        fields()
                );

        assertTrue(
                AutofillAssociationVerifier.findNativeMatches(
                        context(),
                        nativeRequest,
                        Collections.singletonList(
                                credential("https://example.com")
                        )
                ).isEmpty()
        );
    }
}

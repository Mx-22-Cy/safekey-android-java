package com.safekey.app.auth.logic;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BiometricSignInPolicyTest {

    @Test
    public void shouldShowUnlockOption_availableAndConfigured_returnsTrue() {
        assertTrue(
                BiometricSignInPolicy.shouldShowUnlockOption(
                        true,
                        true
                )
        );
    }

    @Test
    public void shouldShowUnlockOption_availableButNotConfigured_returnsFalse() {
        assertFalse(
                BiometricSignInPolicy.shouldShowUnlockOption(
                        true,
                        false
                )
        );
    }

    @Test
    public void shouldShowUnlockOption_unavailable_returnsFalse() {
        assertFalse(
                BiometricSignInPolicy.shouldShowUnlockOption(
                        false,
                        true
                )
        );
    }

    @Test
    public void shouldOfferEnrollment_availableAndNotConfigured_returnsTrue() {
        assertTrue(
                BiometricSignInPolicy.shouldOfferEnrollment(
                        true,
                        false
                )
        );
    }

    @Test
    public void shouldOfferEnrollment_availableAndConfigured_returnsFalse() {
        assertFalse(
                BiometricSignInPolicy.shouldOfferEnrollment(
                        true,
                        true
                )
        );
    }

    @Test
    public void shouldOfferEnrollment_unavailable_returnsFalse() {
        assertFalse(
                BiometricSignInPolicy.shouldOfferEnrollment(
                        false,
                        false
                )
        );
    }

    @Test
    public void requiresReEnrollment_missingKey_returnsTrue() {
        assertTrue(
                BiometricSignInPolicy.requiresReEnrollment(
                        "Biometric unlock key is missing. Re-enroll biometric unlock."
                )
        );
    }

    @Test
    public void requiresReEnrollment_invalidatedKey_returnsTrue() {
        assertTrue(
                BiometricSignInPolicy.requiresReEnrollment(
                        "Biometric unlock key is no longer valid. Re-enroll biometric unlock."
                )
        );
    }

    @Test
    public void requiresReEnrollment_cancelOrOtherError_returnsFalse() {
        assertFalse(
                BiometricSignInPolicy.requiresReEnrollment(
                        "Authentication canceled."
                )
        );
    }
}
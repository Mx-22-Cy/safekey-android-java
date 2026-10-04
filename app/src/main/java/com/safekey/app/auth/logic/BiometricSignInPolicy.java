package com.safekey.app.auth.logic;

public final class BiometricSignInPolicy {

    private BiometricSignInPolicy() {
    }

    public static boolean shouldShowUnlockOption(
            boolean biometricAvailable,
            boolean biometricConfigured
    ) {
        return biometricAvailable
                && biometricConfigured;
    }

    public static boolean shouldOfferEnrollment(
            boolean biometricAvailable,
            boolean biometricConfigured
    ) {
        return biometricAvailable
                && !biometricConfigured;
    }
}
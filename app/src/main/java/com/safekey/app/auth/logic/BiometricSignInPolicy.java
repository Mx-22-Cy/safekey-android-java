package com.safekey.app.auth.logic;

public final class BiometricSignInPolicy {

    private static final String MISSING_KEY_MESSAGE =
            "Biometric unlock key is missing. Re-enroll biometric unlock.";

    private static final String INVALIDATED_KEY_MESSAGE =
            "Biometric unlock key is no longer valid. Re-enroll biometric unlock.";

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
    public static boolean requiresReEnrollment(
            String message
    ) {
        return MISSING_KEY_MESSAGE.equals(message)
                || INVALIDATED_KEY_MESSAGE.equals(message);
    }
}
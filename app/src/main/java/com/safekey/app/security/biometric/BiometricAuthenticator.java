package com.safekey.app.security.biometric;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.util.concurrent.Executor;

import javax.crypto.Cipher;

public class BiometricAuthenticator {

    private static final int REQUIRED_AUTHENTICATORS =
            BiometricManager.Authenticators.BIOMETRIC_STRONG;

    private final FragmentActivity activity;
    private BiometricPrompt activePrompt;

    public BiometricAuthenticator(
            FragmentActivity activity
    ) {

        if (activity == null) {

            throw new IllegalArgumentException(
                    "Activity cannot be null."
            );
        }

        this.activity =
                activity;
    }

    public Availability getAvailability() {

        BiometricManager biometricManager =
                BiometricManager.from(
                        activity
                );

        int result =
                biometricManager.canAuthenticate(
                        REQUIRED_AUTHENTICATORS
                );

        switch (result) {

            case BiometricManager.BIOMETRIC_SUCCESS:

                return Availability.AVAILABLE;

            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:

                return Availability.NO_HARDWARE;

            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:

                return Availability.HARDWARE_UNAVAILABLE;

            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:

                return Availability.NONE_ENROLLED;

            default:

                return Availability.UNAVAILABLE;
        }
    }

    public void authenticate(
            Cipher cipher,
            String title,
            String subtitle,
            AuthenticationCallback callback
    ) {

        if (cipher == null) {

            throw new IllegalArgumentException(
                    "Cipher cannot be null."
            );
        }

        if (title == null
                || title.trim().isEmpty()) {

            throw new IllegalArgumentException(
                    "Biometric prompt title cannot be empty."
            );
        }

        if (callback == null) {

            throw new IllegalArgumentException(
                    "Authentication callback cannot be null."
            );
        }

        Executor executor =
                ContextCompat.getMainExecutor(
                        activity
                );

        final BiometricPrompt[] ownedPrompt = new BiometricPrompt[1];
        BiometricPrompt biometricPrompt =
                new BiometricPrompt(
                        activity,
                        executor,
                        new BiometricPrompt.AuthenticationCallback() {

                            @Override
                            public void onAuthenticationSucceeded(
                                    @NonNull BiometricPrompt.AuthenticationResult result
                            ) {

                                super.onAuthenticationSucceeded(result);
                                if (activePrompt == ownedPrompt[0]) { activePrompt = null; }

                                BiometricPrompt.CryptoObject cryptoObject =
                                        result.getCryptoObject();

                                if (cryptoObject == null
                                        || cryptoObject.getCipher() == null) {

                                    callback.onError(
                                            "Biometric authentication succeeded without an authenticated cipher."
                                    );

                                    return;
                                }

                                callback.onSuccess(
                                        cryptoObject.getCipher()
                                );
                            }

                            @Override
                            public void onAuthenticationError(
                                    int errorCode,
                                    @NonNull CharSequence errorString
                            ) {

                                super.onAuthenticationError(errorCode, errorString);
                                if (activePrompt == ownedPrompt[0]) { activePrompt = null; }

                                callback.onError(
                                        errorString.toString()
                                );
                            }

                            @Override
                            public void onAuthenticationFailed() {

                                super.onAuthenticationFailed();

                                callback.onFailed();
                            }
                        }
                );

        BiometricPrompt.PromptInfo.Builder promptBuilder =
                new BiometricPrompt.PromptInfo.Builder()
                        .setTitle(
                                title
                        )
                        .setAllowedAuthenticators(
                                REQUIRED_AUTHENTICATORS
                        )
                        .setNegativeButtonText(
                                "Cancel"
                        );

        if (subtitle != null
                && !subtitle.trim().isEmpty()) {

            promptBuilder.setSubtitle(
                    subtitle
            );
        }

        BiometricPrompt.CryptoObject cryptoObject =
                new BiometricPrompt.CryptoObject(
                        cipher
                );

        ownedPrompt[0] = biometricPrompt;
        activePrompt = biometricPrompt;
        biometricPrompt.authenticate(
                promptBuilder.build(),
                cryptoObject
        );
    }

    public enum Availability {

        AVAILABLE,
        NO_HARDWARE,
        HARDWARE_UNAVAILABLE,
        NONE_ENROLLED,
        UNAVAILABLE
    }

    public interface AuthenticationCallback {

        void onSuccess(
                Cipher authenticatedCipher
        );

        void onError(
                String message
        );

        void onFailed();
    }

    /** Call on the main thread; owners clear their key copy before cancellation. */
    public void cancelAuthentication() {
        BiometricPrompt prompt = activePrompt;
        activePrompt = null;
        if (prompt != null) { prompt.cancelAuthentication(); }
    }

}
package com.safekey.app.security.biometric;

import androidx.fragment.app.FragmentActivity;

import com.safekey.app.security.keystore.BiometricKeyEnvelopeStore;
import com.safekey.app.security.keystore.BiometricKeyStore;
import com.safekey.app.security.keystore.BiometricVaultKeyProtector;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

public class BiometricVaultKeyManager {

    private final BiometricAuthenticator authenticator;
    private final BiometricKeyStore keyStore;
    private final BiometricVaultKeyProtector protector;
    private final BiometricKeyEnvelopeStore envelopeStore;

    public BiometricVaultKeyManager(
            FragmentActivity activity
    ) {

        if (activity == null) {

            throw new IllegalArgumentException(
                    "Activity cannot be null."
            );
        }

        authenticator =
                new BiometricAuthenticator(
                        activity
                );

        keyStore =
                new BiometricKeyStore();

        protector =
                new BiometricVaultKeyProtector();

        envelopeStore =
                new BiometricKeyEnvelopeStore(
                        activity
                );
    }

    public BiometricAuthenticator.Availability getAvailability() {

        return authenticator.getAvailability();
    }

    public boolean isConfigured()
            throws Exception {

        return keyStore.containsKey()
                && envelopeStore.hasEnvelope();
    }

    public void enableBiometricUnlock(
            byte[] vaultKey,
            String title,
            String subtitle,
            SetupCallback callback
    ) {

        if (vaultKey == null
                || vaultKey.length == 0) {

            throw new IllegalArgumentException(
                    "Vault key cannot be null or empty."
            );
        }

        if (callback == null) {

            throw new IllegalArgumentException(
                    "Setup callback cannot be null."
            );
        }

        if (authenticator.getAvailability()
                != BiometricAuthenticator.Availability.AVAILABLE) {

            callback.onError(
                    "Strong biometric authentication is not available."
            );

            return;
        }

        final byte[] vaultKeyCopy =
                Arrays.copyOf(
                        vaultKey,
                        vaultKey.length
                );

        try {

            Cipher cipher =
                    keyStore.createEncryptionCipher();

            authenticator.authenticate(
                    cipher,
                    title,
                    subtitle,
                    new BiometricAuthenticator.AuthenticationCallback() {

                        @Override
                        public void onSuccess(
                                Cipher authenticatedCipher
                        ) {

                            try {

                                BiometricVaultKeyProtector.WrappedKey wrappedKey =
                                        protector.wrap(
                                                vaultKeyCopy,
                                                authenticatedCipher
                                        );

                                envelopeStore.save(
                                        wrappedKey
                                );

                                callback.onEnabled();

                            } catch (GeneralSecurityException
                                     | IllegalStateException exception) {

                                callback.onError(
                                        "Unable to enable biometric unlock."
                                );

                            } finally {

                                Arrays.fill(
                                        vaultKeyCopy,
                                        (byte) 0
                                );
                            }
                        }

                        @Override
                        public void onError(
                                String message
                        ) {

                            Arrays.fill(
                                    vaultKeyCopy,
                                    (byte) 0
                            );

                            callback.onError(
                                    message
                            );
                        }

                        @Override
                        public void onFailed() {

                            /*
                             * Do not clear vaultKeyCopy here.
                             *
                             * BiometricPrompt can report a failed scan
                             * while keeping the prompt open for another try.
                             */
                            callback.onFailed();
                        }
                    }
            );

        } catch (Exception exception) {

            Arrays.fill(
                    vaultKeyCopy,
                    (byte) 0
            );

            callback.onError(
                    "Unable to prepare biometric unlock."
            );
        }
    }

    public void unlockWithBiometrics(
            String title,
            String subtitle,
            UnlockCallback callback
    ) {

        if (callback == null) {

            throw new IllegalArgumentException(
                    "Unlock callback cannot be null."
            );
        }

        if (authenticator.getAvailability()
                != BiometricAuthenticator.Availability.AVAILABLE) {

            callback.onError(
                    "Strong biometric authentication is not available."
            );

            return;
        }

        final BiometricVaultKeyProtector.WrappedKey wrappedKey;

        try {

            wrappedKey =
                    envelopeStore.load();

        } catch (IllegalStateException exception) {

            callback.onError(
                    "Stored biometric unlock data is invalid."
            );

            return;
        }

        if (wrappedKey == null) {

            callback.onError(
                    "Biometric unlock has not been configured."
            );

            return;
        }

        try {

            Cipher cipher =
                    keyStore.createDecryptionCipher(
                            wrappedKey.getIv()
                    );

            authenticator.authenticate(
                    cipher,
                    title,
                    subtitle,
                    new BiometricAuthenticator.AuthenticationCallback() {

                        @Override
                        public void onSuccess(
                                Cipher authenticatedCipher
                        ) {

                            try {

                                byte[] vaultKey =
                                        protector.unwrap(
                                                wrappedKey,
                                                authenticatedCipher
                                        );

                                /*
                                 * Ownership of vaultKey is transferred
                                 * to the caller.
                                 *
                                 * The caller must clear the byte array
                                 * after using it.
                                 */
                                callback.onUnlocked(
                                        vaultKey
                                );

                            } catch (GeneralSecurityException
                                     | IllegalArgumentException exception) {

                                callback.onError(
                                        "Unable to unlock the protected vault key."
                                );
                            }
                        }

                        @Override
                        public void onError(
                                String message
                        ) {

                            callback.onError(
                                    message
                            );
                        }

                        @Override
                        public void onFailed() {

                            callback.onFailed();
                        }
                    }
            );

        } catch (Exception exception) {

            callback.onError(
                    "Unable to prepare biometric authentication."
            );
        }
    }

    public void disableBiometricUnlock()
            throws Exception {

        envelopeStore.clear();

        keyStore.deleteKey();
    }

    public interface SetupCallback {

        void onEnabled();

        void onError(
                String message
        );

        void onFailed();
    }

    public interface UnlockCallback {

        /*
         * The receiver owns vaultKey and must clear it
         * after using it.
         */
        void onUnlocked(
                byte[] vaultKey
        );

        void onError(
                String message
        );

        void onFailed();
    }
}
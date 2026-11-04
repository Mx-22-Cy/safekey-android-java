package com.safekey.app.security.biometric;

import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicWorkGate;

import android.security.keystore.KeyPermanentlyInvalidatedException;

import androidx.fragment.app.FragmentActivity;

import com.safekey.app.security.keystore.BiometricKeyEnvelopeStore;
import com.safekey.app.security.keystore.BiometricKeyStore;
import com.safekey.app.security.keystore.BiometricVaultKeyProtector;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

public class BiometricVaultKeyManager {

    private static final String RE_ENROLL_MISSING_KEY_MESSAGE =
            "Biometric unlock key is missing. Re-enroll biometric unlock.";

    private static final String RE_ENROLL_INVALIDATED_KEY_MESSAGE =
            "Biometric unlock key is no longer valid. Re-enroll biometric unlock.";

    private final PanicRuntimeScope runtimeScope;
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

        runtimeScope = PanicRuntimeScope.capture(activity);

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

    private void enableBiometricUnlockWhileRunning(
            byte[] vaultKey,
            String title,
            String subtitle,
            SetupCallback callback
    ) {

        BiometricVaultKeyProtector.validateVaultKey(
                vaultKey
        );

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

        final PanicRuntimeScope.PendingOperation pending;
        try {
            pending = runtimeScope.pending(
                    () -> Arrays.fill(vaultKeyCopy, (byte) 0), authenticator::cancelAuthentication);
        } catch (RuntimeException stopped) {
            Arrays.fill(vaultKeyCopy, (byte) 0);
            throw stopped;
        }

        try {
            if (!pending.isCurrent()) { pending.close(); return; }

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

                            if (!pending.isCurrent()) { pending.close(); return; }
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

                                pending.close();
                            }
                        }

                        @Override
                        public void onError(
                                String message
                        ) {

                            boolean current = pending.isCurrent();
                            pending.close();
                            if (!current) { return; }

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
                            if (pending.isCurrent()) { callback.onFailed(); }
                        }
                    }
            );

        } catch (KeyPermanentlyInvalidatedException exception) {

            pending.close();

            callback.onError(
                    RE_ENROLL_INVALIDATED_KEY_MESSAGE
            );

        } catch (Exception exception) {

            pending.close();

            callback.onError(
                    "Unable to prepare biometric unlock."
            );
        }
    }

    private void unlockWithBiometricsWhileRunning(
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

        final PanicRuntimeScope.PendingOperation pending =
                runtimeScope.pending(() -> {}, authenticator::cancelAuthentication);

        try {
            if (!pending.isCurrent()) { pending.close(); return; }

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

                            if (!pending.isCurrent()) { pending.close(); return; }
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
                            } finally { pending.close(); }
                        }

                        @Override
                        public void onError(
                                String message
                        ) {

                            boolean current = pending.isCurrent();
                            pending.close();
                            if (current) { callback.onError(message); }
                        }

                        @Override
                        public void onFailed() {

                            if (pending.isCurrent()) { callback.onFailed(); }
                        }
                    }
            );

        } catch (BiometricKeyStore.BiometricKeyMissingException exception) {
            pending.close();

            callback.onError(
                    RE_ENROLL_MISSING_KEY_MESSAGE
            );

        } catch (KeyPermanentlyInvalidatedException exception) {
            pending.close();

            callback.onError(
                    RE_ENROLL_INVALIDATED_KEY_MESSAGE
            );

        } catch (Exception exception) {
            pending.close();

            callback.onError(
                    "Unable to prepare biometric authentication."
            );
        }
    }

    private void disableBiometricUnlockWhileRunning()
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

    public void disableBiometricUnlock()
            throws Exception {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            disableBiometricUnlockWhileRunning();
        }
    }


    public void enableBiometricUnlock(
            byte[] vaultKey,
            String title,
            String subtitle,
            SetupCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            enableBiometricUnlockWhileRunning(vaultKey, title, subtitle, callback);
        }
    }


    public void unlockWithBiometrics(
            String title,
            String subtitle,
            UnlockCallback callback
    ) {
        try (PanicWorkGate.Operation ignored = runtimeScope.begin()) {
            unlockWithBiometricsWhileRunning(title, subtitle, callback);
        }
    }

}
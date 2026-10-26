package com.safekey.app.security.panic;

import android.content.Context;
import android.os.Looper;
import android.os.SystemClock;

import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelope;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.totp.TotpConfigurationFingerprint;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.security.totp.TotpState;
import com.safekey.app.security.totp.TotpVerificationService;
import com.safekey.app.security.totp.VaultUnlockFlow;
import com.safekey.app.session.SafeKeySession;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;

import javax.crypto.AEADBadTagException;

/** Reauthenticates actual credentials without opening either database. */
public final class AndroidPanicEnrollmentAuthority implements PanicPasswordService.EnrollmentAuthority {
    private final PanicRuntimeScope scope;
    private final SecureVaultCoordinator real;
    private final DecoyVaultCoordinator decoy;
    private final VaultKeyEnvelopeStore realStore;
    private final VaultKeyEnvelopeStore decoyStore;
    private final PanicPasswordStore panicStore;
    private final TotpVerificationService.StateStore totpStore;
    private final PanicMainThread main = new PanicMainThread();
    private final PanicEnrollmentAuthority authority;

    public AndroidPanicEnrollmentAuthority(Context context, SecureVaultCoordinator real,
                                            DecoyVaultCoordinator decoy) {
        this(context, real, decoy, new TotpSecretStore(context));
    }

    // Tests use a real encrypted store with dedicated names, never production TOTP keys.
    AndroidPanicEnrollmentAuthority(Context context, SecureVaultCoordinator real,
                                     DecoyVaultCoordinator decoy,
                                     TotpVerificationService.StateStore totpStore) {
        this.scope = PanicRuntimeScope.capture(Objects.requireNonNull(context, "context"));
        this.real = Objects.requireNonNull(real, "real");
        this.decoy = Objects.requireNonNull(decoy, "decoy");
        if (!real.belongsToPanicRuntime(scope) || !decoy.belongsToPanicRuntime(scope)) {
            throw new IllegalArgumentException("Panic enrollment must use the same vault runtime.");
        }
        realStore = new VaultKeyEnvelopeStore(context);
        decoyStore = VaultKeyEnvelopeStore.forDecoy(context);
        panicStore = new PanicPasswordStore(context);
        this.totpStore = Objects.requireNonNull(totpStore, "totpStore");
        authority = new PanicEnrollmentAuthority(scope.getWorkGate(), this::captureSession,
                this::captureCredentials, SystemClock::elapsedRealtime, 60_000L);
    }

    @Override public PanicPasswordService.Grant authenticate(char[] masterPassword, char[] decoyPassword)
            throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Reauthenticate on a background worker.");
        }
        return authority.authenticate(masterPassword, decoyPassword);
    }

    private PanicEnrollmentAuthority.SessionProof captureSession() throws Exception {
        return main.call(() -> {
            long authentication = SafeKeySession.getManager().getAuthenticationGeneration();
            VaultUnlockFlow.CompletedAuthentication completed = real.getCompletedAuthentication();
            long vaultGeneration = real.getVaultGeneration();
            requireRealSession(authentication, completed, vaultGeneration);
            synchronized (totpStore.getTransactionLock()) {
                requireTotpConfiguration(completed);
            }
            return (PanicEnrollmentAuthority.SessionProof) action -> main.call(() -> {
                Exception[] failure = {null};
                boolean[] flowCurrent = {false};
                boolean sessionCurrent = SafeKeySession.getManager().runIfCurrentAuthentication(
                        authentication, () -> {
                            flowCurrent[0] = real.runIfCurrentCompletedAuthentication(completed, () -> {
                                try {
                                    requireRealSession(authentication, completed, vaultGeneration);
                                    synchronized (totpStore.getTransactionLock()) {
                                        requireTotpConfiguration(completed);
                                        action.run();
                                    }
                                } catch (Exception error) { failure[0] = error; }
                            });
                        });
                if (!sessionCurrent || !flowCurrent[0]) { throw stale(); }
                if (failure[0] != null) { throw failure[0]; }
                return null;
            });
        });
    }

    private void requireRealSession(long authentication, VaultUnlockFlow.CompletedAuthentication completed,
                                     long vaultGeneration) {
        if (scope.isStopped() || authentication < 0 || completed == null
                || real.getCompletedAuthentication() != completed
                || !real.isVaultOpen() || decoy.isDecoyVaultOpen()
                || real.getVaultGeneration() != vaultGeneration) { throw stale(); }
    }

    private void requireTotpConfiguration(VaultUnlockFlow.CompletedAuthentication completed) throws Exception {
        byte[] secret = null;
        byte[] fingerprint = null;
        try (TotpState state = totpStore.load()) {
            if (state != null) { secret = state.copySecret(); }
            fingerprint = TotpConfigurationFingerprint.ofSecret(secret);
            if (!completed.matchesConfiguration(fingerprint)) { throw stale(); }
        } finally {
            clear(secret); clear(fingerprint);
        }
    }

    private PanicEnrollmentAuthority.CredentialProof captureCredentials() throws Exception {
        synchronized (PanicCredentialConfiguration.lock()) {
            long version = PanicCredentialConfiguration.version();
            VaultKeyEnvelope master = realStore.load();
            VaultKeyEnvelope secondary = decoyStore.load();
            PanicPasswordCrypto.Record previousPanic = panicStore.load();
            if (master == null || secondary == null) {
                throw new GeneralSecurityException("Configure both vault credentials before Panic enrollment.");
            }
            return new PanicEnrollmentAuthority.CredentialProof() {
                @Override public boolean matchesMaster(char[] password) throws Exception {
                    return matches(password, master, "safekey:database-key-envelope:v1");
                }
                @Override public boolean matchesDecoy(char[] password) throws Exception {
                    return matches(password, secondary, "safekey:decoy-database-key-envelope:v1");
                }
                @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
                    synchronized (PanicCredentialConfiguration.lock()) {
                        if (scope.isStopped() || version != PanicCredentialConfiguration.version()
                                || !same(master, realStore.load()) || !same(secondary, decoyStore.load())
                                || !same(previousPanic, panicStore.load())) { throw stale(); }
                        action.run();
                    }
                }
            };
        }
    }

    private static boolean matches(char[] password, VaultKeyEnvelope envelope, String context) throws Exception {
        byte[] salt = envelope.getSalt();
        byte[] key = null;
        byte[] databaseKey = null;
        try {
            key = new Argon2idMasterKeyDeriver().deriveKey(password, salt);
            try {
                databaseKey = new AesGcmCipher().decrypt(envelope.getWrappedDatabaseKey(),
                        key, context.getBytes(StandardCharsets.UTF_8));
            } catch (AesGcmException error) {
                if (error.getCause() instanceof AEADBadTagException) { return false; }
                // Invalid storage/format/provider errors must never become an ordinary non-match.
                throw error;
            }
            if (databaseKey.length != 32) {
                throw new GeneralSecurityException("Invalid authenticated vault key.");
            }
            return true;
        } finally { clear(salt); clear(key); clear(databaseKey); }
    }

    private static boolean same(VaultKeyEnvelope first, VaultKeyEnvelope second) {
        return second != null && first.getFormatVersion() == second.getFormatVersion()
                && Arrays.equals(first.getSalt(), second.getSalt())
                && first.getWrappedDatabaseKey().equals(second.getWrappedDatabaseKey());
    }

    private static boolean same(PanicPasswordCrypto.Record first, PanicPasswordCrypto.Record second) {
        return first == null ? second == null : second != null && Arrays.equals(first.encode(), second.encode());
    }

    private static void clear(byte[] value) { if (value != null) { Arrays.fill(value, (byte) 0); } }
    private static CancellationException stale() {
        return new CancellationException("A current authenticated Real vault session is required.");
    }
}

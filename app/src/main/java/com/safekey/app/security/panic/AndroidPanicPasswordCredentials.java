package com.safekey.app.security.panic;

import android.content.Context;

import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;
import com.safekey.app.security.storage.VaultKeyEnvelope;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CancellationException;

/** Storage-only role checks: never opens a database, claims a session or bypasses TOTP. */
final class AndroidPanicPasswordCredentials implements PanicSignInService.Credentials {
    private static final String MASTER_CONTEXT = "safekey:database-key-envelope:v1";
    private static final String DECOY_CONTEXT = "safekey:decoy-database-key-envelope:v1";
    // Public dummy ciphertext is used only to perform the same KDF/AEAD work for absent roles.
    // Its result is always ignored and it can never authorize a route or a wipe.
    private static final VaultKeyEnvelope DUMMY_VAULT = new VaultKeyEnvelope(
            new byte[Argon2idMasterKeyDeriver.SALT_LENGTH_BYTES],
            "SK1." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[12])
                    + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[48]));
    private static final PanicPasswordCrypto.Record DUMMY_PANIC = PanicPasswordCrypto.Record.decode(
            ByteBuffer.allocate(PanicPasswordCrypto.Record.ENCODED_LENGTH).putInt(1).array());

    private final PanicRuntimeScope scope;
    private final VaultKeyEnvelopeStore masterStore;
    private final VaultKeyEnvelopeStore decoyStore;
    private final PanicPasswordStore panicStore;

    AndroidPanicPasswordCredentials(Context context) {
        this(context, new PanicPasswordStore(context));
    }

    // Device tests supply an isolated proof filename, alongside mapped envelope preferences.
    AndroidPanicPasswordCredentials(Context context, PanicPasswordStore proofStore) {
        scope = PanicRuntimeScope.capture(context);
        masterStore = new VaultKeyEnvelopeStore(context);
        decoyStore = VaultKeyEnvelopeStore.forDecoy(context);
        panicStore = java.util.Objects.requireNonNull(proofStore, "proofStore");
    }

    @Override public PanicSignInService.Snapshot capture() {
        synchronized (PanicCredentialConfiguration.lock()) {
            long version = PanicCredentialConfiguration.version();
            VaultKeyEnvelope[] vaults = new VaultKeyEnvelope[2];
            PanicPasswordCrypto.Record[] panic = new PanicPasswordCrypto.Record[1];
            Exception[] errors = new Exception[3];
            try { vaults[0] = masterStore.load(); } catch (Exception error) { errors[0] = error; }
            try { vaults[1] = decoyStore.load(); } catch (Exception error) { errors[1] = error; }
            try { panic[0] = panicStore.load(); } catch (Exception error) { errors[2] = error; }
            return new PanicSignInService.Snapshot() {
                @Override public boolean matchesMaster(char[] candidate) throws Exception {
                    return matchesVault(candidate, vaults[0], MASTER_CONTEXT, errors[0]);
                }
                @Override public boolean matchesDecoy(char[] candidate) throws Exception {
                    return matchesVault(candidate, vaults[1], DECOY_CONTEXT, errors[1]);
                }
                @Override public boolean matchesPanic(char[] candidate) throws Exception {
                    boolean match = new PanicPasswordCrypto().matches(candidate,
                            panic[0] == null ? DUMMY_PANIC : panic[0]);
                    if (errors[2] != null) { throw errors[2]; }
                    return panic[0] != null && match;
                }
                @Override public void commitIfCurrent(PanicPasswordService.Commit action) throws Exception {
                    synchronized (PanicCredentialConfiguration.lock()) {
                        if (scope.isStopped() || version != PanicCredentialConfiguration.version()
                                || !same(vaults[0], masterStore.load()) || !same(vaults[1], decoyStore.load())
                                || !same(panic[0], panicStore.load())) {
                            throw new CancellationException("Password configuration changed. Try again.");
                        }
                        action.run();
                    }
                }
            };
        }
    }

    private static boolean matchesVault(char[] candidate, VaultKeyEnvelope envelope,
                                       String context, Exception error) throws Exception {
        boolean match = AndroidPanicEnrollmentAuthority.matches(candidate,
                envelope == null ? DUMMY_VAULT : envelope, context);
        if (error != null) { throw error; }
        return envelope != null && match;
    }

    private static boolean same(VaultKeyEnvelope first, VaultKeyEnvelope second) {
        return first == null ? second == null : second != null
                && first.getFormatVersion() == second.getFormatVersion()
                && Arrays.equals(first.getSalt(), second.getSalt())
                && first.getWrappedDatabaseKey().equals(second.getWrappedDatabaseKey());
    }

    private static boolean same(PanicPasswordCrypto.Record first, PanicPasswordCrypto.Record second) {
        return first == null ? second == null : second != null && Arrays.equals(first.encode(), second.encode());
    }
}

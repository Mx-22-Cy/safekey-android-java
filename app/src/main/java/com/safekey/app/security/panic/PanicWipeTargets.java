package com.safekey.app.security.panic;

import android.content.Context;
import android.content.SharedPreferences;

import com.safekey.app.session.AutoLockPreferences;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Exact owned resources only. Never enumerates or clears unrelated keys/files. */
public final class PanicWipeTargets {
    private PanicWipeTargets() { }

    /**
     * Resource manifest used by cold-start recovery. Fresh Sign In triggers
     * remain a separate integration step; callers must stop every writer.
     */
    public static List<PanicWipeCoordinator.Target> forSafeKey(Context context) {
        return create(context, Names.production());
    }

    static List<PanicWipeCoordinator.Target> create(Context supplied, Names names) {
        Context context = Objects.requireNonNull(
                Objects.requireNonNull(supplied, "context").getApplicationContext(),
                "applicationContext");
        ArrayList<PanicWipeCoordinator.Target> targets = new ArrayList<>();
        for (String alias : names.aliases) { targets.add(keyTarget(alias)); }
        for (String preference : names.preferences) {
            targets.add(preferenceTarget(context, preference));
        }
        File noBackup = Objects.requireNonNull(context.getNoBackupFilesDir(), "noBackupFilesDir");
        targets.add(fileTarget("TOTP state", PanicFiles.atomicArtifacts(
                new File(noBackup, names.totpFile))));
        for (String database : names.databases) {
            File base = context.getDatabasePath(database);
            targets.add(fileTarget("encrypted database", new File[]{base,
                    new File(base.getPath() + "-wal"), new File(base.getPath() + "-shm"),
                    new File(base.getPath() + "-journal")}));
        }
        targets.add(fileTarget("Panic proof", PanicFiles.atomicArtifacts(
                new File(noBackup, names.panicFile))));
        return Collections.unmodifiableList(targets);
    }

    private static PanicWipeCoordinator.Target keyTarget(String alias) {
        return new PanicWipeCoordinator.Target() {
            @Override public String name() { return "owned Keystore key"; }
            @Override public void erase() throws Exception {
                KeyStore store = openKeyStore();
                if (store.containsAlias(alias)) { store.deleteEntry(alias); }
            }
            @Override public void verifyAbsent() throws Exception {
                if (openKeyStore().containsAlias(alias)) {
                    throw new IOException("An owned Keystore key remains.");
                }
            }
        };
    }

    private static PanicWipeCoordinator.Target preferenceTarget(Context context, String name) {
        File directory = new File(context.getDataDir(), "shared_prefs");
        File[] files = {new File(directory, name + ".xml"),
                new File(directory, name + ".xml.bak")};
        return new PanicWipeCoordinator.Target() {
            @Override public String name() { return "key envelope"; }
            @Override public void erase() throws Exception {
                IOException failure = new IOException("Unable to clear a key envelope.");
                // Clear cached values, then remove XML/backups. One failed
                // operation must not skip the remaining deletion attempts.
                try {
                    SharedPreferences preferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
                    if (!preferences.edit().clear().commit()) {
                        throw new IOException("Unable to clear a cached key envelope.");
                    }
                } catch (Exception error) { failure.addSuppressed(error); }
                try { context.deleteSharedPreferences(name); }
                catch (Exception error) { failure.addSuppressed(error); }
                try { PanicFiles.deleteAll(files); }
                catch (Exception error) { failure.addSuppressed(error); }
                if (failure.getSuppressed().length != 0) {
                    throw failure;
                }
            }
            @Override public void verifyAbsent() throws Exception {
                PanicFiles.requireAbsent(files);
                if (!context.getSharedPreferences(name, Context.MODE_PRIVATE).getAll().isEmpty()) {
                    throw new IOException("A cached key envelope remains.");
                }
            }
        };
    }

    private static PanicWipeCoordinator.Target fileTarget(String name, File[] files) {
        return new PanicWipeCoordinator.Target() {
            @Override public String name() { return name; }
            @Override public void erase() throws Exception { PanicFiles.deleteAll(files); }
            @Override public void verifyAbsent() throws Exception { PanicFiles.requireAbsent(files); }
        };
    }

    private static KeyStore openKeyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }

    static final class Names {
        final String[] databases;
        final String[] preferences;
        final String[] aliases;
        final String totpFile;
        final String panicFile;
        final String journalFile;

        private Names(String[] databases, String[] preferences, String[] aliases,
                      String totpFile, String panicFile, String journalFile) {
            this.databases = databases;
            this.preferences = preferences;
            this.aliases = aliases;
            this.totpFile = totpFile;
            this.panicFile = panicFile;
            this.journalFile = journalFile;
        }

        static Names production() {
            return new Names(new String[]{"safekey.db", "safekey_secondary.db"},
                    new String[]{"safekey_vault_key_envelope", "safekey_decoy_vault_key_envelope",
                            "safekey_biometric_key_envelope", AutoLockPreferences.PREFERENCES_NAME},
                    new String[]{"safekey_biometric_vault_key", "safekey_totp_state_key_v1"},
                    "safekey_totp_state.enc", PanicPasswordStore.FILE_NAME, PanicWipeJournal.FILE_NAME);
        }

        static Names forTests(String prefix) {
            if (prefix == null || !prefix.matches("safekey_panic_test_[A-Za-z0-9_-]+_")) {
                throw new IllegalArgumentException("Isolated Panic test prefix is required.");
            }
            return new Names(new String[]{prefix + "real.db", prefix + "decoy.db"},
                    new String[]{prefix + "real_envelope", prefix + "decoy_envelope",
                            prefix + "biometric_envelope", prefix + "auto_lock"},
                    new String[]{prefix + "biometric_key", prefix + "totp_key"},
                    prefix + "totp.enc", prefix + "panic.enc", prefix + "wipe.pending");
        }
    }
}

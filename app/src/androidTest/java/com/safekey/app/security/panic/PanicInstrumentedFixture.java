package com.safekey.app.security.panic;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.safekey.app.data.database.SafeKeyDatabase;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.Assert.*;

/** Uses UNIQUE test names for every file, preference and Android Keystore key. */
final class PanicInstrumentedFixture implements AutoCloseable {
    static final String MASTER = "Mx8!rv3#Lp9$Kq4@Ft7%";
    static final String DECOY = "Dv7!na2#Wq8$Jt4@Bs9%";
    static final String PANIC = "Px6!mc3#Rs8$Hv2@Ld9%";
    final Context context;
    final String prefix = "safekey_panic_test_" + UUID.randomUUID().toString().replace("-", "") + "_";
    final PanicWipeTargets.Names names = PanicWipeTargets.Names.forTests(prefix);
    final PanicWorkGate gate = new PanicWorkGate();
    final PanicPasswordStore store;
    final PanicWipeJournal journal;
    final CountDownLatch markerArmed = new CountDownLatch(1);
    final List<SafeKeyDatabase> databases = new ArrayList<>();
    final List<byte[]> databaseKeys = new ArrayList<>();
    final List<SharedPreferences> cachedPreferences = new ArrayList<>();
    final List<PanicWipeCoordinator.Target> targets;
    final Object sessionLock = new Object();
    boolean unlocked = true;
    long generation;
    boolean resourcesClosed;
    boolean failClose;
    boolean injectDeletionFailure;
    final PanicWipeCoordinator coordinator;
    final PanicPasswordService service;

    PanicInstrumentedFixture(Context context) throws Exception {
        this.context = context.getApplicationContext();
        store = new PanicPasswordStore(this.context, names.panicFile);
        journal = new PanicWipeJournal(this.context, names.journalFile);
        targets = PanicWipeTargets.create(this.context, names);
        List<PanicWipeCoordinator.Target> wrapped = new ArrayList<>();
        boolean firstDatabase = true;
        for (PanicWipeCoordinator.Target target : targets) {
            if (firstDatabase && target.name().equals("encrypted database")) {
                firstDatabase = false;
                wrapped.add(new PanicWipeCoordinator.Target() {
                    @Override public String name() { return target.name(); }
                    @Override public void erase() throws Exception {
                        if (injectDeletionFailure) { throw new Exception("Injected database deletion failure."); }
                        target.erase();
                    }
                    @Override public void verifyAbsent() throws Exception { target.verifyAbsent(); }
                });
            } else { wrapped.add(target); }
        }
        PanicWipeCoordinator.Journal observedJournal = new PanicWipeCoordinator.Journal() {
            @Override public boolean isPending() throws Exception { return journal.isPending(); }
            @Override public void markPending() throws Exception {
                journal.markPending(); markerArmed.countDown();
            }
            @Override public void clearPending() throws Exception { journal.clearPending(); }
        };
        coordinator = new PanicWipeCoordinator(gate, observedJournal, runtime(), wrapped);
        service = new PanicPasswordService(gate, store, new PanicPasswordCrypto(), coordinator);
        try {
            seed();
        } catch (Exception | AssertionError error) {
            try { close(); } catch (Exception cleanupError) { error.addSuppressed(cleanupError); }
            throw error;
        }
    }

    private void seed() throws Exception {
        try (PanicWorkGate.Operation ignored = gate.begin()) {
            for (String name : names.databases) {
                byte[] key = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
                new SecureRandom().nextBytes(key);
                databaseKeys.add(key);
                SafeKeyDatabase database = new SafeKeyDatabase(context, name);
                databases.add(database);
                database.open(key).execSQL("CREATE TABLE panic_fixture (secret TEXT NOT NULL)");
                database.open(key).execSQL("INSERT INTO panic_fixture VALUES ('isolated test credential')");
            }
            for (String alias : names.aliases) { generateKey(alias); }
            SecretKey key = (SecretKey) keyStore().getKey(names.aliases[1], null);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal("isolated TOTP fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            File totp = new File(context.getNoBackupFilesDir(), names.totpFile);
            write(totp, encrypted);
            write(new File(totp.getPath() + ".bak"), encrypted);
            write(new File(totp.getPath() + ".new"), encrypted);
            for (String preference : names.preferences) {
                SharedPreferences prefs = context.getSharedPreferences(preference, Context.MODE_PRIVATE);
                assertTrue(prefs.edit().putString("wrapped_key", "isolated encrypted envelope").commit());
                cachedPreferences.add(prefs);
            }
        }
        service.enroll(MASTER.toCharArray(), DECOY.toCharArray(), PANIC.toCharArray(),
                PANIC.toCharArray(), this::authenticate);
    }

    private PanicPasswordService.Grant authenticate(char[] master, char[] decoy) {
        synchronized (sessionLock) {
            // Isolated authority port, not the production Sign In/TOTP router.
            if (!unlocked || !Arrays.equals(MASTER.toCharArray(), master)
                    || !Arrays.equals(DECOY.toCharArray(), decoy)) {
                throw new SecurityException("Isolated reauthentication failed.");
            }
            long expected = generation;
            return new PanicPasswordService.Grant() {
                @Override public void commitIfCurrent(PanicPasswordService.Commit commit) throws Exception {
                    synchronized (sessionLock) {
                        if (!unlocked || generation != expected) {
                            throw new SecurityException("Isolated session is stale.");
                        }
                        commit.run();
                    }
                }
                @Override public void close() { }
            };
        }
    }

    PanicWipeCoordinator.Runtime runtime() {
        return new PanicWipeCoordinator.Runtime() {
            @Override public void lockAndClearSession() {
                synchronized (sessionLock) { unlocked = false; generation++; }
            }
            @Override public void closeResources() throws Exception {
                if (failClose) { throw new Exception("Injected close failure."); }
                for (SafeKeyDatabase database : databases) { database.close(); }
                for (byte[] key : databaseKeys) { Arrays.fill(key, (byte) 0); }
                // Closed SQLite connections can remove their own sidecars.
                // Seed all three artifact names AFTER closing, so deletion of
                // every expected path is tested without corrupting an open DB.
                for (String database : names.databases) {
                    File base = context.getDatabasePath(database);
                    if (base.exists()) {
                        for (String suffix : new String[]{"-wal", "-shm", "-journal"}) {
                            write(new File(base.getPath() + suffix), new byte[]{1, 2, 3});
                        }
                    }
                }
                resourcesClosed = true;
            }
            @Override public boolean areResourcesClosed() {
                for (SafeKeyDatabase database : databases) {
                    if (database.isOpen()) { return false; }
                }
                return resourcesClosed;
            }
        };
    }

    void assertWiped() throws Exception {
        assertFalse(unlocked);
        assertTrue(resourcesClosed);
        for (PanicWipeCoordinator.Target target : targets) { target.verifyAbsent(); }
        for (SharedPreferences preferences : cachedPreferences) { assertTrue(preferences.getAll().isEmpty()); }
        for (byte[] key : databaseKeys) { assertArrayEquals(new byte[key.length], key); }
        assertFalse(journal.isPending());
        assertNull(store.load());
    }

    static KeyStore keyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }

    static void generateKey(String alias) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false).build());
        generator.generateKey();
    }

    static void write(File file, byte[] bytes) throws Exception {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new Exception("Unable to create isolated test directory.");
        }
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(bytes); output.getFD().sync();
        }
    }

    @Override public void close() throws Exception {
        Exception failure = new Exception("Isolated Panic test cleanup failed.");
        for (SafeKeyDatabase database : databases) {
            try { database.close(); } catch (Exception error) { failure.addSuppressed(error); }
        }
        for (byte[] key : databaseKeys) { Arrays.fill(key, (byte) 0); }
        for (PanicWipeCoordinator.Target target : targets) {
            try { target.erase(); target.verifyAbsent(); }
            catch (Exception error) { failure.addSuppressed(error); }
        }
        try { journal.clearPending(); } catch (Exception error) { failure.addSuppressed(error); }
        if (failure.getSuppressed().length != 0) { throw failure; }
    }
}

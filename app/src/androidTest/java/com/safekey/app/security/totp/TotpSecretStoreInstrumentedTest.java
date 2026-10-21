package com.safekey.app.security.totp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;

@RunWith(AndroidJUnit4.class)
public class TotpSecretStoreInstrumentedTest {

    private static final String TEST_ALIAS =
            "safekey_totp_instrumented_key";

    private static final String TEST_FILE =
            "safekey_totp_instrumented.enc";

    // Public RFC test data only; not a production enrollment secret.
    private static final byte[] TEST_SECRET =
            "12345678901234567890"
                    .getBytes(StandardCharsets.US_ASCII);

    private Context context;
    private TotpSecretStore store;
    private File stateFile;

    @Before
    public void setUp() throws Exception {
        context = InstrumentationRegistry.getInstrumentation()
                .getTargetContext()
                .getApplicationContext();

        store = new TotpSecretStore(
                context,
                TEST_ALIAS,
                TEST_FILE
        );

        stateFile = new File(
                context.getNoBackupFilesDir(),
                TEST_FILE
        );

        store.clear();
    }

    @After
    public void tearDown() throws Exception {
        if (store != null) {
            store.clear();
        }
    }

    @Test
    public void freshStore_hasNoConfigurationAndCreatesNoKey()
            throws Exception {
        assertFalse(store.isConfigured());
        assertNull(store.load());
        assertFalse(keyStore().containsAlias(TEST_ALIAS));
    }

    @Test
    public void newStoreInstance_readsSecretAndVerificationState()
            throws Exception {
        saveState();

        TotpSecretStore recreated = new TotpSecretStore(
                context,
                TEST_ALIAS,
                TEST_FILE
        );

        try (TotpState loaded = recreated.load()) {
            assertNotNull(loaded);

            byte[] secretCopy = loaded.copySecret();

            try {
                assertArrayEquals(TEST_SECRET, secretCopy);
                assertEquals(37L, loaded.getLastAcceptedStep());
                assertEquals(4, loaded.getFailedAttempts());

                assertEquals(
                        1_234_567_890L,
                        loaded.getBlockedUntilEpochMillis()
                );
            } finally {
                Arrays.fill(secretCopy, (byte) 0);
            }
        }
    }

    @Test
    public void storedFile_doesNotContainPlaintextSecret()
            throws Exception {
        saveState();

        byte[] stored = Files.readAllBytes(stateFile.toPath());

        for (int offset = 0;
             offset <= stored.length - TEST_SECRET.length;
             offset++) {

            byte[] section = Arrays.copyOfRange(
                    stored,
                    offset,
                    offset + TEST_SECRET.length
            );

            assertFalse(Arrays.equals(TEST_SECRET, section));
        }
    }

    @Test
    public void encryptionKey_cannotBeExportedAsBytes()
            throws Exception {
        saveState();

        assertNotNull(
                keyStore().getKey(TEST_ALIAS, null)
        );

        assertNull(
                keyStore().getKey(TEST_ALIAS, null).getEncoded()
        );
    }

    @Test
    public void changedCiphertext_isRejected()
            throws Exception {
        saveState();

        byte[] stored = Files.readAllBytes(stateFile.toPath());
        stored[stored.length - 1] ^= 1;

        Files.write(stateFile.toPath(), stored);

        assertTrue(store.isConfigured());
        assertLoadFails();
    }

    @Test
    public void truncatedAndOversizedFiles_areRejected()
            throws Exception {
        saveState();

        byte[] stored = Files.readAllBytes(stateFile.toPath());

        Files.write(
                stateFile.toPath(),
                Arrays.copyOf(stored, 3)
        );

        assertLoadFails();

        Files.write(
                stateFile.toPath(),
                Arrays.copyOf(stored, stored.length + 1)
        );

        assertLoadFails();
    }

    @Test
    public void missingFile_doesNotSilentlyDisableTotp()
            throws Exception {
        saveState();
        Files.delete(stateFile.toPath());

        assertTrue(store.isConfigured());
        assertLoadFails();
    }

    @Test
    public void missingKey_doesNotSilentlyDisableTotp()
            throws Exception {
        saveState();
        keyStore().deleteEntry(TEST_ALIAS);

        assertTrue(store.isConfigured());
        assertLoadFails();
    }

    @Test
    public void save_doesNotReplaceMissingProtectionKey()
            throws Exception {
        saveState();
        keyStore().deleteEntry(TEST_ALIAS);

        try {
            saveState();

            fail(
                    "A missing protection key must not be silently replaced."
            );
        } catch (GeneralSecurityException expected) {
            assertFalse(
                    keyStore().containsAlias(TEST_ALIAS)
            );
        }
    }

    @Test
    public void repeatedSave_usesFreshEncryption()
            throws Exception {
        saveState();

        byte[] first = Files.readAllBytes(stateFile.toPath());

        saveState();

        byte[] second = Files.readAllBytes(stateFile.toPath());

        assertFalse(Arrays.equals(first, second));

        try (TotpState loaded = store.load()) {
            assertNotNull(loaded);
        }
    }

    @Test
    public void clear_removesStateAndProtectionKey()
            throws Exception {
        saveState();
        store.clear();

        assertFalse(stateFile.exists());

        assertFalse(
                new File(stateFile.getPath() + ".bak").exists()
        );

        assertFalse(
                new File(stateFile.getPath() + ".new").exists()
        );

        assertFalse(
                keyStore().containsAlias(TEST_ALIAS)
        );

        assertFalse(store.isConfigured());
        assertNull(store.load());
    }

    private void saveState() throws Exception {
        try (TotpState state = new TotpState(
                TEST_SECRET,
                37L,
                4,
                1_234_567_890L
        )) {
            store.save(state);
        }
    }

    private void assertLoadFails() throws Exception {
        try (TotpState unexpected = store.load()) {
            fail(
                    unexpected == null
                            ? "Missing state must not silently disable TOTP."
                            : "Damaged TOTP state must not load."
            );
        } catch (GeneralSecurityException | IOException expected) {
            // Expected: the caller must keep authentication locked.
        }
    }

    private static KeyStore keyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(
                "AndroidKeyStore"
        );

        keyStore.load(null);
        return keyStore;
    }
}

package com.safekey.app.data.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.database.Cursor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.Credential;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.UUID;

/** Uses only a disposable, randomly named database; never the real SafeKey vault. */
@RunWith(AndroidJUnit4.class)
public class CredentialEncryptionInstrumentedTest {

    private Context context;
    private String databaseName;
    private byte[] key;
    private SafeKeyDatabase manager;
    private VaultItemCipher cipher;
    private SQLiteDatabase database;
    private CredentialRepository repository;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        databaseName = "test_credential_v4_" + UUID.randomUUID() + ".db";
        key = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
        Arrays.fill(key, (byte) 81);
        manager = new SafeKeyDatabase(context, databaseName);
        cipher = new VaultItemCipher(key);
        database = manager.openForItemEncryption(key, cipher);
        repository = new CredentialRepository(database, cipher);
    }

    @After
    public void tearDown() {
        try {
            if (manager != null) {
                manager.close();
            }
        } finally {
            if (cipher != null) {
                cipher.close();
            }
            if (context != null && databaseName != null) {
                context.deleteDatabase(databaseName);
            }
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    @Test
    public void insertEncryptsBothFieldsAndReadsReturnAuthorizedPlaintext() throws Exception {
        long id = add("First", "fixture-password-1", "fixture-notes-1");
        RawFields raw = rawFields(id);
        assertEquals(1, raw.version);
        assertEquals(UUID.fromString(raw.uuid).toString(), raw.uuid);
        assertNotEquals("fixture-password-1", raw.password);
        assertNotEquals("fixture-notes-1", raw.notes);
        assertEquals("fixture-password-1", cipher.decrypt(
                VaultItemCipher.Field.CREDENTIAL_PASSWORD, raw.uuid, raw.password));
        assertEquals("fixture-notes-1", cipher.decrypt(
                VaultItemCipher.Field.CREDENTIAL_NOTES, raw.uuid, raw.notes));

        Credential loaded = repository.getById(id);
        assertNotNull(loaded);
        assertEquals("fixture-password-1", loaded.getPassword());
        assertEquals("fixture-notes-1", loaded.getNotes());
        assertEquals(1, repository.getAll().size());
        assertEquals(id, repository.search("First").get(0).getId());
    }

    @Test
    public void updateRetainsRecordIdentityAndInvalidatesOldBreachResult() {
        long id = add("Account", "original-password", "original-notes");
        String initialUuid = rawFields(id).uuid;
        assertEquals(PasswordBreachResult.Status.BREACHED, repository.updateBreachStatus(
                id, "original-password", PasswordBreachResult.Status.BREACHED));

        Credential edited = repository.getById(id);
        edited.setPassword("replacement-password");
        edited.setTitle("Updated account");
        assertEquals(1, repository.update(edited));

        RawFields after = rawFields(id);
        assertEquals(initialUuid, after.uuid);
        assertEquals(1, after.version);
        Credential saved = repository.getById(id);
        assertEquals("replacement-password", saved.getPassword());
        assertEquals("original-notes", saved.getNotes());
        assertEquals(PasswordBreachResult.Status.NOT_CHECKED, saved.getBreachStatus());
        assertNull(repository.updateBreachStatus(
                id, "original-password", PasswordBreachResult.Status.NOT_FOUND));
        assertEquals(PasswordBreachResult.Status.NOT_FOUND, repository.updateBreachStatus(
                id, "replacement-password", PasswordBreachResult.Status.NOT_FOUND));
    }

    @Test
    public void encryptedFieldsAreRandomizedEvenForEqualPasswords() {
        long first = add("One", "same-value", "same-notes");
        long second = add("Two", "same-value", "same-notes");
        RawFields one = rawFields(first);
        RawFields two = rawFields(second);
        assertNotEquals(one.uuid, two.uuid);
        assertNotEquals(one.password, two.password);
        assertNotEquals(one.notes, two.notes);
        assertEquals("same-value", repository.getById(first).getPassword());
        assertEquals("same-value", repository.getById(second).getPassword());
    }

    @Test
    public void swappingCiphertextAcrossRecordsFailsClosed() {
        long first = add("One", "secret-one", "note-one");
        long second = add("Two", "secret-two", "note-two");
        String firstCiphertext = rawFields(first).password;
        database.execSQL("UPDATE credentials SET password_ciphertext = ? WHERE id = ?",
                new Object[]{firstCiphertext, second});
        expectRejected(() -> repository.getById(second));
        assertEquals("secret-one", repository.getById(first).getPassword());
    }

    @Test
    public void corruptCiphertextAndLegacyMetadataNeverFallbackToPlaintext() {
        long id = add("One", "secret-one", "note-one");
        database.execSQL("UPDATE credentials SET notes_ciphertext = ? WHERE id = ?",
                new Object[]{"untrusted-plaintext", id});
        expectRejected(() -> repository.getById(id));

        database.execSQL("UPDATE credentials SET field_encryption_version = 0 WHERE id = ?",
                new Object[]{id});
        expectRejected(() -> repository.getById(id));
    }

    @Test
    public void reopeningPreservesCiphertextAndRecordIdentity() {
        long id = add("One", "persistent-password", "persistent-notes");
        String uuid = rawFields(id).uuid;
        manager.close();
        cipher.close();

        cipher = new VaultItemCipher(key);
        database = manager.openForItemEncryption(key, cipher);
        repository = new CredentialRepository(database, cipher);
        assertEquals(uuid, rawFields(id).uuid);
        assertEquals("persistent-password", repository.getById(id).getPassword());
        assertEquals("persistent-notes", repository.getById(id).getNotes());
    }

    @Test
    public void legacyConstructorRefusesEncryptedDatabaseAndClosedCipherStopsAccess() {
        expectRejected(() -> new CredentialRepository(database));
        long id = add("One", "secret-one", "note-one");
        cipher.close();
        expectRejected(() -> repository.getById(id));
        expectRejected(() -> add("Two", "secret-two", "note-two"));
    }

    private long add(String title, String password, String notes) {
        long id = repository.insert(new Credential(
                title, "fixture-user", password, "example.test", "Work", notes));
        assertTrue(id > 0);
        return id;
    }

    private RawFields rawFields(long id) {
        Cursor cursor = database.rawQuery(
                "SELECT record_uuid, field_encryption_version, password_ciphertext, "
                        + "notes_ciphertext FROM credentials WHERE id = ?",
                new String[]{Long.toString(id)});
        try {
            assertTrue(cursor.moveToFirst());
            return new RawFields(cursor.getString(0), cursor.getInt(1),
                    cursor.getString(2), cursor.getString(3));
        } finally {
            cursor.close();
        }
    }

    private static void expectRejected(Runnable operation) {
        try {
            operation.run();
            fail("Expected the repository to reject invalid encrypted data or access.");
        } catch (IllegalStateException expected) {
            // Authentication or version failure must not return plaintext.
        }
    }

    private static final class RawFields {
        final String uuid;
        final int version;
        final String password;
        final String notes;

        RawFields(String uuid, int version, String password, String notes) {
            this.uuid = uuid;
            this.version = version;
            this.password = password;
            this.notes = notes;
        }
    }
}

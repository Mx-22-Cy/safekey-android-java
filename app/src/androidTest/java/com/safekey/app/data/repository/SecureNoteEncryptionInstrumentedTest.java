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

import com.safekey.app.data.database.SafeKeyDatabase;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.security.crypto.VaultItemCipher;

import net.zetetic.database.sqlcipher.SQLiteDatabase;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/** v4 Secure Notes tests use a disposable SQLCipher database, never a user vault. */
@RunWith(AndroidJUnit4.class)
public class SecureNoteEncryptionInstrumentedTest {

    private Context context;
    private String databaseName;
    private byte[] databaseKey;
    private SafeKeyDatabase manager;
    private VaultItemCipher cipher;
    private SQLiteDatabase database;
    private SecureNoteRepository repository;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        databaseName = "test_secure_notes_v4_" + UUID.randomUUID() + ".db";
        databaseKey = new byte[SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES];
        Arrays.fill(databaseKey, (byte) 72);
        manager = new SafeKeyDatabase(context, databaseName);
        cipher = new VaultItemCipher(databaseKey);
        database = manager.openForItemEncryption(databaseKey, cipher);
        repository = new SecureNoteRepository(database, cipher);
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
            if (databaseKey != null) {
                Arrays.fill(databaseKey, (byte) 0);
            }
        }
    }

    @Test
    public void insertionEncryptsContentAndAuthorizedReadsDecryptIt() throws Exception {
        long id = add("Enrollment", "fictional recovery phrase");
        RawNote raw = rawNote(id);
        assertEquals(1, raw.version);
        assertEquals(UUID.fromString(raw.uuid).toString(), raw.uuid);
        assertNotEquals("fictional recovery phrase", raw.content);
        assertEquals("fictional recovery phrase", cipher.decrypt(
                VaultItemCipher.Field.SECURE_NOTE_CONTENT, raw.uuid, raw.content));
        SecureNote read = repository.getById(id);
        assertNotNull(read);
        assertEquals("fictional recovery phrase", read.getContent());
        assertEquals(id, repository.getAll().get(0).getId());
    }

    @Test
    public void editingPreservesRecordUuidAndMakesFreshCiphertext() {
        long id = add("Personal", "fictional original");
        RawNote before = rawNote(id);
        SecureNote edited = repository.getById(id);
        edited.setContent("fictional replacement");
        edited.setTitle("Updated personal");
        assertEquals(1, repository.update(edited));
        RawNote after = rawNote(id);
        assertEquals(before.uuid, after.uuid);
        assertEquals(1, after.version);
        assertNotEquals(before.content, after.content);
        assertEquals("fictional replacement", repository.getById(id).getContent());
        assertEquals("Updated personal", repository.getById(id).getTitle());
    }

    @Test
    public void searchFindsDecryptedContentAndLiteralWildcardCharacters() {
        long wanted = add("Unrelated", "Very private RECOVERY phrase % _ for testing");
        add("Other", "different fictional content");
        List<SecureNote> found = repository.search("recovery PHRASE");
        assertEquals(1, found.size());
        assertEquals(wanted, found.get(0).getId());
        assertEquals(wanted, repository.search("%").get(0).getId());
        assertEquals(1, repository.search("_").size());
        assertEquals(wanted, repository.search("unrelated").get(0).getId());
        assertEquals(2, repository.search("  ").size());
    }

    @Test
    public void encryptsEqualContentsDifferentlyAcrossRecords() {
        long first = add("First", "same fictional content");
        long second = add("Second", "same fictional content");
        RawNote a = rawNote(first);
        RawNote b = rawNote(second);
        assertNotEquals(a.uuid, b.uuid);
        assertNotEquals(a.content, b.content);
        assertEquals("same fictional content", repository.getById(first).getContent());
        assertEquals("same fictional content", repository.getById(second).getContent());
    }

    @Test
    public void swappedCiphertextAndCorruptedContentNeverFallBackToPlaintext() {
        long first = add("First", "first secret");
        long second = add("Second", "second secret");
        String firstCiphertext = rawNote(first).content;
        database.execSQL("UPDATE secure_notes SET content_ciphertext = ? WHERE id = ?",
                new Object[]{firstCiphertext, second});
        expectRejected(() -> repository.getById(second));
        assertEquals("first secret", repository.getById(first).getContent());
        database.execSQL("UPDATE secure_notes SET content_ciphertext = ? WHERE id = ?",
                new Object[]{"forged plaintext", first});
        expectRejected(() -> repository.getById(first));
        expectRejected(() -> repository.search("First"));
    }

    @Test
    public void invalidMetadataAndWrongFieldCiphertextAreRejected() throws Exception {
        long id = add("Sensitive", "content fixture");
        RawNote raw = rawNote(id);
        String wrongField = cipher.encrypt(
                VaultItemCipher.Field.CREDENTIAL_NOTES, raw.uuid, "wrong field");
        database.execSQL("UPDATE secure_notes SET content_ciphertext = ? WHERE id = ?",
                new Object[]{wrongField, id});
        expectRejected(() -> repository.getById(id));

        database.execSQL("UPDATE secure_notes SET content_ciphertext = ? WHERE id = ?",
                new Object[]{raw.content, id});
        database.execSQL("UPDATE secure_notes SET field_encryption_version = 0 WHERE id = ?",
                new Object[]{id});
        expectRejected(() -> repository.getById(id));

        database.execSQL("UPDATE secure_notes SET field_encryption_version = 1, "
                        + "record_uuid = ? WHERE id = ?",
                new Object[]{"invalid-uuid", id});
        expectRejected(() -> repository.getById(id));
    }

    @Test
    public void reopenedVaultPreservesEncryptedNoteAndIdentity() {
        long id = add("Persistent", "persistent fictional note");
        String uuid = rawNote(id).uuid;
        manager.close();
        cipher.close();
        cipher = new VaultItemCipher(databaseKey);
        database = manager.openForItemEncryption(databaseKey, cipher);
        repository = new SecureNoteRepository(database, cipher);
        assertEquals(uuid, rawNote(id).uuid);
        assertEquals("persistent fictional note", repository.getById(id).getContent());
        assertEquals(1, repository.delete(id));
        assertNull(repository.getById(id));
    }

    @Test
    public void legacyConstructorRejectsV4AndClosingCipherDeniesAccess() {
        expectRejected(() -> new SecureNoteRepository(database));
        long id = add("Example", "test content");
        cipher.close();
        expectRejected(() -> repository.getById(id));
        expectRejected(() -> add("Another", "content"));
        expectRejected(() -> repository.search("test"));
    }

    private long add(String title, String content) {
        long id = repository.insert(new SecureNote(title, content));
        assertTrue(id > 0);
        return id;
    }

    private RawNote rawNote(long id) {
        Cursor cursor = database.rawQuery(
                "SELECT record_uuid, field_encryption_version, content_ciphertext "
                        + "FROM secure_notes WHERE id = ?",
                new String[]{Long.toString(id)});
        try {
            assertTrue(cursor.moveToFirst());
            return new RawNote(cursor.getString(0), cursor.getInt(1), cursor.getString(2));
        } finally {
            cursor.close();
        }
    }

    private static void expectRejected(Runnable operation) {
        try {
            operation.run();
            fail("Expected encrypted data or closed-cipher access to be rejected.");
        } catch (IllegalStateException expected) {
            // Invalid authenticated data must not be returned as plaintext.
        }
    }

    private static final class RawNote {
        final String uuid;
        final int version;
        final String content;

        RawNote(String uuid, int version, String content) {
            this.uuid = uuid;
            this.version = version;
            this.content = content;
        }
    }
}

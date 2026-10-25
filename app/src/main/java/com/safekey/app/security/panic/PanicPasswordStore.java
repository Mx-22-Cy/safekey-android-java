package com.safekey.app.security.panic;

import android.content.Context;

import java.io.File;
import java.io.IOException;
import java.util.Objects;

/** Verifier persistence only; enrollment authorization belongs to the service. */
public final class PanicPasswordStore implements PanicPasswordService.Store {
    static final String FILE_NAME = "safekey_panic_password.enc";
    private static final Object LOCK = new Object();
    private final File file;

    public PanicPasswordStore(Context context) {
        this(context, FILE_NAME);
    }

    // Only tests in this package can select an isolated proof file.
    PanicPasswordStore(Context context, String fileName) {
        Objects.requireNonNull(context, "context");
        if (!FILE_NAME.equals(fileName)
                && (fileName == null
                || !fileName.matches("safekey_panic_test_[A-Za-z0-9_-]+\\.enc"))) {
            throw new IllegalArgumentException("Invalid Panic proof name.");
        }
        file = new File(Objects.requireNonNull(
                context.getApplicationContext().getNoBackupFilesDir(), "noBackupFilesDir"),
                fileName);
    }

    @Override
    public Object transactionLock() { return LOCK; }

    @Override
    public PanicPasswordCrypto.Record load() throws IOException {
        synchronized (LOCK) {
            if (!PanicFiles.anyExists(PanicFiles.atomicArtifacts(file))) { return null; }
            try {
                return PanicPasswordCrypto.Record.decode(
                        PanicFiles.readExact(file, PanicPasswordCrypto.Record.ENCODED_LENGTH));
            } catch (IllegalArgumentException invalidRecord) {
                throw new IOException("Stored Panic proof is invalid.", invalidRecord);
            }
        }
    }

    @Override
    public void save(PanicPasswordCrypto.Record record) throws IOException {
        Objects.requireNonNull(record, "record");
        synchronized (LOCK) { PanicFiles.writeExact(file, record.encode()); }
    }
}

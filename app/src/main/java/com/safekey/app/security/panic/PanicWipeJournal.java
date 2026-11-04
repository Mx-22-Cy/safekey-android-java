package com.safekey.app.security.panic;

import android.content.Context;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** The no-backup marker is retained until every cleanup verification passes. */
public final class PanicWipeJournal implements PanicWipeCoordinator.Journal {
    static final String FILE_NAME = "safekey_panic_wipe.pending";
    private static final byte[] PENDING = "safekey:panic-wipe:v1\n"
            .getBytes(StandardCharsets.US_ASCII);
    private static final Object LOCK = new Object();
    private final File file;

    public PanicWipeJournal(Context context) { this(context, FILE_NAME); }

    PanicWipeJournal(Context context, String fileName) {
        Objects.requireNonNull(context, "context");
        if (!FILE_NAME.equals(fileName)
                && (fileName == null || !fileName.matches(
                "safekey_panic_test_[A-Za-z0-9_-]+\\.pending"))) {
            throw new IllegalArgumentException("Invalid Panic marker name.");
        }
        file = new File(Objects.requireNonNull(
                context.getApplicationContext().getNoBackupFilesDir(), "noBackupFilesDir"),
                fileName);
    }

    @Override
    public boolean isPending() throws IOException {
        synchronized (LOCK) {
            // Partial/corrupted marker artifacts mean recovery, never permission
            // to authenticate. Marker contents do not select wipe targets.
            return PanicFiles.anyExists(PanicFiles.atomicArtifacts(file));
        }
    }

    @Override
    public void markPending() throws IOException {
        synchronized (LOCK) { PanicFiles.writeExact(file, PENDING); }
    }

    @Override
    public void clearPending() throws IOException {
        synchronized (LOCK) { PanicFiles.deleteAll(PanicFiles.atomicArtifacts(file)); }
    }
}

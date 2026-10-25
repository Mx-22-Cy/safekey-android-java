package com.safekey.app.security.panic;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.AtomicFile;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;

/** Internal helpers; no recursive deletion and no user-supplied paths. */
final class PanicFiles {
    private PanicFiles() { }

    static File[] atomicArtifacts(File base) {
        return new File[]{base, new File(base.getPath() + ".bak"),
                new File(base.getPath() + ".new")};
    }

    private static boolean exists(File file) throws IOException {
        try {
            Files.readAttributes(file.toPath(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return true;
        } catch (NoSuchFileException absent) {
            return false;
        }
    }

    static boolean anyExists(File[] files) throws IOException {
        for (File file : files) {
            if (exists(file)) { return true; }
        }
        return false;
    }

    static void requireAbsent(File[] files) throws IOException {
        if (anyExists(files)) {
            throw new IOException("Panic storage artifact remains.");
        }
    }

    static void deleteAll(File[] files) throws IOException {
        IOException failure = new IOException("Unable to remove Panic storage artifacts.");
        for (File file : files) {
            try {
                if (exists(file) && !file.delete()) {
                    throw new IOException("Storage deletion failed.");
                }
            } catch (IOException | SecurityException error) {
                failure.addSuppressed(error);
            }
        }
        for (File file : files) {
            try {
                syncDirectory(file.getParentFile());
            } catch (IOException error) {
                failure.addSuppressed(error);
            }
        }
        if (failure.getSuppressed().length != 0) { throw failure; }
        requireAbsent(files);
    }

    static byte[] readExact(File file, int length) throws IOException {
        byte[] bytes = new byte[length];
        try (FileInputStream input = new AtomicFile(file).openRead()) {
            int offset = 0;
            while (offset < length) {
                int count = input.read(bytes, offset, length - offset);
                if (count < 0) { throw new IOException("Stored Panic data is truncated."); }
                offset += count;
            }
            if (input.read() != -1) { throw new IOException("Stored Panic data is oversized."); }
        }
        return bytes;
    }

    static void writeExact(File file, byte[] bytes) throws IOException {
        AtomicFile atomicFile = new AtomicFile(file);
        FileOutputStream output = null;
        try {
            output = atomicFile.startWrite();
            output.write(bytes);
            output.getFD().sync();
            atomicFile.finishWrite(output);
            output = null;
            syncDirectory(file.getParentFile());
            if (!Arrays.equals(bytes, readExact(file, bytes.length))) {
                throw new IOException("Unable to verify saved Panic data.");
            }
        } finally {
            if (output != null) { atomicFile.failWrite(output); }
        }
    }

    private static void syncDirectory(File directory) throws IOException {
        if (directory == null || !exists(directory)) { return; }
        FileDescriptor descriptor = null;
        try {
            descriptor = Os.open(directory.getPath(),
                    OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW, 0);
            if (!OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)) {
                throw new IOException("Panic storage parent is not a directory.");
            }
            Os.fsync(descriptor);
        } catch (ErrnoException error) {
            throw new IOException("Unable to sync Panic storage directory.", error);
        } finally {
            if (descriptor != null) {
                try {
                    Os.close(descriptor);
                } catch (ErrnoException error) {
                    throw new IOException("Unable to close Panic directory handle.", error);
                }
            }
        }
    }
}

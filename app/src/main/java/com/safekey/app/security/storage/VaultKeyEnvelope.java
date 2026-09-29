package com.safekey.app.security.storage;

import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import java.util.Arrays;
import java.util.Objects;

public final class VaultKeyEnvelope {

    public static final int CURRENT_FORMAT_VERSION = 1;

    private final int formatVersion;
    private final byte[] salt;
    private final String wrappedDatabaseKey;

    public VaultKeyEnvelope(
            byte[] salt,
            String wrappedDatabaseKey
    ) {
        this(
                CURRENT_FORMAT_VERSION,
                salt,
                wrappedDatabaseKey
        );
    }

    public VaultKeyEnvelope(
            int formatVersion,
            byte[] salt,
            String wrappedDatabaseKey
    ) {
        if (formatVersion != CURRENT_FORMAT_VERSION) {
            throw new IllegalArgumentException(
                    "Unsupported vault key envelope version: "
                            + formatVersion
                            + "."
            );
        }

        Objects.requireNonNull(
                salt,
                "salt"
        );

        Objects.requireNonNull(
                wrappedDatabaseKey,
                "wrappedDatabaseKey"
        );

        if (
                salt.length
                        != Argon2idMasterKeyDeriver
                        .SALT_LENGTH_BYTES
        ) {
            throw new IllegalArgumentException(
                    "Salt must contain exactly "
                            + Argon2idMasterKeyDeriver
                            .SALT_LENGTH_BYTES
                            + " bytes."
            );
        }

        if (wrappedDatabaseKey.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Wrapped database key must not be empty."
            );
        }

        this.formatVersion =
                formatVersion;

        this.salt =
                Arrays.copyOf(
                        salt,
                        salt.length
                );

        this.wrappedDatabaseKey =
                wrappedDatabaseKey;
    }

    public int getFormatVersion() {
        return formatVersion;
    }

    public byte[] getSalt() {
        return Arrays.copyOf(
                salt,
                salt.length
        );
    }

    public String getWrappedDatabaseKey() {
        return wrappedDatabaseKey;
    }
}

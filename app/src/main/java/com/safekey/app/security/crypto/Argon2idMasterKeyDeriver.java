package com.safekey.app.security.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public final class Argon2idMasterKeyDeriver
        implements MasterKeyDeriver {

    public static final int SALT_LENGTH_BYTES = 16;
    public static final int DERIVED_KEY_LENGTH_BYTES = 32;
    public static final int MEMORY_KIB = 19 * 1024;
    public static final int ITERATIONS = 2;
    public static final int PARALLELISM = 1;

    private final SecureRandom secureRandom;

    public Argon2idMasterKeyDeriver() {
        this(new SecureRandom());
    }

    Argon2idMasterKeyDeriver(
            SecureRandom secureRandom
    ) {
        this.secureRandom =
                Objects.requireNonNull(
                        secureRandom,
                        "secureRandom"
                );
    }

    public byte[] generateSalt() {
        byte[] salt =
                new byte[SALT_LENGTH_BYTES];

        secureRandom.nextBytes(salt);

        return salt;
    }

    @Override
    public byte[] deriveKey(
            char[] masterPassword,
            byte[] salt
    ) {
        Objects.requireNonNull(
                masterPassword,
                "masterPassword"
        );

        Objects.requireNonNull(
                salt,
                "salt"
        );

        if (masterPassword.length == 0) {
            throw new IllegalArgumentException(
                    "Master password must not be empty."
            );
        }

        if (salt.length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "Salt must contain exactly "
                            + SALT_LENGTH_BYTES
                            + " bytes."
            );
        }

        byte[] saltCopy =
                Arrays.copyOf(
                        salt,
                        salt.length
                );

        byte[] derivedKey =
                new byte[DERIVED_KEY_LENGTH_BYTES];

        Argon2Parameters.Builder parameterBuilder =
                new Argon2Parameters.Builder(
                        Argon2Parameters.ARGON2_id
                )
                        .withVersion(
                                Argon2Parameters.ARGON2_VERSION_13
                        )
                        .withMemoryAsKB(MEMORY_KIB)
                        .withIterations(ITERATIONS)
                        .withParallelism(PARALLELISM)
                        .withSalt(saltCopy);

        try {
            Argon2BytesGenerator generator =
                    new Argon2BytesGenerator();

            generator.init(
                    parameterBuilder.build()
            );

            generator.generateBytes(
                    masterPassword,
                    derivedKey
            );

            return derivedKey;

        } catch (RuntimeException exception) {
            Arrays.fill(
                    derivedKey,
                    (byte) 0
            );

            throw exception;

        } finally {
            parameterBuilder.clear();

            Arrays.fill(
                    saltCopy,
                    (byte) 0
            );
        }
    }
}

package com.safekey.app.data.database;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class SqlCipherKeyEncoderTest {

    @Test
    public void encode_knownKey_returnsSqlCipherRawKeyLiteral() {
        byte[] databaseKey =
                new byte[
                        SqlCipherKeyEncoder
                                .DATABASE_KEY_LENGTH_BYTES
                        ];

        for (
                int index = 0;
                index < databaseKey.length;
                index++
        ) {
            databaseKey[index] =
                    (byte) index;
        }

        byte[] encodedKey =
                SqlCipherKeyEncoder.encode(
                        databaseKey
                );

        assertEquals(
                "x'000102030405060708090A0B0C0D0E0F"
                        + "101112131415161718191A1B1C1D1E1F'",
                new String(
                        encodedKey,
                        StandardCharsets.US_ASCII
                )
        );
    }

    @Test
    public void encode_highBitBytes_usesUnsignedHexValues() {
        byte[] databaseKey =
                new byte[
                        SqlCipherKeyEncoder
                                .DATABASE_KEY_LENGTH_BYTES
                        ];

        Arrays.fill(
                databaseKey,
                (byte) 0xFF
        );

        byte[] encodedKey =
                SqlCipherKeyEncoder.encode(
                        databaseKey
                );

        assertEquals(
                "x'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'",
                new String(
                        encodedKey,
                        StandardCharsets.US_ASCII
                )
        );
    }

    @Test
    public void encode_doesNotModifyOriginalKey() {
        byte[] databaseKey =
                new byte[
                        SqlCipherKeyEncoder
                                .DATABASE_KEY_LENGTH_BYTES
                        ];

        for (
                int index = 0;
                index < databaseKey.length;
                index++
        ) {
            databaseKey[index] =
                    (byte) (
                            255 - index
                    );
        }

        byte[] originalKey =
                Arrays.copyOf(
                        databaseKey,
                        databaseKey.length
                );

        SqlCipherKeyEncoder.encode(
                databaseKey
        );

        assertArrayEquals(
                originalKey,
                databaseKey
        );
    }

    @Test
    public void encode_nullKey_throwsIllegalArgumentException() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                SqlCipherKeyEncoder.encode(
                                        null
                                )
                );

        assertEquals(
                "Database key cannot be null.",
                exception.getMessage()
        );
    }

    @Test
    public void encode_shortKey_throwsIllegalArgumentException() {
        byte[] databaseKey =
                new byte[
                        SqlCipherKeyEncoder
                                .DATABASE_KEY_LENGTH_BYTES
                                - 1
                        ];

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                SqlCipherKeyEncoder.encode(
                                        databaseKey
                                )
                );

        assertEquals(
                "Database key must contain exactly 32 bytes.",
                exception.getMessage()
        );
    }

    @Test
    public void encode_longKey_throwsIllegalArgumentException() {
        byte[] databaseKey =
                new byte[
                        SqlCipherKeyEncoder
                                .DATABASE_KEY_LENGTH_BYTES
                                + 1
                        ];

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                SqlCipherKeyEncoder.encode(
                                        databaseKey
                                )
                );

        assertEquals(
                "Database key must contain exactly 32 bytes.",
                exception.getMessage()
        );
    }
}

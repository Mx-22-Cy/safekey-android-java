package com.safekey.app.data.database;

final class SqlCipherKeyEncoder {

    static final int DATABASE_KEY_LENGTH_BYTES =
            SafeKeyDatabase.DATABASE_KEY_LENGTH_BYTES;

    private static final byte[] HEX_DIGITS = {
            '0', '1', '2', '3',
            '4', '5', '6', '7',
            '8', '9', 'A', 'B',
            'C', 'D', 'E', 'F'
    };

    private static final int ENCODED_KEY_LENGTH_BYTES =
            2
                    + (DATABASE_KEY_LENGTH_BYTES * 2)
                    + 1;

    private SqlCipherKeyEncoder() {
        // Utility class.
    }

    static byte[] encode(
            byte[] databaseKey
    ) {
        if (databaseKey == null) {
            throw new IllegalArgumentException(
                    "Database key cannot be null."
            );
        }

        if (
                databaseKey.length
                        != DATABASE_KEY_LENGTH_BYTES
        ) {
            throw new IllegalArgumentException(
                    "Database key must contain exactly "
                            + DATABASE_KEY_LENGTH_BYTES
                            + " bytes."
            );
        }

        byte[] encodedKey =
                new byte[ENCODED_KEY_LENGTH_BYTES];

        encodedKey[0] = 'x';
        encodedKey[1] = '\'';

        int outputIndex = 2;

        for (byte value : databaseKey) {
            int unsignedValue =
                    value & 0xFF;

            encodedKey[outputIndex] =
                    HEX_DIGITS[
                            unsignedValue >>> 4
                            ];

            outputIndex++;

            encodedKey[outputIndex] =
                    HEX_DIGITS[
                            unsignedValue & 0x0F
                            ];

            outputIndex++;
        }

        encodedKey[outputIndex] = '\'';

        return encodedKey;
    }
}

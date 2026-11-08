package com.safekey.app.security.storage;

import com.safekey.app.security.crypto.AesGcmCipher;
import com.safekey.app.security.crypto.AesGcmException;
import com.safekey.app.security.crypto.Argon2idMasterKeyDeriver;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class RecoveryKeyProtectorTest {

    private final RecoveryKeyProtector protector = new RecoveryKeyProtector(
            new Argon2idMasterKeyDeriver(), new AesGcmCipher(), new SecureRandom());

    @Test
    public void generatedKeyRecoversOriginalDatabaseKey() throws Exception {
        char[] recoveryKey = protector.generateRecoveryKey();
        byte[] databaseKey = new byte[32];
        Arrays.fill(databaseKey, (byte) 42);
        byte[] recovered = null;
        try {
            assertEquals(32, recoveryKey.length);
            VaultKeyEnvelope envelope = protector.wrap(recoveryKey, databaseKey);
            recovered = protector.unwrap(recoveryKey, envelope);
            assertArrayEquals(databaseKey, recovered);
        } finally {
            Arrays.fill(recoveryKey, '\0');
            Arrays.fill(databaseKey, (byte) 0);
            if (recovered != null) {
                Arrays.fill(recovered, (byte) 0);
            }
        }
    }

    @Test
    public void differentValidRecoveryKeyIsRejected() throws Exception {
        char[] recoveryKey = protector.generateRecoveryKey();
        byte[] databaseKey = new byte[32];
        try {
            VaultKeyEnvelope envelope = protector.wrap(recoveryKey, databaseKey);
            recoveryKey[0] = recoveryKey[0] == '0' ? '1' : '0';
            try {
                byte[] unexpectedKey = protector.unwrap(recoveryKey, envelope);
                Arrays.fill(unexpectedKey, (byte) 0);
                fail("A different Recovery key unwrapped the envelope.");
            } catch (AesGcmException expected) {
                // A well-formed but incorrect key must fail authentication.
            }
        } finally {
            Arrays.fill(recoveryKey, '\0');
            Arrays.fill(databaseKey, (byte) 0);
        }
    }
}

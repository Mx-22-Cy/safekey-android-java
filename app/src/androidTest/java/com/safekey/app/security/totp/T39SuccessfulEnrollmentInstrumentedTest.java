package com.safekey.app.security.totp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Repeatable test of successful encrypted TOTP enrollment using ONLY test-owned state.
 * This verifies the service/storage path. It does not replace the separate real UI flow test.
 */
@RunWith(AndroidJUnit4.class)
public class T39SuccessfulEnrollmentInstrumentedTest {
    private static final String TEST_ALIAS = "safekey_totp_t39_success_test_v1";
    private static final String TEST_FILE = "safekey_totp_t39_success_test_v1.enc";

    private TotpSecretStore testStore;
    private TotpSecretStore productionStore;
    private boolean productionWasConfigured;

    @Before
    public void setUp() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        productionStore = new TotpSecretStore(context);
        productionWasConfigured = productionStore.isConfigured();
        testStore = new TotpSecretStore(context, TEST_ALIAS, TEST_FILE);
        // The dedicated alias and filename are owned by this test class alone.
        testStore.clear();
    }

    @After
    public void tearDown() throws Exception {
        try {
            if (testStore != null) testStore.clear();
        } finally {
            if (productionStore != null) {
                assertEquals("Test modified production TOTP configuration",
                        productionWasConfigured, productionStore.isConfigured());
            }
        }
    }

    @Test
    public void validTotpCodeEnablesIsolatedEncryptedEnrollment() throws Exception {
        assertFalse("Isolated TOTP store should start empty", testStore.isConfigured());
        TotpEnrollmentService enrollment = new TotpEnrollmentService(testStore,
                new SecureRandom(), System::currentTimeMillis,
                android.os.SystemClock::elapsedRealtime);
        try (TotpEnrollmentService.PendingSetup setup = enrollment.begin()) {
            assertNotNull(setup);
            char[] encoded = setup.copyBase32Secret();
            byte[] secret = null;
            char[] code = null;
            try {
                secret = decodeBase32(encoded);
                assertEquals(20, secret.length);
                code = TotpGenerator.generate(secret,
                        System.currentTimeMillis() / 1000L).toCharArray();
                assertEquals(TotpEnrollmentService.Confirmation.ENABLED,
                        enrollment.confirm(setup, code));
                assertTrue("Enabled TOTP not persisted", testStore.isConfigured());
                assertNotNull("Encrypted TOTP state cannot be reloaded",
                        new TotpSecretStore(
                                InstrumentationRegistry.getInstrumentation().getTargetContext(),
                                TEST_ALIAS, TEST_FILE).load());
            } finally {
                Arrays.fill(encoded, '\0');
                if (secret != null) Arrays.fill(secret, (byte) 0);
                if (code != null) Arrays.fill(code, '\0');
            }
        }
    }

    private static byte[] decodeBase32(char[] encoded) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : encoded) {
            int value;
            if (c >= 'A' && c <= 'Z') value = c - 'A';
            else if (c >= '2' && c <= '7') value = c - '2' + 26;
            else throw new IllegalArgumentException("Invalid Base32 character");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                output.write((buffer >>> bits) & 255);
            }
        }
        return output.toByteArray();
    }
}

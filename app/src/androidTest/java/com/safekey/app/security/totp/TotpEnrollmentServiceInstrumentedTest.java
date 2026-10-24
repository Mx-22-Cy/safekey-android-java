package com.safekey.app.security.totp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

@RunWith(AndroidJUnit4.class)
public class TotpEnrollmentServiceInstrumentedTest {

    private static final String TEST_ALIAS =
            "safekey_totp_enrollment_instrumented_key";
    private static final String TEST_FILE =
            "safekey_totp_enrollment_instrumented.enc";

    // Public RFC test data only.
    private static final byte[] TEST_SECRET =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private Context context;
    private TotpSecretStore store;
    private AtomicLong wall;
    private TotpEnrollmentService service;

    @Before
    public void setUp() throws Exception {
        context = InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
        store = newStore();
        store.clear();
        wall = new AtomicLong(59_000L);
        service = new TotpEnrollmentService(
                store, new FixedRandom(), wall::get, () -> 0L
        );
    }

    @After
    public void tearDown() throws Exception {
        if (store != null) {
            store.clear();
        }
    }

    @Test
    public void confirmedEnrollment_persistsAndConsumesSetupCode() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            assertEquals(TotpEnrollmentService.Confirmation.ENABLED,
                    service.confirm(pending, "287082".toCharArray()));
            assertFalse(pending.isActive());
        }

        try (TotpState saved = newStore().load()) {
            byte[] secret = saved.copySecret();
            try {
                assertArrayEquals(TEST_SECRET, secret);
                assertEquals(1L, saved.getLastAcceptedStep());
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
        }

        TotpVerificationService verifier =
                new TotpVerificationService(newStore(), wall::get);

        assertEquals(TotpVerificationService.Status.INVALID_CODE,
                verifier.verify("287082".toCharArray()).getStatus());

        wall.set(89_000L);

        assertEquals(TotpVerificationService.Status.VERIFIED,
                verifier.verify("359152".toCharArray()).getStatus());
    }

    @Test
    public void cancelledSetup_doesNotEnableTotp() throws Exception {
        TotpEnrollmentService.PendingSetup pending = service.begin();
        pending.close();

        assertEquals(TotpEnrollmentService.Confirmation.CANCELLED,
                service.confirm(pending, "287082".toCharArray()));
        assertFalse(store.isConfigured());
        assertNull(store.load());
    }

    @Test
    public void wrongConfirmation_doesNotPersistSecret() throws Exception {
        try (TotpEnrollmentService.PendingSetup pending = service.begin()) {
            assertEquals(TotpEnrollmentService.Confirmation.INVALID_CODE,
                    service.confirm(pending, "000000".toCharArray()));
            assertFalse(store.isConfigured());
            assertNull(store.load());
        }
    }

    @Test
    public void anotherPendingSetup_cannotOverwriteEncryptedConfiguration()
            throws Exception {
        try (TotpEnrollmentService.PendingSetup first = service.begin();
             TotpEnrollmentService.PendingSetup second = service.begin()) {
            service.confirm(first, "287082".toCharArray());

            File file = new File(context.getNoBackupFilesDir(), TEST_FILE);
            byte[] before = Files.readAllBytes(file.toPath());

            assertEquals(TotpEnrollmentService.Confirmation.ALREADY_CONFIGURED,
                    service.confirm(second, "287082".toCharArray()));
            assertArrayEquals(before, Files.readAllBytes(file.toPath()));
        }
    }

    private TotpSecretStore newStore() {
        return new TotpSecretStore(context, TEST_ALIAS, TEST_FILE);
    }

    private static final class FixedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(TEST_SECRET, 0, bytes, 0, bytes.length);
        }
    }
}

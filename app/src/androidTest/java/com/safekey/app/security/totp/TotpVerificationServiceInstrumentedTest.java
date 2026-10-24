package com.safekey.app.security.totp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@RunWith(AndroidJUnit4.class)
public class TotpVerificationServiceInstrumentedTest {

    private static final String TEST_ALIAS =
            "safekey_totp_verification_instrumented_key";

    private static final String TEST_FILE =
            "safekey_totp_verification_instrumented.enc";

    // Public RFC test data only.
    private static final byte[] TEST_SECRET =
            "12345678901234567890"
                    .getBytes(StandardCharsets.US_ASCII);

    private Context context;
    private TotpSecretStore store;
    private AtomicLong timeMillis;
    private TotpVerificationService service;

    @Before
    public void setUp() throws Exception {
        context = InstrumentationRegistry.getInstrumentation()
                .getTargetContext()
                .getApplicationContext();

        store = newStore();
        store.clear();

        timeMillis = new AtomicLong(59_000L);

        try (TotpState state =
                     new TotpState(TEST_SECRET, -1L, 0, 0L)) {
            store.save(state);
        }

        service = newService();
    }

    @After
    public void tearDown() throws Exception {
        if (store != null) {
            store.clear();
        }
    }

    @Test
    public void newServiceAndStore_rejectPreviouslyAcceptedCode()
            throws Exception {
        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify("287082").getStatus()
        );

        service = newService();

        assertEquals(
                TotpVerificationService.Status.INVALID_CODE,
                verify("287082").getStatus()
        );

        try (TotpState saved = newStore().load()) {
            assertEquals(1L, saved.getLastAcceptedStep());
        }
    }

    @Test
    public void cooldown_survivesNewServiceAndStore()
            throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            verify("000000");
        }

        service = newService();

        TotpVerificationService.Result blocked =
                verify("287082");

        assertEquals(
                TotpVerificationService.Status.RETRY_LATER,
                blocked.getStatus()
        );

        assertEquals(
                30_000L,
                blocked.getRetryAfterMillis()
        );

        timeMillis.set(89_000L);

        assertEquals(
                TotpVerificationService.Status.VERIFIED,
                verify("359152").getStatus()
        );

        try (TotpState saved = newStore().load()) {
            assertEquals(2L, saved.getLastAcceptedStep());
            assertEquals(0, saved.getFailedAttempts());

            assertEquals(
                    0L,
                    saved.getBlockedUntilEpochMillis()
            );
        }
    }

    @Test
    public void corruptState_isNotTreatedAsSuccessfulOrDisabledTotp()
            throws Exception {
        File file = new File(
                context.getNoBackupFilesDir(),
                TEST_FILE
        );

        byte[] encrypted =
                Files.readAllBytes(file.toPath());

        encrypted[encrypted.length - 1] ^= 1;

        Files.write(file.toPath(), encrypted);

        try {
            verify("287082");

            fail(
                    "Unreadable TOTP state must keep authentication locked."
            );
        } catch (GeneralSecurityException | IOException expected) {
            // No verification result was returned.
        }
    }

    @Test
    public void separateServices_cannotAcceptSameCodeConcurrently()
            throws Exception {
        ExecutorService workers =
                Executors.newFixedThreadPool(2);

        CountDownLatch start = new CountDownLatch(1);

        try {
            Future<TotpVerificationService.Status> first =
                    workers.submit(() -> {
                        start.await();

                        return newService()
                                .verify("287082".toCharArray())
                                .getStatus();
                    });

            Future<TotpVerificationService.Status> second =
                    workers.submit(() -> {
                        start.await();

                        return newService()
                                .verify("287082".toCharArray())
                                .getStatus();
                    });

            start.countDown();

            TotpVerificationService.Status a =
                    first.get(20, TimeUnit.SECONDS);

            TotpVerificationService.Status b =
                    second.get(20, TimeUnit.SECONDS);

            int accepted =
                    (a == TotpVerificationService.Status.VERIFIED
                            ? 1 : 0)
                            + (b == TotpVerificationService.Status.VERIFIED
                            ? 1 : 0);

            assertEquals(1, accepted);

            try (TotpState saved = newStore().load()) {
                assertEquals(1L, saved.getLastAcceptedStep());
                assertEquals(1, saved.getFailedAttempts());
            }
        } finally {
            workers.shutdownNow();
        }
    }

    private TotpSecretStore newStore() {
        return new TotpSecretStore(
                context,
                TEST_ALIAS,
                TEST_FILE
        );
    }

    private TotpVerificationService newService() {
        return new TotpVerificationService(
                newStore(),
                timeMillis::get
        );
    }

    private TotpVerificationService.Result verify(String code)
            throws Exception {
        return service.verify(code.toCharArray());
    }
}

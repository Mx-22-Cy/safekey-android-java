package com.safekey.app.security.storage;

import com.safekey.app.security.results.AndroidCredentialSecurity;
import com.safekey.app.security.results.CredentialSecurityController;
import com.safekey.app.security.results.CredentialSecuritySummary;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.DecoyVaultCoordinator;
import com.safekey.app.security.storage.DecoyVaultStorage;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.security.storage.VaultOperations;
import com.safekey.app.security.totp.TotpSecretStore;
import com.safekey.app.session.SafeKeySession;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class ActiveVaultSecurityInstrumentedTest {

    private static final long TIMEOUT_SECONDS = 45;

    private static final String REAL_PASSWORD =
            "real vault integration password 2026";

    private static final String DECOY_PASSWORD =
            "decoy vault integration password 2026";

    private static final String DESTRUCTIVE_TEST_FLAG =
            "allowDestructiveActiveVaultSecurityTests";

    private Context context;
    private SafeKeyApplication application;

    private CredentialSecurityController realController;
    private CredentialSecurityController decoyController;

    private boolean destructiveTestEnabled;

    @Before
    public void setUp() throws Exception {

        // Never delete vault data unless the test runner
        // explicitly authorizes destructive testing.
        String permission =
                InstrumentationRegistry.getArguments()
                        .getString(DESTRUCTIVE_TEST_FLAG);

        Assume.assumeTrue(
                "This test requires a disposable SafeKey installation.",
                "true".equalsIgnoreCase(permission));

        context = InstrumentationRegistry.getInstrumentation()
                .getTargetContext()
                .getApplicationContext();

        application = (SafeKeyApplication) context;

        destructiveTestEnabled = true;

        application.registerSessionCleanup();

        SafeKeySession.unlockAfterAuthentication();
        SafeKeySession.lock();

        awaitAuthenticationReady();

        clearStoredTestVaults();

        DecoyVaultStorage.ensureDatabaseFile(context);
    }

    @After
    public void tearDown() throws Exception {

        if (!destructiveTestEnabled) {
            return;
        }

        InstrumentationRegistry.getInstrumentation()
                .runOnMainSync(() -> {

                    if (realController != null) {
                        realController.close();
                        realController = null;
                    }

                    if (decoyController != null) {
                        decoyController.close();
                        decoyController = null;
                    }
                });

        SafeKeySession.lock();

        application.registerSessionCleanup();

        // Wait until database connections are closed
        // before deleting the disposable test data.
        awaitAuthenticationReady();

        clearStoredTestVaults();

        DecoyVaultStorage.ensureDatabaseFile(context);
    }

    @Test
    public void realAndDecoySecurityResultsRemainIsolated()
            throws Exception {

        SecureVaultCoordinator real =
                application.getSecureVaultCoordinator();

        char[] realPassword =
                REAL_PASSWORD.toCharArray();

        try {
            awaitSimple(callback ->
                    real.createVault(
                            realPassword,
                            callback));
        } finally {
            Arrays.fill(realPassword, '\0');
        }

        activateReal();

        assertEquals(
                SafeKeyApplication.ActiveVault.REAL,
                application.getActiveVault());

        VaultOperations realOperations =
                application.getActiveVaultOperations();

        Long breachedId = this.<Long>awaitResult(
                callback ->
                        realOperations.addCredential(
                                new Credential(
                                        "Real breached credential",
                                        "real@example.com",
                                        "real-weak-password",
                                        "https://real.example.com",
                                        "Work",
                                        ""),
                                callback));

        assertNotNull(breachedId);

        this.<Long>awaitResult(
                callback ->
                        realOperations.addCredential(
                                new Credential(
                                        "Real second credential",
                                        "second@example.com",
                                        "real-second-password",
                                        "https://second.example.com",
                                        "Personal",
                                        ""),
                                callback));

        // Save a known breach result in the Real Vault.
        this.<PasswordBreachResult.Status>awaitResult(
                callback ->
                        real.updateCredentialBreachStatus(
                                real.getVaultGeneration(),
                                breachedId,
                                "real-weak-password",
                                PasswordBreachResult.Status.BREACHED,
                                callback));

        realController =
                AndroidCredentialSecurity.createForActiveVault(
                        application,
                        false);

        CredentialSecuritySummary realSummary =
                awaitSummary(realController);

        assertEquals(
                2,
                realSummary.getTotalCount());

        assertEquals(
                1,
                realSummary.getBreachCount());

        // End the Real Vault session.
        SafeKeySession.lock();

        awaitAuthenticationReady();

        assertEquals(
                SafeKeyApplication.ActiveVault.NONE,
                application.getActiveVault());

        // Create and authenticate the Decoy Vault.
        DecoyVaultCoordinator decoy =
                application.getDecoyVaultCoordinator();

        char[] decoyPassword =
                DECOY_PASSWORD.toCharArray();

        try {
            awaitSimple(callback ->
                    decoy.createDecoyVault(
                            decoyPassword,
                            callback));

            awaitSimple(decoy::closeDecoyVault);

            awaitSimple(callback ->
                    decoy.unlockDecoyVault(
                            decoyPassword,
                            callback));

        } finally {
            Arrays.fill(decoyPassword, '\0');
        }

        activateDecoy();

        assertEquals(
                SafeKeyApplication.ActiveVault.DECOY,
                application.getActiveVault());

        VaultOperations decoyOperations =
                application.getActiveVaultOperations();

        this.<Long>awaitResult(
                callback ->
                        decoyOperations.addCredential(
                                new Credential(
                                        "Decoy-only credential",
                                        "decoy@example.com",
                                        "decoy-password",
                                        "https://decoy.example.com",
                                        "Personal",
                                        ""),
                                callback));

        // Requesting breach checks must not enable
        // network checks or breach persistence in Decoy.
        decoyController =
                AndroidCredentialSecurity.createForActiveVault(
                        application,
                        true);

        CredentialSecuritySummary decoySummary =
                awaitSummary(decoyController);

        assertEquals(
                "Decoy must contain only its own credential",
                1,
                decoySummary.getTotalCount());

        assertEquals(
                "Real breach results must not appear in Decoy",
                0,
                decoySummary.getBreachCount());

        InstrumentationRegistry.getInstrumentation()
                .runOnMainSync(decoyController::checkAll);

        // Verify an old Real controller cannot publish
        // results after Decoy authentication.
        CountDownLatch rejected =
                new CountDownLatch(1);

        AtomicBoolean staleResults =
                new AtomicBoolean(false);

        InstrumentationRegistry.getInstrumentation()
                .runOnMainSync(() ->
                        realController.load(
                                new CredentialSecurityController.Listener() {

                                    @Override
                                    public void onResults(
                                            CredentialSecuritySummary summary) {

                                        staleResults.set(true);
                                        rejected.countDown();
                                    }

                                    @Override
                                    public void onError(Exception error) {

                                        rejected.countDown();
                                    }
                                },
                                false));

        assertTrue(
                "Old Real controller was not rejected",
                rejected.await(
                        TIMEOUT_SECONDS,
                        TimeUnit.SECONDS));

        assertFalse(
                "Old Real results must not appear in Decoy",
                staleResults.get());
    }

    private void clearStoredTestVaults() throws Exception {

        // Clear the primary key envelope using SafeKey's
        // existing storage cleanup implementation.
        new VaultKeyEnvelopeStore(context).clear();

        new TotpSecretStore(context).clear();

        // Clear Decoy enrollment preferences.
        boolean clearedDecoyPreferences =
                context.getSharedPreferences(
                                VaultKeyEnvelopeStore.DECOY_PREFERENCES_NAME,
                                Context.MODE_PRIVATE)
                        .edit()
                        .clear()
                        .commit();

        assertTrue(
                "Could not clear Decoy test preferences",
                clearedDecoyPreferences);

        // Delete only the two disposable SafeKey databases.
        context.deleteDatabase("safekey.db");

        context.deleteDatabase(
                DecoyVaultStorage.DATABASE_NAME);
    }

    private void activateReal() {

        InstrumentationRegistry.getInstrumentation()
                .runOnMainSync(() -> {

                    SafeKeySession.unlockAfterAuthentication();

                    application.activateRealVault();
                });
    }

    private void activateDecoy() {

        InstrumentationRegistry.getInstrumentation()
                .runOnMainSync(() -> {

                    SafeKeySession.unlockAfterAuthentication();

                    application.activateDecoyVault();
                });
    }

    private CredentialSecuritySummary awaitSummary(
            CredentialSecurityController controller)
            throws Exception {

        CountDownLatch completed =
                new CountDownLatch(1);

        AtomicReference<CredentialSecuritySummary> summary =
                new AtomicReference<>();

        AtomicReference<Exception> error =
                new AtomicReference<>();

        InstrumentationRegistry.getInstrumentation()
                .runOnMainSync(() ->
                        controller.load(
                                new CredentialSecurityController.Listener() {

                                    @Override
                                    public void onResults(
                                            CredentialSecuritySummary result) {

                                        summary.set(result);
                                        completed.countDown();
                                    }

                                    @Override
                                    public void onError(Exception exception) {

                                        error.set(exception);
                                        completed.countDown();
                                    }
                                },
                                false));

        assertTrue(
                "Security summary timed out",
                completed.await(
                        TIMEOUT_SECONDS,
                        TimeUnit.SECONDS));

        assertNull(
                "Security analysis failed",
                error.get());

        assertNotNull(
                "Missing security summary",
                summary.get());

        return summary.get();
    }

    private void awaitAuthenticationReady()
            throws Exception {

        awaitSimple(
                application::prepareForVaultAuthentication);
    }

    private interface SimpleOperation {

        void execute(
                VaultDataService.SimpleCallback callback);
    }

    private void awaitSimple(
            SimpleOperation operation)
            throws Exception {

        CountDownLatch completed =
                new CountDownLatch(1);

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.execute(
                new VaultDataService.SimpleCallback() {

                    @Override
                    public void onSuccess() {
                        completed.countDown();
                    }

                    @Override
                    public void onError(Exception exception) {

                        error.set(exception);
                        completed.countDown();
                    }
                });

        assertTrue(
                "Vault operation timed out",
                completed.await(
                        TIMEOUT_SECONDS,
                        TimeUnit.SECONDS));

        assertNull(
                "Vault operation failed",
                error.get());
    }

    private interface ResultOperation<T> {

        void execute(
                VaultDataService.ResultCallback<T> callback);
    }

    private <T> T awaitResult(
            ResultOperation<T> operation)
            throws Exception {

        CountDownLatch completed =
                new CountDownLatch(1);

        AtomicReference<T> value =
                new AtomicReference<>();

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.execute(
                new VaultDataService.ResultCallback<T>() {

                    @Override
                    public void onSuccess(T result) {

                        value.set(result);
                        completed.countDown();
                    }

                    @Override
                    public void onError(Exception exception) {

                        error.set(exception);
                        completed.countDown();
                    }
                });

        assertTrue(
                "Vault result timed out",
                completed.await(
                        TIMEOUT_SECONDS,
                        TimeUnit.SECONDS));

        assertNull(
                "Vault result operation failed",
                error.get());

        return value.get();
    }
}

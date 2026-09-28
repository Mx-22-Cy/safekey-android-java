package com.safekey.app.security.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.crypto.AesGcmException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class SecureVaultCoordinatorInstrumentedTest {

    private static final String DATABASE_NAME =
            "safekey.db";

    private static final long CALLBACK_TIMEOUT_SECONDS =
            30;

    private Context context;

    private SecureVaultCoordinator coordinator;

    @Before
    public void setUp() {
        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        clearStoredVault();

        coordinator =
                new SecureVaultCoordinator(
                        context
                );
    }

    @After
    public void tearDown() {
        shutdownCoordinator();

        clearStoredVault();

        context = null;
    }

    @Test
    public void createCloseAndReopen_withCorrectPassword_succeeds()
            throws Exception {
        char[] masterPassword =
                "correct horse battery staple"
                        .toCharArray();

        awaitSuccess(
                callback ->
                        coordinator.createVault(
                                masterPassword,
                                callback
                        )
        );

        assertTrue(
                coordinator.hasVault()
        );

        assertTrue(
                coordinator.isVaultOpen()
        );

        awaitSuccess(
                coordinator::closeVault
        );

        assertFalse(
                coordinator.isVaultOpen()
        );

        shutdownCoordinator();

        coordinator =
                new SecureVaultCoordinator(
                        context
                );

        assertTrue(
                coordinator.hasVault()
        );

        awaitSuccess(
                callback ->
                        coordinator.unlockVault(
                                masterPassword,
                                callback
                        )
        );

        assertTrue(
                coordinator.isVaultOpen()
        );
    }

    @Test
    public void unlock_withWrongPassword_failsAndKeepsVaultClosed()
            throws Exception {
        char[] correctPassword =
                "correct horse battery staple"
                        .toCharArray();

        char[] wrongPassword =
                "incorrect master password value"
                        .toCharArray();

        awaitSuccess(
                callback ->
                        coordinator.createVault(
                                correctPassword,
                                callback
                        )
        );

        awaitSuccess(
                coordinator::closeVault
        );

        Exception exception =
                awaitError(
                        callback ->
                                coordinator.unlockVault(
                                        wrongPassword,
                                        callback
                                )
                );

        assertTrue(
                exception instanceof AesGcmException
        );

        assertEquals(
                "Unable to decrypt protected data.",
                exception.getMessage()
        );

        assertFalse(
                coordinator.isVaultOpen()
        );
    }

    @Test
    public void unlock_withTamperedEnvelope_failsAndKeepsVaultClosed()
            throws Exception {
        char[] masterPassword =
                "correct horse battery staple"
                        .toCharArray();

        awaitSuccess(
                callback ->
                        coordinator.createVault(
                                masterPassword,
                                callback
                        )
        );

        awaitSuccess(
                coordinator::closeVault
        );

        tamperWithWrappedDatabaseKey();

        Exception exception =
                awaitError(
                        callback ->
                                coordinator.unlockVault(
                                        masterPassword,
                                        callback
                                )
                );

        assertTrue(
                exception instanceof AesGcmException
        );

        assertEquals(
                "Unable to decrypt protected data.",
                exception.getMessage()
        );

        assertFalse(
                coordinator.isVaultOpen()
        );
    }

    @Test
    public void create_whenVaultAlreadyExists_isRejected()
            throws Exception {
        char[] masterPassword =
                "correct horse battery staple"
                        .toCharArray();

        awaitSuccess(
                callback ->
                        coordinator.createVault(
                                masterPassword,
                                callback
                        )
        );

        Exception exception =
                awaitError(
                        callback ->
                                coordinator.createVault(
                                        masterPassword,
                                        callback
                                )
                );

        assertTrue(
                exception instanceof IllegalStateException
        );

        assertEquals(
                "A vault has already been created.",
                exception.getMessage()
        );

        assertTrue(
                coordinator.isVaultOpen()
        );
    }

    @Test
    public void unlock_withoutCreatedVault_isRejected()
            throws Exception {
        char[] masterPassword =
                "correct horse battery staple"
                        .toCharArray();

        Exception exception =
                awaitError(
                        callback ->
                                coordinator.unlockVault(
                                        masterPassword,
                                        callback
                                )
                );

        assertTrue(
                exception instanceof IllegalStateException
        );

        assertEquals(
                "No vault has been created.",
                exception.getMessage()
        );

        assertFalse(
                coordinator.isVaultOpen()
        );
    }

    private void tamperWithWrappedDatabaseKey() {
        SharedPreferences preferences =
                context.getSharedPreferences(
                        VaultKeyEnvelopeStore.PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                );

        String wrappedDatabaseKey =
                preferences.getString(
                        VaultKeyEnvelopeStore
                                .KEY_WRAPPED_DATABASE_KEY,
                        null
                );

        assertNotNull(
                wrappedDatabaseKey
        );

        int ciphertextStart =
                wrappedDatabaseKey.lastIndexOf(
                        '.'
                )
                        + 1;

        char originalCharacter =
                wrappedDatabaseKey.charAt(
                        ciphertextStart
                );

        char replacementCharacter =
                originalCharacter == 'A'
                        ? 'B'
                        : 'A';

        String tamperedValue =
                wrappedDatabaseKey.substring(
                        0,
                        ciphertextStart
                )
                        + replacementCharacter
                        + wrappedDatabaseKey.substring(
                        ciphertextStart + 1
                );

        boolean saved =
                preferences
                        .edit()
                        .putString(
                                VaultKeyEnvelopeStore
                                        .KEY_WRAPPED_DATABASE_KEY,
                                tamperedValue
                        )
                        .commit();

        assertTrue(
                saved
        );
    }

    private void shutdownCoordinator() {
        if (coordinator == null) {
            return;
        }

        coordinator.shutdown();

        long deadline =
                SystemClock.elapsedRealtime()
                        + TimeUnit.SECONDS.toMillis(
                        CALLBACK_TIMEOUT_SECONDS
                );

        while (
                coordinator.isVaultOpen()
                        && SystemClock.elapsedRealtime()
                        < deadline
        ) {
            SystemClock.sleep(
                    50
            );
        }

        coordinator = null;
    }

    private void clearStoredVault() {
        if (context == null) {
            return;
        }

        context.deleteDatabase(
                DATABASE_NAME
        );

        context
                .getSharedPreferences(
                        VaultKeyEnvelopeStore.PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                )
                .edit()
                .clear()
                .commit();
    }

    private void awaitSuccess(
            AsyncOperation operation
    ) throws Exception {
        CountDownLatch latch =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.run(
                new VaultDataService.SimpleCallback() {

                    @Override
                    public void onSuccess() {
                        latch.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {
                        error.set(
                                exception
                        );

                        latch.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for successful operation.",
                latch.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        if (error.get() != null) {
            throw error.get();
        }
    }

    private Exception awaitError(
            AsyncOperation operation
    ) throws Exception {
        CountDownLatch latch =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.run(
                new VaultDataService.SimpleCallback() {

                    @Override
                    public void onSuccess() {
                        latch.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {
                        error.set(
                                exception
                        );

                        latch.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for failed operation.",
                latch.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        if (error.get() == null) {
            fail(
                    "Expected the operation to fail."
            );
        }

        return error.get();
    }

    private interface AsyncOperation {

        void run(
                VaultDataService.SimpleCallback callback
        );
    }
}

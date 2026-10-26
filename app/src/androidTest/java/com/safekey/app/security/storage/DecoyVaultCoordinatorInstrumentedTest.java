package com.safekey.app.security.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.data.model.Credential;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.data.service.VaultDataService;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class DecoyVaultCoordinatorInstrumentedTest {

    private static final String PRIMARY_DATABASE_NAME =
            "safekey.db";

    private static final long CALLBACK_TIMEOUT_SECONDS =
            30;

    private Context context;

    private SecureVaultCoordinator primaryCoordinator;
    private DecoyVaultCoordinator decoyCoordinator;

    @Before
    public void setUp() {
        context =
                InstrumentationRegistry
                        .getInstrumentation()
                        .getTargetContext();

        clearStoredVaults();

        /*
         * Week 10 requirement:
         * the secondary encrypted database exists even
         * before Decoy enrollment.
         */
        DecoyVaultStorage.ensureDatabaseFile(
                context
        );

        primaryCoordinator =
                new SecureVaultCoordinator(
                        context
                );

        decoyCoordinator =
                new DecoyVaultCoordinator(
                        context
                );
    }

    @After
    public void tearDown() {
        shutdownCoordinators();

        clearStoredVaults();

        /*
         * Restore the normal always-present secondary
         * storage state after each test.
         */
        if (context != null) {
            DecoyVaultStorage.ensureDatabaseFile(
                    context
            );
        }

        primaryCoordinator = null;
        decoyCoordinator = null;
        context = null;
    }

    @Test
    public void pendingEnrollment_afterCloseCompletes_cannotCreateDecoy()
            throws Exception {

        java.lang.reflect.Field executorField =
                DecoyVaultCoordinator.class
                        .getDeclaredField("securityExecutor");
        executorField.setAccessible(true);

        java.util.concurrent.ExecutorService executor =
                (java.util.concurrent.ExecutorService)
                        executorField.get(decoyCoordinator);

        CountDownLatch workerStarted = new CountDownLatch(1);
        CountDownLatch releaseWorker = new CountDownLatch(1);
        CountDownLatch enrollmentCompleted = new CountDownLatch(1);

        java.util.concurrent.atomic.AtomicBoolean enrollmentSucceeded =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        AtomicReference<Exception> enrollmentError =
                new AtomicReference<>();

        java.util.concurrent.Future<?> blockingTask =
                executor.submit(() -> {
                    workerStarted.countDown();

                    try {
                        releaseWorker.await(60, TimeUnit.SECONDS);
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                    }
                });

        try {
            assertTrue(workerStarted.await(
                    CALLBACK_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS
            ));

            decoyCoordinator.createDecoyVault(
                    password("decoy enrollment regression password"),
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            enrollmentSucceeded.set(true);
                            enrollmentCompleted.countDown();
                        }

                        @Override
                        public void onError(Exception exception) {
                            enrollmentError.set(exception);
                            enrollmentCompleted.countDown();
                        }
                    }
            );

            // Close finishes before the queued enrollment resumes.
            awaitSuccess(decoyCoordinator::closeDecoyVault);

        } finally {
            releaseWorker.countDown();
        }

        blockingTask.get(
                CALLBACK_TIMEOUT_SECONDS,
                TimeUnit.SECONDS
        );

        assertTrue(enrollmentCompleted.await(
                CALLBACK_TIMEOUT_SECONDS,
                TimeUnit.SECONDS
        ));

        assertFalse(enrollmentSucceeded.get());
        assertNotNull(enrollmentError.get());

        // The cancelled enrollment must not create a vault.
        assertFalse(decoyCoordinator.hasDecoyVault());
        assertFalse(decoyCoordinator.isDecoyVaultOpen());
    }
    @Test
    public void enrollmentPausedAfterDerivation_closeRejectsCreation()
            throws Exception {

        CountDownLatch derivationPaused = new CountDownLatch(1);
        CountDownLatch resumeDerivation = new CountDownLatch(1);
        CountDownLatch enrollmentCompleted = new CountDownLatch(1);

        java.util.concurrent.atomic.AtomicBoolean enrollmentSucceeded =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        AtomicReference<Exception> enrollmentError =
                new AtomicReference<>();

        decoyCoordinator.enrollmentDerivationTestHook = () -> {
            derivationPaused.countDown();

            try {
                if (!resumeDerivation.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                            "Timed out waiting to resume enrollment."
                    );
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(exception);
            }
        };

        try {
            decoyCoordinator.createDecoyVault(
                    password("decoy derivation regression password"),
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            enrollmentSucceeded.set(true);
                            enrollmentCompleted.countDown();
                        }

                        @Override
                        public void onError(Exception exception) {
                            enrollmentError.set(exception);
                            enrollmentCompleted.countDown();
                        }
                    }
            );

            // Enrollment has completed Argon2id derivation.
            assertTrue(
                    "Enrollment did not reach the derivation pause.",
                    derivationPaused.await(
                            CALLBACK_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS
                    )
            );

            // Close the vault before allowing enrollment to continue.
            awaitSuccess(decoyCoordinator::closeDecoyVault);

            assertFalse(decoyCoordinator.hasDecoyVault());
            assertFalse(decoyCoordinator.isDecoyVaultOpen());

        } finally {
            resumeDerivation.countDown();
            decoyCoordinator.enrollmentDerivationTestHook = () -> {};
        }

        assertTrue(
                "Enrollment callback did not finish.",
                enrollmentCompleted.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertFalse(
                "Cancelled enrollment must not succeed.",
                enrollmentSucceeded.get()
        );

        assertNotNull(
                "Cancelled enrollment must report an error.",
                enrollmentError.get()
        );

        assertFalse(
                "Cancelled enrollment must not save an envelope.",
                decoyCoordinator.hasDecoyVault()
        );

        assertFalse(
                "Cancelled enrollment must not reopen the database.",
                decoyCoordinator.isDecoyVaultOpen()
        );
    }
    @Test
    public void staleCreationCleanup_cannotDeleteNewerDecoyVault()
            throws Exception {

        java.lang.reflect.Field generationField =
                DecoyVaultCoordinator.class
                        .getDeclaredField("unlockGeneration");

        generationField.setAccessible(true);

        long staleGeneration =
                generationField.getLong(decoyCoordinator);

        // Invalidate the old generation.
        awaitSuccess(decoyCoordinator::closeDecoyVault);

        // Create a legitimate vault in the newer generation.
        awaitSuccess(callback ->
                decoyCoordinator.createDecoyVault(
                        password("newer decoy lifecycle password"),
                        callback
                )
        );

        assertTrue(decoyCoordinator.hasDecoyVault());
        assertTrue(decoyCoordinator.isDecoyVaultOpen());

        // Simulate delayed cleanup from an older enrollment.
        java.lang.reflect.Method cleanupMethod =
                DecoyVaultCoordinator.class.getDeclaredMethod(
                        "cleanupFailedCreation",
                        Exception.class,
                        long.class
                );

        cleanupMethod.setAccessible(true);

        cleanupMethod.invoke(
                decoyCoordinator,
                new IllegalStateException("Simulated stale failure"),
                staleGeneration
        );

        // The newer vault and its key envelope must survive.
        assertTrue(decoyCoordinator.hasDecoyVault());
        assertTrue(DecoyVaultStorage.databaseFileExists(context));
        assertTrue(decoyCoordinator.isDecoyVaultOpen());

        // Verify the database can still be reopened.
        awaitSuccess(decoyCoordinator::closeDecoyVault);

        awaitSuccess(callback ->
                decoyCoordinator.unlockDecoyVault(
                        password("newer decoy lifecycle password"),
                        callback
                )
        );

        assertTrue(decoyCoordinator.isDecoyVaultOpen());
    }
    @Test
    public void pendingUnlock_afterCloseCompletes_cannotReopenDecoy()
            throws Exception {

        awaitSuccess(callback ->
                decoyCoordinator.createDecoyVault(
                        password("decoy lifecycle regression password"),
                        callback
                )
        );

        awaitSuccess(decoyCoordinator::closeDecoyVault);

        java.lang.reflect.Field executorField =
                DecoyVaultCoordinator.class
                        .getDeclaredField("securityExecutor");
        executorField.setAccessible(true);

        java.util.concurrent.ExecutorService executor =
                (java.util.concurrent.ExecutorService)
                        executorField.get(decoyCoordinator);

        CountDownLatch workerStarted = new CountDownLatch(1);
        CountDownLatch releaseWorker = new CountDownLatch(1);
        CountDownLatch unlockCompleted = new CountDownLatch(1);

        java.util.concurrent.atomic.AtomicBoolean unlockSucceeded =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        AtomicReference<Exception> unlockError =
                new AtomicReference<>();

        java.util.concurrent.Future<?> blockingTask =
                executor.submit(() -> {
                    workerStarted.countDown();
                    try {
                        releaseWorker.await(60, TimeUnit.SECONDS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                });

        try {
            assertTrue(
                    workerStarted.await(
                            CALLBACK_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS
                    )
            );

            decoyCoordinator.unlockDecoyVault(
                    password("decoy lifecycle regression password"),
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            unlockSucceeded.set(true);
                            unlockCompleted.countDown();
                        }

                        @Override
                        public void onError(Exception exception) {
                            unlockError.set(exception);
                            unlockCompleted.countDown();
                        }
                    }
            );

            // Closing must invalidate the queued unlock.
            awaitSuccess(decoyCoordinator::closeDecoyVault);

        } finally {
            releaseWorker.countDown();
        }

        blockingTask.get(
                CALLBACK_TIMEOUT_SECONDS,
                TimeUnit.SECONDS
        );

        assertTrue(
                unlockCompleted.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        assertFalse(unlockSucceeded.get());
        assertNotNull(unlockError.get());
        assertFalse(decoyCoordinator.isDecoyVaultOpen());
    }
    @Test
    public void pendingDatabaseOpen_afterClose_cannotReopenDecoy()
            throws Exception {

        awaitSuccess(callback -> decoyCoordinator.createDecoyVault(
                password("decoy database handoff regression"),
                callback
        ));

        awaitSuccess(decoyCoordinator::closeDecoyVault);

        java.lang.reflect.Field serviceField =
                DecoyVaultCoordinator.class.getDeclaredField("vaultDataService");
        serviceField.setAccessible(true);
        VaultDataService service =
                (VaultDataService) serviceField.get(decoyCoordinator);

        java.lang.reflect.Field databaseExecutorField =
                VaultDataService.class.getDeclaredField("executorService");
        databaseExecutorField.setAccessible(true);
        java.util.concurrent.ExecutorService databaseExecutor =
                (java.util.concurrent.ExecutorService)
                        databaseExecutorField.get(service);

        java.lang.reflect.Field securityExecutorField =
                DecoyVaultCoordinator.class.getDeclaredField("securityExecutor");
        securityExecutorField.setAccessible(true);
        java.util.concurrent.ExecutorService securityExecutor =
                (java.util.concurrent.ExecutorService)
                        securityExecutorField.get(decoyCoordinator);

        CountDownLatch databaseBlocked = new CountDownLatch(1);
        CountDownLatch releaseDatabase = new CountDownLatch(1);
        CountDownLatch unlockFinished = new CountDownLatch(1);
        CountDownLatch closeFinished = new CountDownLatch(1);

        java.util.concurrent.atomic.AtomicBoolean unlockSucceeded =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        AtomicReference<Exception> unlockError = new AtomicReference<>();
        AtomicReference<Exception> closeError = new AtomicReference<>();

        java.util.concurrent.Future<?> blocker = databaseExecutor.submit(() -> {
            databaseBlocked.countDown();
            try {
                releaseDatabase.await(60, TimeUnit.SECONDS);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        });

        try {
            assertTrue(databaseBlocked.await(
                    CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS));

            decoyCoordinator.unlockDecoyVault(
                    password("decoy database handoff regression"),
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            unlockSucceeded.set(true);
                            unlockFinished.countDown();
                        }

                        @Override
                        public void onError(Exception exception) {
                            unlockError.set(exception);
                            unlockFinished.countDown();
                        }
                    }
            );

            // Wait until the unlock worker has queued the database open.
            securityExecutor.submit(() -> {}).get(
                    CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);

            // Invalidate unlock before the database worker resumes.
            decoyCoordinator.closeDecoyVault(
                    new VaultDataService.SimpleCallback() {
                        @Override
                        public void onSuccess() {
                            closeFinished.countDown();
                        }

                        @Override
                        public void onError(Exception exception) {
                            closeError.set(exception);
                            closeFinished.countDown();
                        }
                    }
            );
        } finally {
            releaseDatabase.countDown();
        }

        blocker.get(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertTrue(closeFinished.await(
                CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        assertTrue(unlockFinished.await(
                CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS));

        assertTrue("Close should succeed.", closeError.get() == null);
        assertFalse("Stale unlock must fail.", unlockSucceeded.get());
        assertNotNull(unlockError.get());
        assertFalse(decoyCoordinator.isDecoyVaultOpen());
    }
    @Test
    public void createCloseAndReopenDecoy_withCorrectPassword_succeeds()
            throws Exception {

        awaitSuccess(
                callback ->
                        decoyCoordinator.createDecoyVault(
                                password(
                                        "decoy password example 2026"
                                ),
                                callback
                        )
        );

        assertTrue(
                decoyCoordinator.hasDecoyVault()
        );

        assertTrue(
                decoyCoordinator.isDecoyVaultOpen()
        );

        assertTrue(
                DecoyVaultStorage.databaseFileExists(
                        context
                )
        );

        awaitSuccess(
                decoyCoordinator::closeDecoyVault
        );

        assertFalse(
                decoyCoordinator.isDecoyVaultOpen()
        );

        decoyCoordinator.shutdown();

        waitForDecoyClosed();

        decoyCoordinator =
                new DecoyVaultCoordinator(
                        context
                );

        assertTrue(
                decoyCoordinator.hasDecoyVault()
        );

        awaitSuccess(
                callback ->
                        decoyCoordinator.unlockDecoyVault(
                                password(
                                        "decoy password example 2026"
                                ),
                                callback
                        )
        );

        assertTrue(
                decoyCoordinator.isDecoyVaultOpen()
        );
    }

    @Test
    public void unlockDecoy_withWrongPassword_failsAndKeepsDecoyClosed()
            throws Exception {

        awaitSuccess(
                callback ->
                        decoyCoordinator.createDecoyVault(
                                password(
                                        "correct decoy password 2026"
                                ),
                                callback
                        )
        );

        awaitSuccess(
                decoyCoordinator::closeDecoyVault
        );

        Exception error =
                awaitError(
                        callback ->
                                decoyCoordinator.unlockDecoyVault(
                                        password(
                                                "wrong decoy password 2026"
                                        ),
                                        callback
                                )
                );

        assertNotNull(
                error
        );

        assertFalse(
                decoyCoordinator.isDecoyVaultOpen()
        );
    }

    @Test
    public void primaryCredential_neverAppearsInDecoyVault()
            throws Exception {

        createBothVaults();

        Long insertedId =
                awaitResult(
                        callback ->
                                primaryCoordinator.addCredential(
                                        new Credential(
                                                "Primary Account",
                                                "primary-user",
                                                "primary-password",
                                                "https://primary.example",
                                                "Personal",
                                                "Primary credential only"
                                        ),
                                        callback
                                )
                );

        assertTrue(
                insertedId > 0L
        );

        List<Credential> primaryCredentials =
                awaitResult(
                        primaryCoordinator::getCredentials
                );

        List<Credential> decoyCredentials =
                awaitResult(
                        decoyCoordinator::getCredentials
                );

        assertEquals(
                1,
                primaryCredentials.size()
        );

        assertEquals(
                "Primary Account",
                primaryCredentials
                        .get(0)
                        .getTitle()
        );

        assertTrue(
                decoyCredentials.isEmpty()
        );
    }

    @Test
    public void decoyCredential_neverAppearsInPrimaryVault()
            throws Exception {

        createBothVaults();

        Long insertedId =
                awaitResult(
                        callback ->
                                decoyCoordinator.addCredential(
                                        new Credential(
                                                "Decoy Account",
                                                "decoy-user",
                                                "decoy-password",
                                                "https://decoy.example",
                                                "Personal",
                                                "Decoy credential only"
                                        ),
                                        callback
                                )
                );

        assertTrue(
                insertedId > 0L
        );

        List<Credential> decoyCredentials =
                awaitResult(
                        decoyCoordinator::getCredentials
                );

        List<Credential> primaryCredentials =
                awaitResult(
                        primaryCoordinator::getCredentials
                );

        assertEquals(
                1,
                decoyCredentials.size()
        );

        assertEquals(
                "Decoy Account",
                decoyCredentials
                        .get(0)
                        .getTitle()
        );

        assertTrue(
                primaryCredentials.isEmpty()
        );
    }

    @Test
    public void primaryAndDecoyCredentials_remainFullySeparated()
            throws Exception {

        createBothVaults();

        Long primaryId =
                awaitResult(
                        callback ->
                                primaryCoordinator.addCredential(
                                        new Credential(
                                                "Real Email",
                                                "real-user",
                                                "real-secret",
                                                "https://real.example",
                                                "Work",
                                                "Real vault"
                                        ),
                                        callback
                                )
                );

        Long decoyId =
                awaitResult(
                        callback ->
                                decoyCoordinator.addCredential(
                                        new Credential(
                                                "Decoy Email",
                                                "decoy-user",
                                                "decoy-secret",
                                                "https://decoy.example",
                                                "Work",
                                                "Decoy vault"
                                        ),
                                        callback
                                )
                );

        assertTrue(
                primaryId > 0L
        );

        assertTrue(
                decoyId > 0L
        );

        List<Credential> primaryCredentials =
                awaitResult(
                        primaryCoordinator::getCredentials
                );

        List<Credential> decoyCredentials =
                awaitResult(
                        decoyCoordinator::getCredentials
                );

        assertEquals(
                1,
                primaryCredentials.size()
        );

        assertEquals(
                1,
                decoyCredentials.size()
        );

        Credential primary =
                primaryCredentials.get(
                        0
                );

        Credential decoy =
                decoyCredentials.get(
                        0
                );

        assertEquals(
                "Real Email",
                primary.getTitle()
        );

        assertEquals(
                "real-user",
                primary.getUsername()
        );

        assertEquals(
                "real-secret",
                primary.getPassword()
        );

        assertEquals(
                "Decoy Email",
                decoy.getTitle()
        );

        assertEquals(
                "decoy-user",
                decoy.getUsername()
        );

        assertEquals(
                "decoy-secret",
                decoy.getPassword()
        );
    }

    @Test
    public void primaryAndDecoySecureNotes_remainFullySeparated()
            throws Exception {

        createBothVaults();

        Long primaryNoteId =
                awaitResult(
                        callback ->
                                primaryCoordinator.addSecureNote(
                                        new SecureNote(
                                                "Primary Secret Note",
                                                "This belongs only to the real vault."
                                        ),
                                        callback
                                )
                );

        Long decoyNoteId =
                awaitResult(
                        callback ->
                                decoyCoordinator.addSecureNote(
                                        new SecureNote(
                                                "Decoy Secret Note",
                                                "This belongs only to the Decoy Vault."
                                        ),
                                        callback
                                )
                );

        assertTrue(
                primaryNoteId > 0L
        );

        assertTrue(
                decoyNoteId > 0L
        );

        List<SecureNote> primaryNotes =
                awaitResult(
                        primaryCoordinator::getSecureNotes
                );

        List<SecureNote> decoyNotes =
                awaitResult(
                        decoyCoordinator::getSecureNotes
                );

        assertEquals(
                1,
                primaryNotes.size()
        );

        assertEquals(
                1,
                decoyNotes.size()
        );

        assertEquals(
                "Primary Secret Note",
                primaryNotes
                        .get(0)
                        .getTitle()
        );

        assertEquals(
                "This belongs only to the real vault.",
                primaryNotes
                        .get(0)
                        .getContent()
        );

        assertEquals(
                "Decoy Secret Note",
                decoyNotes
                        .get(0)
                        .getTitle()
        );

        assertEquals(
                "This belongs only to the Decoy Vault.",
                decoyNotes
                        .get(0)
                        .getContent()
        );
    }

    @Test
    public void primaryPassword_cannotUnlockDecoyVault()
            throws Exception {

        createBothVaults();

        awaitSuccess(
                decoyCoordinator::closeDecoyVault
        );

        Exception error =
                awaitError(
                        callback ->
                                decoyCoordinator.unlockDecoyVault(
                                        password(
                                                "real master password 2026"
                                        ),
                                        callback
                                )
                );

        assertNotNull(
                error
        );

        assertFalse(
                decoyCoordinator.isDecoyVaultOpen()
        );

        /*
         * The failed primary-password attempt must
         * not damage the Decoy Vault.
         */
        awaitSuccess(
                callback ->
                        decoyCoordinator.unlockDecoyVault(
                                password(
                                        "decoy master password 2026"
                                ),
                                callback
                        )
        );

        assertTrue(
                decoyCoordinator.isDecoyVaultOpen()
        );
    }

    @Test
    public void decoyPassword_cannotUnlockPrimaryVault()
            throws Exception {

        createBothVaults();

        awaitSuccess(
                primaryCoordinator::closeVault
        );

        Exception error =
                awaitError(
                        callback ->
                                primaryCoordinator.unlockVault(
                                        password(
                                                "decoy master password 2026"
                                        ),
                                        callback
                                )
                );

        assertNotNull(
                error
        );

        assertFalse(
                primaryCoordinator.isVaultOpen()
        );

        /*
         * The failed Decoy-password attempt must
         * not damage the primary vault.
         */
        awaitSuccess(
                callback ->
                        primaryCoordinator.unlockVault(
                                password(
                                        "real master password 2026"
                                ),
                                callback
                        )
        );

        assertTrue(
                primaryCoordinator.isVaultOpen()
        );
    }

    @Test
    public void unopenedDecoyFlow_cannotReadPrimaryVaultData()
            throws Exception {

        awaitSuccess(
                callback ->
                        primaryCoordinator.createVault(
                                password(
                                        "real master password 2026"
                                ),
                                callback
                        )
        );

        Long insertedId =
                awaitResult(
                        callback ->
                                primaryCoordinator.addCredential(
                                        new Credential(
                                                "Primary Only",
                                                "primary-user",
                                                "primary-password",
                                                "",
                                                "Personal",
                                                ""
                                        ),
                                        callback
                                )
                );

        assertTrue(
                insertedId > 0L
        );

        Exception error =
                awaitResultError(
                        decoyCoordinator::getCredentials
                );

        assertTrue(
                error instanceof IllegalStateException
        );

        assertEquals(
                "Vault is not open.",
                error.getMessage()
        );
    }

    @Test
    public void primaryAndDecoyUseIndependentDatabaseFilesAndEnvelopes()
            throws Exception {

        createBothVaults();

        assertTrue(
                context
                        .getDatabasePath(
                                PRIMARY_DATABASE_NAME
                        )
                        .exists()
        );

        assertTrue(
                context
                        .getDatabasePath(
                                DecoyVaultStorage.DATABASE_NAME
                        )
                        .exists()
        );

        assertFalse(
                context
                        .getDatabasePath(
                                PRIMARY_DATABASE_NAME
                        )
                        .getCanonicalPath()
                        .equals(
                                context
                                        .getDatabasePath(
                                                DecoyVaultStorage.DATABASE_NAME
                                        )
                                        .getCanonicalPath()
                        )
        );

        VaultKeyEnvelopeStore primaryStore =
                new VaultKeyEnvelopeStore(
                        context
                );

        VaultKeyEnvelopeStore decoyStore =
                VaultKeyEnvelopeStore.forDecoy(
                        context
                );

        assertTrue(
                primaryStore.hasEnvelope()
        );

        assertTrue(
                decoyStore.hasEnvelope()
        );

        VaultKeyEnvelope primaryEnvelope =
                primaryStore.load();

        VaultKeyEnvelope decoyEnvelope =
                decoyStore.load();

        assertNotNull(
                primaryEnvelope
        );

        assertNotNull(
                decoyEnvelope
        );

        assertFalse(
                primaryEnvelope
                        .getWrappedDatabaseKey()
                        .equals(
                                decoyEnvelope
                                        .getWrappedDatabaseKey()
                        )
        );
    }


    @Test
    public void lifecycleCallbacks_doNotHoldCoordinatorLock()
            throws Exception {

        java.lang.reflect.Field lockField =
                DecoyVaultCoordinator.class.getDeclaredField("lifecycleLock");
        lockField.setAccessible(true);

        Object lifecycleMonitor = lockField.get(decoyCoordinator);
        String correctPassword = "decoy deadlock regression password";

        // Enrollment success must not hold lifecycleLock.
        assertCallbackOutsideLifecycleLock(
                lifecycleMonitor,
                callback -> decoyCoordinator.createDecoyVault(
                        password(correctPassword), callback),
                true
        );

        // Close success must not hold lifecycleLock.
        assertCallbackOutsideLifecycleLock(
                lifecycleMonitor,
                decoyCoordinator::closeDecoyVault,
                true
        );

        // Unlock success must not hold lifecycleLock.
        assertCallbackOutsideLifecycleLock(
                lifecycleMonitor,
                callback -> decoyCoordinator.unlockDecoyVault(
                        password(correctPassword), callback),
                true
        );

        assertCallbackOutsideLifecycleLock(
                lifecycleMonitor,
                decoyCoordinator::closeDecoyVault,
                true
        );

        // Unlock failure must also release lifecycleLock.
        assertCallbackOutsideLifecycleLock(
                lifecycleMonitor,
                callback -> decoyCoordinator.unlockDecoyVault(
                        password("incorrect decoy password"), callback),
                false
        );
    }

    private void assertCallbackOutsideLifecycleLock(
            Object lifecycleMonitor,
            SimpleOperation operation,
            boolean expectedSuccess
    ) throws Exception {

        CountDownLatch completed = new CountDownLatch(1);

        java.util.concurrent.atomic.AtomicBoolean lockHeld =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        java.util.concurrent.atomic.AtomicBoolean succeeded =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        AtomicReference<Exception> error = new AtomicReference<>();

        operation.run(new VaultDataService.SimpleCallback() {
            @Override
            public void onSuccess() {
                try {
                    lockHeld.set(Thread.holdsLock(lifecycleMonitor));

                    // Exercise the session-monitor access from the P1 report.
                    com.safekey.app.session.SafeKeySession.getState();

                    succeeded.set(true);
                } finally {
                    completed.countDown();
                }
            }

            @Override
            public void onError(Exception exception) {
                try {
                    lockHeld.set(Thread.holdsLock(lifecycleMonitor));

                    com.safekey.app.session.SafeKeySession.getState();

                    error.set(exception);
                } finally {
                    completed.countDown();
                }
            }
        });

        assertTrue(
                "Timed out waiting for Decoy Vault callback.",
                completed.await(
                        CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        );

        assertFalse(
                "External callback executed while holding lifecycleLock.",
                lockHeld.get()
        );

        assertEquals(
                "Unexpected Decoy Vault callback result.",
                expectedSuccess,
                succeeded.get()
        );

        if (!expectedSuccess) {
            assertNotNull(error.get());
        }
    }

    private void createBothVaults()
            throws Exception {

        awaitSuccess(
                callback ->
                        primaryCoordinator.createVault(
                                password(
                                        "real master password 2026"
                                ),
                                callback
                        )
        );

        awaitSuccess(
                callback ->
                        decoyCoordinator.createDecoyVault(
                                password(
                                        "decoy master password 2026"
                                ),
                                callback
                        )
        );

        assertTrue(
                primaryCoordinator.isVaultOpen()
        );

        assertTrue(
                decoyCoordinator.isDecoyVaultOpen()
        );
    }

    private void shutdownCoordinators() {
        if (decoyCoordinator != null) {
            decoyCoordinator.shutdown();

            waitForDecoyClosed();
        }

        if (primaryCoordinator != null) {
            primaryCoordinator.shutdown();

            waitForPrimaryClosed();
        }
    }

    private void waitForPrimaryClosed() {
        if (primaryCoordinator == null) {
            return;
        }

        long deadline =
                SystemClock.elapsedRealtime()
                        + TimeUnit.SECONDS.toMillis(
                        CALLBACK_TIMEOUT_SECONDS
                );

        while (
                primaryCoordinator.isVaultOpen()
                        && SystemClock.elapsedRealtime()
                        < deadline
        ) {
            SystemClock.sleep(
                    50
            );
        }
    }

    private void waitForDecoyClosed() {
        if (decoyCoordinator == null) {
            return;
        }

        long deadline =
                SystemClock.elapsedRealtime()
                        + TimeUnit.SECONDS.toMillis(
                        CALLBACK_TIMEOUT_SECONDS
                );

        while (
                decoyCoordinator.isDecoyVaultOpen()
                        && SystemClock.elapsedRealtime()
                        < deadline
        ) {
            SystemClock.sleep(
                    50
            );
        }
    }

    private void clearStoredVaults() {
        if (context == null) {
            return;
        }

        context.deleteDatabase(
                PRIMARY_DATABASE_NAME
        );

        context.deleteDatabase(
                DecoyVaultStorage.DATABASE_NAME
        );

        context
                .getSharedPreferences(
                        VaultKeyEnvelopeStore.PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                )
                .edit()
                .clear()
                .commit();

        context
                .getSharedPreferences(
                        VaultKeyEnvelopeStore.DECOY_PREFERENCES_NAME,
                        Context.MODE_PRIVATE
                )
                .edit()
                .clear()
                .commit();
    }

    private void awaitSuccess(
            SimpleOperation operation
    ) throws Exception {

        CountDownLatch completed =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.run(
                new VaultDataService.SimpleCallback() {
                    @Override
                    public void onSuccess() {
                        completed.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {
                        error.set(
                                exception
                        );

                        completed.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for successful operation.",
                completed.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        if (error.get() != null) {
            throw error.get();
        }
    }

    private Exception awaitError(
            SimpleOperation operation
    ) throws Exception {

        CountDownLatch completed =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.run(
                new VaultDataService.SimpleCallback() {
                    @Override
                    public void onSuccess() {
                        completed.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {
                        error.set(
                                exception
                        );

                        completed.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for failed operation.",
                completed.await(
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

    private <T> T awaitResult(
            ResultOperation<T> operation
    ) throws Exception {

        CountDownLatch completed =
                new CountDownLatch(
                        1
                );

        AtomicReference<T> result =
                new AtomicReference<>();

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.run(
                new VaultDataService.ResultCallback<T>() {
                    @Override
                    public void onSuccess(
                            T value
                    ) {
                        result.set(
                                value
                        );

                        completed.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {
                        error.set(
                                exception
                        );

                        completed.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for result.",
                completed.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        if (error.get() != null) {
            throw error.get();
        }

        return result.get();
    }

    private <T> Exception awaitResultError(
            ResultOperation<T> operation
    ) throws Exception {

        CountDownLatch completed =
                new CountDownLatch(
                        1
                );

        AtomicReference<Exception> error =
                new AtomicReference<>();

        operation.run(
                new VaultDataService.ResultCallback<T>() {
                    @Override
                    public void onSuccess(
                            T value
                    ) {
                        completed.countDown();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {
                        error.set(
                                exception
                        );

                        completed.countDown();
                    }
                }
        );

        assertTrue(
                "Timed out waiting for failed result.",
                completed.await(
                        CALLBACK_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        );

        if (error.get() == null) {
            fail(
                    "Expected the result operation to fail."
            );
        }

        return error.get();
    }

    private static char[] password(
            String value
    ) {
        return value.toCharArray();
    }

    private interface SimpleOperation {

        void run(
                VaultDataService.SimpleCallback callback
        );
    }

    private interface ResultOperation<T> {

        void run(
                VaultDataService.ResultCallback<T> callback
        );
    }
}

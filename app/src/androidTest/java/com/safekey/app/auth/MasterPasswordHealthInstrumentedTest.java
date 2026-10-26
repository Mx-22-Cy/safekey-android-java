package com.safekey.app.auth;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.breach.HibpRangeSource;
import com.safekey.app.breach.PasswordBreachCoordinator;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.VaultKeyEnvelope;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.testutil.CallbackTimeoutDiagnostics;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;

import static org.junit.Assert.assertEquals;

/** Deterministic range responses; no HTTP requests or sleeps. */
@RunWith(AndroidJUnit4.class)
public class MasterPasswordHealthInstrumentedTest {
    private static final String PASSWORD = "clouds drift quietly over mountains";
    private MasterPasswordHealth health;
    private VaultKeyEnvelopeStore store;
    private FakeSource source;
    private VaultKeyEnvelope original;

    @Before
    public void setUp() {
        Context base = InstrumentationRegistry.getInstrumentation().getTargetContext();
        Context context = new ContextWrapper(base) {
            @Override public Context getApplicationContext() { return this; }
            @Override public SharedPreferences getSharedPreferences(String name, int mode) {
                return super.getSharedPreferences("t45_health_" + name, mode);
            }
        };
        store = new VaultKeyEnvelopeStore(context);
        store.clear();
        original = new VaultKeyEnvelope(new byte[16], "original wrapped database key");
        store.save(original);
        source = new FakeSource();
        health = new MasterPasswordHealth(context, source);
        SafeKeySession.lock();
        SafeKeySession.unlockAfterAuthentication();
    }

    @After
    public void tearDown() {
        health.close();
        SafeKeySession.lock();
        store.clear();
    }

    @Test
    public void confirmedMatchRecordsBreachUsingOnlyFiveCharacterPrefix() throws Exception {
        start();
        String hash = hash();
        assertEquals(5, source.prefix.length());
        assertEquals(hash.substring(0, 5), source.prefix.toUpperCase(Locale.US));
        source.callback.onSuccess(hash.substring(5) + ":19\r\n");
        drain();
        assertEquals(MasterPasswordCheckStatus.BREACHED, health.getStatus());
    }

    @Test
    public void confirmedNoMatchClearsPendingStatus() throws Exception {
        start();
        source.callback.onSuccess(differentSuffix() + ":1\r\n");
        drain();
        assertEquals(MasterPasswordCheckStatus.CHECKED, health.getStatus());
    }

    @Test
    public void networkFailureKeepsPendingStatus() throws Exception {
        start();
        source.callback.onError(new IOException("Test offline response"));
        drain();
        assertEquals(MasterPasswordCheckStatus.PENDING, health.getStatus());
    }

    @Test
    public void failedRecheckCannotEraseKnownBreachWarning() throws Exception {
        store.updateMasterPasswordCheckStatus(original, MasterPasswordCheckStatus.BREACHED);
        start();
        source.callback.onError(new IOException("Test offline response"));
        drain();
        assertEquals(MasterPasswordCheckStatus.BREACHED, health.getStatus());
    }

    @Test
    public void resultFromPreviousAuthenticationCannotUpdateReplacementSession() throws Exception {
        start();
        SafeKeySession.lock();
        SafeKeySession.unlockAfterAuthentication();
        source.callback.onSuccess(differentSuffix() + ":1\r\n");
        drain();
        assertEquals(MasterPasswordCheckStatus.PENDING, health.getStatus());
    }

    @Test
    public void resultForPreviousEnvelopeCannotMarkNewPasswordChecked() throws Exception {
        start();
        store.save(new VaultKeyEnvelope(new byte[16], "replacement wrapped database key"));
        source.callback.onSuccess(differentSuffix() + ":1\r\n");
        drain();
        assertEquals(MasterPasswordCheckStatus.PENDING, health.getStatus());
    }

    private void start() throws Exception {
        char[] candidate = PASSWORD.toCharArray();
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(
                    () -> health.recheckAfterAuthentication(candidate));
        } finally { Arrays.fill(candidate, '\0'); }
        CallbackTimeoutDiagnostics.await(source.requested, 30L);
    }

    private void drain() throws Exception {
        Field coordinatorField = MasterPasswordHealth.class.getDeclaredField("coordinator");
        coordinatorField.setAccessible(true);
        PasswordBreachCoordinator coordinator =
                (PasswordBreachCoordinator) coordinatorField.get(health);
        Field workerField = PasswordBreachCoordinator.class.getDeclaredField("workerExecutor");
        workerField.setAccessible(true);
        ExecutorService worker = (ExecutorService) workerField.get(coordinator);
        CountDownLatch finished = new CountDownLatch(1);
        worker.execute(finished::countDown);
        CallbackTimeoutDiagnostics.await(finished, 30L);
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
    }

    private static String hash() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-1")
                .digest(PASSWORD.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder();
        for (byte value : hash) { result.append(String.format(Locale.US, "%02X", value & 255)); }
        Arrays.fill(hash, (byte) 0);
        return result.toString();
    }

    private static String differentSuffix() throws Exception {
        String suffix = hash().substring(5);
        return (suffix.charAt(0) == '0' ? "1" : "0") + suffix.substring(1);
    }

    private static final class FakeSource implements HibpRangeSource {
        private final CountDownLatch requested = new CountDownLatch(1);
        private volatile String prefix;
        private volatile Callback callback;
        @Override public void fetchRange(String prefix, Callback callback) {
            this.prefix = prefix;
            this.callback = callback;
            requested.countDown();
        }
    }
}

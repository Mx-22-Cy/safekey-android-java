package com.safekey.app.auth;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.safekey.app.auth.logic.MasterPasswordScreening;
import com.safekey.app.breach.HibpRangeClient;
import com.safekey.app.breach.HibpRangeSource;
import com.safekey.app.breach.PasswordBreachCoordinator;
import com.safekey.app.security.storage.MasterPasswordCheckStatus;
import com.safekey.app.security.storage.VaultKeyEnvelope;
import com.safekey.app.security.storage.VaultKeyEnvelopeStore;
import com.safekey.app.session.SafeKeySession;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicLong;

/** Online checking never saves a password or a password-derived lookup hash. */
public final class MasterPasswordHealth implements AutoCloseable {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final VaultKeyEnvelopeStore store;
    private final PasswordBreachCoordinator coordinator;
    private final HibpRangeSource rangeSource;
    private final MasterPasswordScreening screening;
    private final AtomicLong generation = new AtomicLong();
    private final Set<Runnable> listeners = new CopyOnWriteArraySet<>();
    private MasterPasswordScreening.Request recheck;

    public MasterPasswordHealth(Context context) {
        this(context, new HibpRangeClient());
    }

    // Instrumented tests use a deterministic range source, never the internet.
    MasterPasswordHealth(Context context, HibpRangeSource source) {
        rangeSource = source;
        store = new VaultKeyEnvelopeStore(context);
        coordinator = new PasswordBreachCoordinator(source);
        screening = new MasterPasswordScreening((password, callback) -> {
            PasswordBreachCoordinator.Request request =
                    coordinator.check(password, callback::onResult);
            return request::close;
        });
    }

    public MasterPasswordScreening getScreening() {
        return screening;
    }

    public MasterPasswordCheckStatus getStatus() {
        return store.getMasterPasswordCheckStatus();
    }

    public void addListener(Runnable listener) {
        listeners.add(listener);
    }

    public void removeListener(Runnable listener) {
        listeners.remove(listener);
    }

    /**
     * Call on the main thread only after the password AND required TOTP have
     * completed and the vault session has been claimed. Borrows the array for
     * this call; the caller clears it immediately afterward.
     */
    public void recheckAfterAuthentication(char[] password) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("Password recheck must start on the main thread.");
        }
        long authentication = SafeKeySession.getManager().getAuthenticationGeneration();
        if (authentication < 0L || password == null || password.length == 0
                || getStatus() == MasterPasswordCheckStatus.CHECKED) {
            return;
        }
        final VaultKeyEnvelope expected;
        try {
            expected = store.load();
        } catch (RuntimeException invalidStore) {
            return;
        }
        if (expected == null) { return; }
        long token = generation.incrementAndGet();
        if (recheck != null) { recheck.close(); }
        recheck = screening.recheckExistingPassword(password, result -> {
            if (token != generation.get()) { return; }
            MasterPasswordCheckStatus status;
            switch (result.getOutcome()) {
                case BREACHED:
                    status = MasterPasswordCheckStatus.BREACHED;
                    break;
                case CHECKED_ACCEPTABLE:
                    status = MasterPasswordCheckStatus.CHECKED;
                    break;
                default:
                    return; // An unavailable recheck never clears a breach warning.
            }
            boolean[] updated = {false};
            try {
                SafeKeySession.getManager().runIfCurrentAuthentication(authentication,
                        () -> updated[0] = store.updateMasterPasswordCheckStatus(expected, status));
            } catch (RuntimeException storageError) {
                return; // Authentication remains independent of metadata persistence.
            }
            if (updated[0]) {
                for (Runnable listener : listeners) { listener.run(); }
            }
        });
    }

    @Override
    public void close() {
        cancelRecheck();
        listeners.clear();
        coordinator.shutdown();
        if (rangeSource instanceof HibpRangeClient) {
            ((HibpRangeClient) rangeSource).shutdown();
        }
    }

    /** Safe to call while the session manager lock is held on any thread. */
    public void cancelRecheck() {
        long token = generation.incrementAndGet();
        // Never wait for a checker lock here: its main-thread callback may be
        // checking the session lock held by the caller.
        main.post(() -> {
            if (token == generation.get() && recheck != null) {
                recheck.close();
                recheck = null;
            }
        });
    }
}

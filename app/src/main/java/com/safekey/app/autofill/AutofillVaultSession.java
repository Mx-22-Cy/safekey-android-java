package com.safekey.app.autofill;

import android.content.Context;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;
import com.safekey.app.security.storage.VaultOperations;

import java.util.List;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Restricts Autofill credential access to one authenticated vault session.
 *
 * Does not unlock a vault and does not switch between Real and Decoy.
 *
 * This guard does not replace final authentication at dataset selection.
 */
public final class AutofillVaultSession {

    private final SafeKeyApplication application;
    private final VaultOperations operations;
    private final SafeKeyApplication.ActiveVault vaultIdentity;
    private final long authenticationGeneration;

    private AutofillVaultSession(
            SafeKeyApplication application,
            VaultOperations operations,
            SafeKeyApplication.ActiveVault vaultIdentity,
            long authenticationGeneration
    ) {
        this.application = application;
        this.operations = operations;
        this.vaultIdentity = vaultIdentity;
        this.authenticationGeneration = authenticationGeneration;
    }

    public static AutofillVaultSession capture(Context context) {
        if (context == null) {
            return null;
        }

        if (!(context.getApplicationContext()
                instanceof SafeKeyApplication)) {
            return null;
        }

        SafeKeyApplication app =
                (SafeKeyApplication) context.getApplicationContext();

        try {
            if (SafeKeySession.getState() != SessionState.UNLOCKED) {
                return null;
            }
            long generation = SafeKeySession.getManager()
                    .getAuthenticationGeneration();
            SafeKeyApplication.ActiveVault selected = app.getActiveVault();
            if (generation < 0L || selected == SafeKeyApplication.ActiveVault.NONE) {
                return null;
            }
            VaultOperations current = app.getActiveVaultOperations();
            if (SafeKeySession.getManager().getAuthenticationGeneration() != generation
                    || app.getActiveVault() != selected) {
                return null;
            }
            return new AutofillVaultSession(app, current, selected, generation);
        } catch (IllegalStateException exception) {
            return null;
        }
    }

    /** Separate, explicit vault and authentication binding prevents vault switching. */
    public boolean isCurrent() {
        try {
            if (SafeKeySession.getState() != SessionState.UNLOCKED) {
                return false;
            }
            long currentGeneration = SafeKeySession.getManager()
                    .getAuthenticationGeneration();
            SafeKeyApplication.ActiveVault currentVault = application.getActiveVault();
            if (currentVault != vaultIdentity || currentGeneration != authenticationGeneration) {
                return false;
            }
            VaultOperations currentOperations = application.getActiveVaultOperations();
            return matchesBinding(vaultIdentity, authenticationGeneration, operations,
                    currentVault, currentGeneration, currentOperations, true);
        } catch (IllegalStateException exception) {
            return false;
        }
    }

    /** Testable policy used by the production authorization check above. */
    static boolean matchesBinding(
            SafeKeyApplication.ActiveVault expectedVault,
            long expectedGeneration,
            Object expectedOperations,
            SafeKeyApplication.ActiveVault actualVault,
            long actualGeneration,
            Object actualOperations,
            boolean unlocked
    ) {
        return unlocked
                && expectedVault != null
                && expectedVault != SafeKeyApplication.ActiveVault.NONE
                && expectedVault == actualVault
                && expectedGeneration >= 0L
                && expectedGeneration == actualGeneration
                && expectedOperations != null
                && expectedOperations == actualOperations;
    }

    public void getCredentials(
            VaultDataService.ResultCallback<List<Credential>> callback
    ) {
        requestCredentialsForSession(this::isCurrent, operations, callback);
    }

    /** Re-fetch from the original vault before allowing dataset delivery. */
    public void getCredential(
            long id,
            VaultDataService.ResultCallback<Credential> callback
    ) {
        requestCredentialForSession(id, this::isCurrent, operations, callback);
    }

    /*
     * These package-private entry points use the exact production submission path.
     * Tests substitute a session predicate and rejecting VaultOperations so they
     * can reproduce a worker shutdown without unlocking a real vault.
     */
    static void requestCredentialsForSession(
            BooleanSupplier current,
            VaultOperations source,
            VaultDataService.ResultCallback<List<Credential>> callback
    ) {
        Objects.requireNonNull(callback, "callback");
        if (source == null) {
            callback.onError(sessionExpired());
            return;
        }
        submitLookup(current, source::getCredentials, callback);
    }

    static void requestCredentialForSession(
            long id,
            BooleanSupplier current,
            VaultOperations source,
            VaultDataService.ResultCallback<Credential> callback
    ) {
        Objects.requireNonNull(callback, "callback");
        if (id <= 0L || source == null) {
            callback.onError(sessionExpired());
            return;
        }
        submitLookup(current, result -> source.getCredential(id, result), callback);
    }

    @FunctionalInterface
    interface LookupSubmission<T> {
        void submit(VaultDataService.ResultCallback<T> callback);
    }

    /**
     * Worker shutdown may race with the session precheck. Convert synchronous
     * submission rejection to one error callback, not an uncaught exception.
     *
     * A worker that calls back inline and then throws must NOT release its
     * credential. The gate defers inline results until submission succeeds.
     */
    private static <T> void submitLookup(
            BooleanSupplier current,
            LookupSubmission<T> submission,
            VaultDataService.ResultCallback<T> callback
    ) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(callback, "callback");

        final boolean allowed;
        try {
            allowed = current.getAsBoolean();
        } catch (RuntimeException precheckError) {
            callback.onError(precheckError);
            return;
        }
        if (!allowed) {
            callback.onError(sessionExpired());
            return;
        }

        LookupDelivery<T> delivery = new LookupDelivery<>(current, callback);
        try {
            submission.submit(delivery);
        } catch (RuntimeException submissionError) {
            // Includes CancellationException and RejectedExecutionException.
            delivery.reject(submissionError);
            return;
        }
        delivery.accept();
    }

    /** Exactly-once result gate, including a callback-before-rejection race. */
    private static final class LookupDelivery<T>
            implements VaultDataService.ResultCallback<T> {

        private final BooleanSupplier current;
        private final VaultDataService.ResultCallback<T> destination;
        private boolean submitting = true;
        private boolean finished;
        private boolean hasPending;
        private boolean pendingSuccess;
        private T pendingValue;
        private Exception pendingError;

        LookupDelivery(BooleanSupplier current,
                       VaultDataService.ResultCallback<T> destination) {
            this.current = current;
            this.destination = destination;
        }

        @Override
        public void onSuccess(T value) {
            receive(true, value, null);
        }

        @Override
        public void onError(Exception error) {
            receive(false, null, error);
        }

        private void receive(boolean success, T value, Exception error) {
            synchronized (this) {
                if (finished) {
                    return;
                }
                if (submitting) {
                    if (!hasPending) {
                        hasPending = true;
                        pendingSuccess = success;
                        pendingValue = value;
                        pendingError = error;
                    }
                    return;
                }
                finished = true;
            }
            deliver(success, value, error);
        }

        void accept() {
            boolean deliverPending;
            boolean success;
            T value;
            Exception error;
            synchronized (this) {
                if (finished) {
                    return;
                }
                submitting = false;
                deliverPending = hasPending;
                success = pendingSuccess;
                value = pendingValue;
                error = pendingError;
                hasPending = false;
                pendingValue = null;
                pendingError = null;
                if (deliverPending) {
                    finished = true;
                }
            }
            if (deliverPending) {
                deliver(success, value, error);
            }
        }

        void reject(RuntimeException error) {
            synchronized (this) {
                if (finished) {
                    return;
                }
                finished = true;
                submitting = false;
                hasPending = false;
                pendingValue = null;
                pendingError = null;
            }
            destination.onError(error);
        }

        private void deliver(boolean success, T value, Exception error) {
            final boolean allowed;
            try {
                allowed = current.getAsBoolean();
            } catch (RuntimeException recheckError) {
                destination.onError(recheckError);
                return;
            }
            if (!allowed) {
                destination.onError(sessionExpired());
            } else if (success) {
                destination.onSuccess(value);
            } else {
                destination.onError(error);
            }
        }
    }

    private static IllegalStateException sessionExpired() {
        return new IllegalStateException(
                "The Autofill vault session is no longer active."
        );
    }
}
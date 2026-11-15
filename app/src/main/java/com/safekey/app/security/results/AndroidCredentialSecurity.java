
package com.safekey.app.security.results;

import android.os.Handler;
import android.os.Looper;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.breach.HibpRangeClient;
import com.safekey.app.breach.PasswordBreachCoordinator;
import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.generator.PasswordStrengthEvaluator;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.security.storage.VaultOperations;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.BooleanSupplier;

/**
 * Android adapters keep the reusable policy/controller
 * independent of Activities.
 */
public final class AndroidCredentialSecurity {

    private static final long INVALID_GENERATION = Long.MIN_VALUE;

    private AndroidCredentialSecurity() { }

    /**
     * Builds a controller bound to the specific authenticated
     * vault session.
     *
     * Call only after the app has activated a Real or Decoy Vault.
     *
     * Decoy analysis is local-only:
     * no breach-network checks or persistence.
     */
    public static CredentialSecurityController createForActiveVault(
            SafeKeyApplication app,
            boolean requestBreachChecks) {

        Objects.requireNonNull(app, "app");

        final SafeKeyApplication.ActiveVault selected =
                app.getActiveVault();

        if (selected == SafeKeyApplication.ActiveVault.NONE) {
            throw new IllegalStateException(
                    "An authenticated vault is required.");
        }

        // This instance belongs to this session.
        // Never fetch a replacement in callbacks.
        final VaultOperations selectedOperations =
                app.getActiveVaultOperations();

        final SecureVaultCoordinator realCoordinator =
                selected == SafeKeyApplication.ActiveVault.REAL
                        ? app.getSecureVaultCoordinator()
                        : null;

        final BooleanSupplier sessionValid = () -> {

            if (SafeKeySession.getState() != SessionState.UNLOCKED) {
                return false;
            }

            try {
                return app.getActiveVault() == selected
                        && app.getActiveVaultOperations()
                        == selectedOperations;

            } catch (IllegalStateException exception) {
                return false;
            }
        };

        CredentialSecurityController.Source source =
                new CredentialSecurityController.Source() {

                    @Override
                    public long getGeneration() {

                        if (!sessionValid.getAsBoolean()) {
                            return INVALID_GENERATION;
                        }

                        // The Decoy path has no breach-generation API.
                        // Session identity provides its lifetime boundary.
                        // Its controller is read-only.
                        return realCoordinator == null
                                ? 1L
                                : realCoordinator.getVaultGeneration();
                    }

                    @Override
                    public void load(
                            CredentialSecurityController.Result<List<Credential>>
                                    callback) {

                        if (!sessionValid.getAsBoolean()) {
                            callback.onError(
                                    new IllegalStateException(
                                            "Vault session expired."));
                            return;
                        }

                        // Session-bound operations reject callbacks
                        // from previous authenticated sessions.
                        selectedOperations.getCredentials(adapt(callback));
                    }

                    @Override
                    public void save(
                            long generation,
                            long id,
                            String expectedPassword,
                            PasswordBreachResult.Status status,
                            CredentialSecurityController.Result<
                                    PasswordBreachResult.Status> callback) {

                        if (realCoordinator == null
                                || !sessionValid.getAsBoolean()
                                || realCoordinator.getVaultGeneration()
                                != generation) {

                            callback.onError(
                                    new IllegalStateException(
                                            "Breach results cannot be saved "
                                                    + "in this vault session."));
                            return;
                        }

                        realCoordinator.updateCredentialBreachStatus(
                                generation,
                                id,
                                expectedPassword,
                                status,
                                adapt(callback));
                    }
                };

        // Only the authenticated Real Vault can run HIBP checks
        // and persist breach results.
        return newController(
                source,
                sessionValid,
                requestBreachChecks && realCoordinator != null);
    }

    /**
     * Legacy Real Vault adapter retained for existing
     * callers and tests.
     *
     * New UI integrations should use createForActiveVault.
     */
    public static CredentialSecurityController create(
            SecureVaultCoordinator vault,
            boolean checks) {

        Objects.requireNonNull(vault, "vault");

        CredentialSecurityController.Source source =
                new CredentialSecurityController.Source() {

                    @Override
                    public long getGeneration() {
                        return vault.getVaultGeneration();
                    }

                    @Override
                    public void load(
                            CredentialSecurityController.Result<List<Credential>>
                                    callback) {

                        vault.getCredentials(adapt(callback));
                    }

                    @Override
                    public void save(
                            long generation,
                            long id,
                            String expectedPassword,
                            PasswordBreachResult.Status status,
                            CredentialSecurityController.Result<
                                    PasswordBreachResult.Status> callback) {

                        vault.updateCredentialBreachStatus(
                                generation,
                                id,
                                expectedPassword,
                                status,
                                adapt(callback));
                    }
                };

        return newController(
                source,
                () -> SafeKeySession.getState()
                        == SessionState.UNLOCKED,
                checks);
    }

    private static CredentialSecurityController newController(
            CredentialSecurityController.Source source,
            BooleanSupplier sessionValid,
            boolean checks) {

        Handler handler = new Handler(Looper.getMainLooper());

        Executor main = action -> {

            if (!handler.post(action)) {
                throw new RejectedExecutionException(
                        "UI delivery unavailable.");
            }
        };

        HibpRangeClient client =
                checks ? new HibpRangeClient() : null;

        PasswordBreachCoordinator breaches =
                checks ? new PasswordBreachCoordinator(client) : null;

        CredentialSecurityController.Checker checker =
                (password, callback) -> {

                    if (breaches == null) {
                        throw new IllegalStateException(
                                "Read-only security analysis.");
                    }

                    PasswordBreachCoordinator.Request request =
                            breaches.check(
                                    password,
                                    callback::accept);

                    return request::close;
                };

        CredentialSecurityController.StrengthEstimator strength =
                new CredentialSecurityController.StrengthEstimator() {

                    private PasswordStrengthEvaluator evaluator;

                    @Override
                    public int evaluate(char[] password) {

                        if (evaluator == null) {
                            evaluator = new PasswordStrengthEvaluator();
                        }

                        return evaluator.evaluate(password).getScore();
                    }
                };

        return new CredentialSecurityController(
                source,
                checker,
                strength,
                Executors.newSingleThreadExecutor(),
                main,
                sessionValid,
                () -> {

                    if (breaches != null) {
                        breaches.shutdown();
                    }

                    if (client != null) {
                        client.shutdown();
                    }
                },
                checks);
    }

    private static <T> VaultDataService.ResultCallback<T> adapt(
            CredentialSecurityController.Result<T> callback) {

        return new VaultDataService.ResultCallback<T>() {

            @Override
            public void onSuccess(T result) {
                callback.onSuccess(result);
            }

            @Override
            public void onError(Exception error) {
                callback.onError(error);
            }
        };
    }
}

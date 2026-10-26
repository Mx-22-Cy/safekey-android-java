package com.safekey.app.security.results;

import android.os.Handler;
import android.os.Looper;

import com.safekey.app.breach.HibpRangeClient;
import com.safekey.app.breach.PasswordBreachCoordinator;
import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.data.model.Credential;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.generator.PasswordStrengthEvaluator;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.logic.SessionState;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/** Android adapters keep the reusable policy/controller independent of Activities. */
public final class AndroidCredentialSecurity {
    private AndroidCredentialSecurity() { }

    public static CredentialSecurityController create(SecureVaultCoordinator vault, boolean checks) {
        Handler handler = new Handler(Looper.getMainLooper());
        Executor main = action -> {
            if (!handler.post(action)) { throw new RejectedExecutionException("UI delivery unavailable."); }
        };
        HibpRangeClient client = checks ? new HibpRangeClient() : null;
        PasswordBreachCoordinator breaches = checks ? new PasswordBreachCoordinator(client) : null;
        CredentialSecurityController.Checker checker = (password, callback) -> {
            if (breaches == null) { throw new IllegalStateException("Read-only security analysis."); }
            PasswordBreachCoordinator.Request request = breaches.check(password, callback::accept);
            return request::close;
        };
        CredentialSecurityController.StrengthEstimator strength = new CredentialSecurityController.StrengthEstimator() {
            private PasswordStrengthEvaluator evaluator;
            @Override public int evaluate(char[] password) {
                if (evaluator == null) { evaluator = new PasswordStrengthEvaluator(); }
                return evaluator.evaluate(password).getScore();
            }
        };
        CredentialSecurityController.Source source = new CredentialSecurityController.Source() {
            @Override public long getGeneration() { return vault.getVaultGeneration(); }
            @Override public void load(CredentialSecurityController.Result<List<Credential>> callback) {
                vault.getCredentials(adapt(callback));
            }
            @Override public void save(long generation, long id, String expectedPassword,
                                       PasswordBreachResult.Status status,
                                       CredentialSecurityController.Result<PasswordBreachResult.Status> callback) {
                vault.updateCredentialBreachStatus(generation, id, expectedPassword, status, adapt(callback));
            }
        };
        return new CredentialSecurityController(source, checker, strength,
                Executors.newSingleThreadExecutor(), main,
                () -> SafeKeySession.getState() == SessionState.UNLOCKED,
                () -> {
                    if (breaches != null) { breaches.shutdown(); }
                    if (client != null) { client.shutdown(); }
                }, checks);
    }

    private static <T> VaultDataService.ResultCallback<T> adapt(CredentialSecurityController.Result<T> callback) {
        return new VaultDataService.ResultCallback<T>() {
            @Override public void onSuccess(T result) { callback.onSuccess(result); }
            @Override public void onError(Exception error) { callback.onError(error); }
        };
    }
}

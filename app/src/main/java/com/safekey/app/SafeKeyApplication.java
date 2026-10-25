package com.safekey.app;

import android.app.Application;
import android.util.Log;

import com.safekey.app.auth.MasterPasswordHealth;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.session.SafeKeySession;

public final class SafeKeyApplication extends Application {

    private SecureVaultCoordinator secureVaultCoordinator;
    private MasterPasswordHealth masterPasswordHealth;

    @Override
    public void onCreate() {
        super.onCreate();

        secureVaultCoordinator =
                new SecureVaultCoordinator(this);

        masterPasswordHealth = new MasterPasswordHealth(this);

        registerSessionCleanup();
    }

    public void registerSessionCleanup() {
        SafeKeySession.registerSensitiveDataCleanup(
                () -> {
                    masterPasswordHealth.cancelRecheck();
                    secureVaultCoordinator.closeVault(
                        new VaultDataService.SimpleCallback() {
                            @Override
                            public void onSuccess() {
                                // The vault connection is closed.
                            }

                            @Override
                            public void onError(Exception exception) {
                                Log.e(
                                        "SafeKeyApplication",
                                        "Failed to close the vault after session lock."
                                );
                            }
                        }
                    );
                }
        );
    }
    public MasterPasswordHealth getMasterPasswordHealth() {
        return masterPasswordHealth;
    }

    public SecureVaultCoordinator getSecureVaultCoordinator() {
        return secureVaultCoordinator;
    }
}

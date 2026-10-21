package com.safekey.app;

import android.app.Application;
import android.util.Log;

import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.DecoyVaultStorage;
import com.safekey.app.security.storage.SecureVaultCoordinator;
import com.safekey.app.session.SafeKeySession;

public final class SafeKeyApplication extends Application {

    private SecureVaultCoordinator secureVaultCoordinator;

    @Override
    public void onCreate() {
        super.onCreate();

        /*
         * Week 10 Decoy Vault storage requirement.
         *
         * Keep the secondary encrypted database present
         * regardless of whether Decoy enrollment has occurred.
         * This happens before authentication UI is displayed.
         */
        DecoyVaultStorage.ensureDatabaseFile(
                this
        );

        secureVaultCoordinator =
                new SecureVaultCoordinator(
                        this
                );

        registerSessionCleanup();
    }

    public void registerSessionCleanup() {
        SafeKeySession.registerSensitiveDataCleanup(
                () -> secureVaultCoordinator.closeVault(
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
                )
        );
    }

    public SecureVaultCoordinator getSecureVaultCoordinator() {
        return secureVaultCoordinator;
    }
}

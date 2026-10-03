package com.safekey.app;

import android.app.Application;

import com.safekey.app.security.storage.SecureVaultCoordinator;

public final class SafeKeyApplication extends Application {

    private SecureVaultCoordinator secureVaultCoordinator;

    @Override
    public void onCreate() {

        super.onCreate();

        secureVaultCoordinator =
                new SecureVaultCoordinator(
                        this
                );
    }

    public SecureVaultCoordinator getSecureVaultCoordinator() {
        return secureVaultCoordinator;
    }
}
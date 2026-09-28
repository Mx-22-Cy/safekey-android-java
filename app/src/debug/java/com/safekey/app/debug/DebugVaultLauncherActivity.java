package com.safekey.app.debug;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.session.SafeKeySession;
import com.safekey.app.vault.VaultActivity;

public class DebugVaultLauncherActivity extends AppCompatActivity {

    @Override
    protected void onCreate(
            Bundle savedInstanceState
    ) {

        super.onCreate(
                savedInstanceState
        );

        /*
         * DEBUG BUILD ONLY.
         *
         * This bypass exists only so the Week 4 Vault UI
         * can be tested before real authentication
         * integration is completed.
         *
         * Never move this call into production code.
         */
        SafeKeySession.getManager()
                .unlockAfterAuthentication();

        Intent intent =
                new Intent(
                        DebugVaultLauncherActivity.this,
                        VaultActivity.class
                );

        startActivity(
                intent
        );

        finish();
    }
}
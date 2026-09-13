package com.safekey.app.home;

import android.graphics.Color;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.R;

public class HomeActivity extends AppCompatActivity {

    private SecurityScoreView securityScoreView;

    private TextView textAtRiskCount;
    private TextView textBreachCount;
    private TextView textCredentialCount;
    private TextView textFavoriteCount;
    private TextView textSecureNoteCount;

    @Override
    protected void onCreate(
            Bundle savedInstanceState
    ) {

        super.onCreate(savedInstanceState);

        getWindow().setStatusBarColor(
                Color.parseColor("#050B15")
        );

        getWindow().setNavigationBarColor(
                Color.parseColor("#050B15")
        );

        setContentView(
                R.layout.activity_home
        );

        securityScoreView =
                findViewById(
                        R.id.securityScoreView
                );

        textAtRiskCount =
                findViewById(
                        R.id.textAtRiskCount
                );

        textBreachCount =
                findViewById(
                        R.id.textBreachCount
                );

        textCredentialCount =
                findViewById(
                        R.id.textCredentialCount
                );

        textFavoriteCount =
                findViewById(
                        R.id.textFavoriteCount
                );

        textSecureNoteCount =
                findViewById(
                        R.id.textSecureNoteCount
                );

        Button buttonOpenVault =
                findViewById(
                        R.id.buttonOpenVault
                );

        Button buttonAddCredential =
                findViewById(
                        R.id.buttonAddCredential
                );

        showPreviewData();

        buttonOpenVault.setOnClickListener(
                view ->
                        Toast.makeText(
                                this,
                                "Vault navigation will be connected during integration.",
                                Toast.LENGTH_SHORT
                        ).show()
        );

        buttonAddCredential.setOnClickListener(
                view ->
                        Toast.makeText(
                                this,
                                "Credential creation will be connected during integration.",
                                Toast.LENGTH_SHORT
                        ).show()
        );
    }

    private void showPreviewData() {

        /*
         * UI PREVIEW DATA ONLY.
         *
         * These values are intentionally not read
         * from the real encrypted vault yet.
         */

        securityScoreView.setScore(
                82
        );

        textAtRiskCount.setText(
                "2"
        );

        textBreachCount.setText(
                "1"
        );

        textCredentialCount.setText(
                "12"
        );

        textFavoriteCount.setText(
                "4"
        );

        textSecureNoteCount.setText(
                "3"
        );

        /*
         * TODO(Maryam/security integration):
         *
         * Replace the preview Security Score,
         * at-risk count and breach-alert count
         * with values produced by the approved
         * security layer.
         *
         * Breach checking must use the project's
         * privacy-preserving HIBP k-anonymity design.
         *
         * Never send plaintext passwords
         * to an external breach service.
         *
         * TODO(Data/UI integration):
         *
         * Replace credential, favorite and note
         * preview counts with values obtained through
         * VaultDataService after secure vault unlock.
         */
    }
}
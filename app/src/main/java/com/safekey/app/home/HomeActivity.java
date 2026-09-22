package com.safekey.app.home;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.safekey.app.R;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

public class HomeActivity extends AppCompatActivity {

    private static final int PREVIEW_SECURITY_SCORE = 82;

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
        WindowCompat.enableEdgeToEdge(
                getWindow()
        );

        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.setAppearanceLightStatusBars(false);
        insetsController.setAppearanceLightNavigationBars(false);

        setContentView(
                R.layout.activity_home
        );
        android.view.View rootHome =
                findViewById(
                        R.id.rootHome
                );

        ViewCompat.setOnApplyWindowInsetsListener(
                rootHome,
                (view, windowInsets) -> {

                    Insets systemBars =
                            windowInsets.getInsets(
                                    WindowInsetsCompat.Type.systemBars()
                            );

                    view.setPadding(
                            systemBars.left,
                            systemBars.top,
                            systemBars.right,
                            systemBars.bottom
                    );

                    return windowInsets;
                }
        );

        ViewCompat.requestApplyInsets(
                rootHome
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
                                R.string.home_vault_navigation_pending,
                                Toast.LENGTH_SHORT
                        ).show()
        );

        buttonAddCredential.setOnClickListener(
                view ->
                        Toast.makeText(
                                this,
                                R.string.home_credential_creation_pending,
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
                PREVIEW_SECURITY_SCORE
        );

        textAtRiskCount.setText(
                R.string.home_preview_at_risk_count
        );

        textBreachCount.setText(
                R.string.home_preview_breach_count
        );

        textCredentialCount.setText(
                R.string.home_preview_credential_count
        );

        textFavoriteCount.setText(
                R.string.home_preview_favorite_count
        );

        textSecureNoteCount.setText(
                R.string.home_preview_secure_note_count
        );

        /*
         * TODO(Security integration):
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
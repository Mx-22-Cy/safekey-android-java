package com.safekey.app.generator;

import android.os.Bundle;
import android.os.PersistableBundle;
import android.widget.CheckBox;
import android.widget.ProgressBar;
import android.widget.SeekBar;
import android.widget.TextView;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.widget.Toast;
import android.content.Intent;
import android.view.View;
import android.annotation.SuppressLint;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.appcompat.widget.AppCompatImageButton;

import com.safekey.app.R;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.session.ProtectedActivity;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.vault.VaultActivity;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GeneratorActivity extends ProtectedActivity {

    public static final String EXTRA_SELECTION_MODE =
            "generator_selection_mode";

    public static final String EXTRA_GENERATED_PASSWORD =
            "generated_password";

    private TextView textGeneratedPassword;
    private TextView textStrengthLabel;
    private TextView textStrengthFeedback;
    private TextView textPasswordLength;
    private TextView textPasswordLengthMin;
    private TextView textPasswordLengthMax;

    private ProgressBar progressPasswordStrength;
    private SeekBar seekPasswordLength;

    private CheckBox checkUppercase;
    private CheckBox checkLowercase;
    private CheckBox checkNumbers;
    private CheckBox checkSymbols;

    private AppCompatImageButton buttonToggleGeneratedPassword;

    private AppCompatImageButton buttonBackGenerator;

    private TextView buttonCopyPassword;
    private TextView buttonRegeneratePassword;
    private TextView buttonUsePassword;
    private char[] generatedPassword;
    private boolean passwordVisible = false;
    private boolean lengthSliderTracking = false;
    private final PasswordGenerator passwordGenerator =
            new PasswordGenerator();
    private static final int MAX_STRENGTH_SCORE = 4;

    private final PasswordStrengthEvaluator passwordStrengthEvaluator =
            new PasswordStrengthEvaluator();

    private final ExecutorService strengthExecutor =
            Executors.newSingleThreadExecutor();
    private int strengthRequestId = 0;

    private final class StrengthEvaluationTask implements Runnable {

        private char[] passwordSnapshot;
        private final int requestId;

        private StrengthEvaluationTask(
                char[] passwordSnapshot,
                int requestId
        ) {
            this.passwordSnapshot = passwordSnapshot;
            this.requestId = requestId;
        }

        @Override
        public void run() {

            PasswordStrengthResult result;

            try {
                result =
                        passwordStrengthEvaluator.evaluate(
                                passwordSnapshot
                        );
            } finally {
                clearPasswordSnapshot();
            }

            runOnUiThread(
                    () -> {
                        if (requestId != strengthRequestId
                                || isFinishing()
                                || isDestroyed()) {
                            return;
                        }

                        displayStrengthResult(result);
                    }
            );
        }

        private void clearPasswordSnapshot() {
            if (passwordSnapshot != null) {
                Arrays.fill(
                        passwordSnapshot,
                        '\0'
                );
                passwordSnapshot = null;
            }
        }
    }
    private View bottomNavigationGenerator;

    private View navHome;
    private View navVault;
    private View navAlerts;
    private View navSettings;

    @Override
    protected void onCreate(
            Bundle savedInstanceState
    ) {

        super.onCreate(
                savedInstanceState
        );

        WindowCompat.enableEdgeToEdge(
                getWindow()
        );

        WindowInsetsControllerCompat insetsController =
                WindowCompat.getInsetsController(
                        getWindow(),
                        getWindow().getDecorView()
                );

        insetsController.setAppearanceLightStatusBars(
                false
        );

        insetsController.setAppearanceLightNavigationBars(
                false
        );

        setContentView(
                R.layout.activity_generator
        );

        bindViews();

        setupSelectionMode();

        setupGeneratorDefaults();

        setupLengthControl();

        generatePassword();

        setupGeneratorActions();

        setupCharacterTypeControls();

        ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(
                        R.id.rootGenerator
                ),
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
    }

    private void setupSelectionMode() {

        boolean selectionMode =
                getIntent().getBooleanExtra(
                        EXTRA_SELECTION_MODE,
                        false
                );

        buttonUsePassword.setVisibility(
                selectionMode
                        ? View.VISIBLE
                        : View.GONE
        );

        bottomNavigationGenerator.setVisibility(
                selectionMode
                        ? View.GONE
                        : View.VISIBLE
        );

        buttonBackGenerator.setVisibility(
                selectionMode
                        ? View.VISIBLE
                        : View.GONE
        );
    }

    private void bindViews() {

        textGeneratedPassword =
                findViewById(
                        R.id.textGeneratedPassword
                );

        textStrengthLabel =
                findViewById(
                        R.id.textStrengthLabel
                );

        textStrengthFeedback =
                findViewById(
                        R.id.textStrengthFeedback
                );

        textPasswordLength =
                findViewById(
                        R.id.textPasswordLength
                );

        textPasswordLengthMin =
                findViewById(
                        R.id.textPasswordLengthMin
                );

        textPasswordLengthMax =
                findViewById(
                        R.id.textPasswordLengthMax
                );

        progressPasswordStrength =
                findViewById(
                        R.id.progressPasswordStrength
                );

        seekPasswordLength =
                findViewById(
                        R.id.seekPasswordLength
                );

        checkUppercase =
                findViewById(
                        R.id.checkUppercase
                );

        checkLowercase =
                findViewById(
                        R.id.checkLowercase
                );

        checkNumbers =
                findViewById(
                        R.id.checkNumbers
                );

        checkSymbols =
                findViewById(
                        R.id.checkSymbols
                );

        buttonToggleGeneratedPassword =
                findViewById(
                        R.id.buttonToggleGeneratedPassword
                );

        buttonCopyPassword =
                findViewById(
                        R.id.buttonCopyPassword
                );

        buttonRegeneratePassword =
                findViewById(
                        R.id.buttonRegeneratePassword
                );

        buttonUsePassword =
                findViewById(
                        R.id.buttonUsePassword
                );

        buttonBackGenerator =
                findViewById(
                        R.id.buttonBackGenerator
                );

        bottomNavigationGenerator =
                findViewById(
                        R.id.bottomNavigationGenerator
                );

        navHome =
                findViewById(
                        R.id.navHome
                );

        navVault =
                findViewById(
                        R.id.navVault
                );

        navAlerts =
                findViewById(
                        R.id.navAlerts
                );

        navSettings =
                findViewById(
                        R.id.navSettings
                );
    }

    private void setupGeneratorDefaults() {

        int minLength =
                PasswordGenerator.MIN_LENGTH;

        int maxLength =
                PasswordGenerator.MAX_LENGTH;

        int defaultLength =
                PasswordGenerator.DEFAULT_LENGTH;

        textPasswordLengthMin.setText(
                String.valueOf(minLength)
        );

        textPasswordLengthMax.setText(
                String.valueOf(maxLength)
        );

        textPasswordLength.setText(
                String.valueOf(defaultLength)
        );

        seekPasswordLength.setMax(
                maxLength - minLength
        );

        seekPasswordLength.setProgress(
                defaultLength - minLength
        );

        progressPasswordStrength.setMax(
                MAX_STRENGTH_SCORE
        );

        checkUppercase.setChecked(
                true
        );

        checkLowercase.setChecked(
                true
        );

        checkNumbers.setChecked(
                true
        );

        checkSymbols.setChecked(
                true
        );
    }

    private void setupLengthControl() {

        seekPasswordLength.setOnSeekBarChangeListener(
                new SeekBar.OnSeekBarChangeListener() {

                    @Override
                    public void onProgressChanged(
                            SeekBar seekBar,
                            int progress,
                            boolean fromUser
                    ) {

                        int length =
                                PasswordGenerator.MIN_LENGTH
                                        + progress;

                        textPasswordLength.setText(
                                String.valueOf(length)
                        );

                        if (fromUser && !lengthSliderTracking) {
                            generatePassword();
                        }
                    }

                    @Override
                    public void onStartTrackingTouch(
                            SeekBar seekBar
                    ) {
                        lengthSliderTracking = true;
                    }

                    @Override
                    public void onStopTrackingTouch(
                            SeekBar seekBar
                    ) {
                        lengthSliderTracking = false;
                        generatePassword();
                    }
                }
        );
    }

    private void generatePassword() {

        int length =
                PasswordGenerator.MIN_LENGTH
                        + seekPasswordLength.getProgress();

        boolean useUppercase =
                checkUppercase.isChecked();

        boolean useLowercase =
                checkLowercase.isChecked();

        boolean useNumbers =
                checkNumbers.isChecked();

        boolean useSymbols =
                checkSymbols.isChecked();

        if (!useUppercase
                && !useLowercase
                && !useNumbers
                && !useSymbols) {

            return;
        }

        if (generatedPassword != null) {

            Arrays.fill(
                    generatedPassword,
                    '\0'
            );
        }

        generatedPassword =
                passwordGenerator.generate(
                        length,
                        useLowercase,
                        useUppercase,
                        useNumbers,
                        useSymbols
                );

        updateGeneratedPasswordDisplay();

        evaluateGeneratedPasswordStrength();
    }

    private void updateGeneratedPasswordDisplay() {

        if (generatedPassword == null) {

            textGeneratedPassword.setText("");
            return;
        }

        if (passwordVisible) {

            textGeneratedPassword.setText(
                    new String(
                            generatedPassword
                    )
            );

            return;
        }

        char[] hiddenPassword =
                new char[generatedPassword.length];

        Arrays.fill(
                hiddenPassword,
                '•'
        );

        textGeneratedPassword.setText(
                new String(
                        hiddenPassword
                )
        );

        Arrays.fill(
                hiddenPassword,
                '\0'
        );
    }

    private void evaluateGeneratedPasswordStrength() {

        if (generatedPassword == null
                || generatedPassword.length == 0) {
            return;
        }

        textStrengthLabel.setText(
                R.string.generator_strength_checking
        );
        textStrengthFeedback.setText("");
        progressPasswordStrength.setProgress(0);

        char[] passwordSnapshot =
                generatedPassword.clone();

        int requestId =
                ++strengthRequestId;

        strengthExecutor.execute(
                new StrengthEvaluationTask(
                        passwordSnapshot,
                        requestId
                )
        );
    }

    private void displayStrengthResult(
            PasswordStrengthResult result
    ) {

        if (result == null || result.isEmpty()) {
            textStrengthLabel.setText("");
            textStrengthFeedback.setText("");
            progressPasswordStrength.setProgress(0);

            return;
        }

        int score =
                result.getScore();

        progressPasswordStrength.setProgress(
                score
        );

        int labelResource;
        int colorResource;

        switch (score) {

            case 0:
                labelResource =
                        R.string.generator_strength_very_weak;

                colorResource =
                        R.color.vault_risk_red;
                break;

            case 1:
                labelResource =
                        R.string.generator_strength_weak;

                colorResource =
                        R.color.vault_risk_red;
                break;

            case 2:
                labelResource =
                        R.string.generator_strength_fair;

                colorResource =
                        R.color.vault_risk_amber;
                break;

            case 3:
                labelResource =
                        R.string.generator_strength_strong;

                colorResource =
                        R.color.vault_accent;
                break;

            case 4:
                labelResource =
                        R.string.generator_strength_very_strong;

                colorResource =
                        R.color.vault_accent;
                break;

            default:
                return;
        }

        String label =
                getString(
                        labelResource
                );

        int color =
                getColor(
                        colorResource
                );

        textStrengthLabel.setText(
                label
        );

        textStrengthLabel.setTextColor(
                color
        );

        progressPasswordStrength.setProgressTintList(
                android.content.res.ColorStateList.valueOf(
                        color
                )
        );

        String warning =
                result.getWarning();

        if (warning != null
                && !warning.trim().isEmpty()) {

            textStrengthFeedback.setText(
                    warning
            );

            return;
        }

        if (!result.getSuggestions().isEmpty()) {

            textStrengthFeedback.setText(
                    result.getSuggestions().get(0)
            );

            return;
        }

        textStrengthFeedback.setText("");
    }
    private void setupGeneratorActions() {

        buttonRegeneratePassword.setOnClickListener(
                view ->
                        generatePassword()
        );

        buttonToggleGeneratedPassword.setOnClickListener(
                view ->
                        toggleGeneratedPasswordVisibility()
        );

        buttonCopyPassword.setOnClickListener(
                view ->
                        copyGeneratedPassword()
        );

        buttonUsePassword.setOnClickListener(
                view ->
                        returnGeneratedPassword()
        );

        buttonBackGenerator.setOnClickListener(
                view ->
                        finish()
        );

        navHome.setOnClickListener(
                view -> {

                    Intent intent =
                            new Intent(
                                    GeneratorActivity.this,
                                    HomeActivity.class
                            );

                    intent.addFlags(
                            Intent.FLAG_ACTIVITY_CLEAR_TOP
                                    | Intent.FLAG_ACTIVITY_SINGLE_TOP
                    );

                    startActivity(
                            intent
                    );

                    finish();
                }
        );

        navVault.setOnClickListener(
                view -> {

                    Intent intent =
                            new Intent(
                                    GeneratorActivity.this,
                                    VaultActivity.class
                            );

                    intent.addFlags(
                            Intent.FLAG_ACTIVITY_CLEAR_TOP
                                    | Intent.FLAG_ACTIVITY_SINGLE_TOP
                    );

                    startActivity(
                            intent
                    );

                    finish();
                }
        );

        navAlerts.setOnClickListener(
                view -> {

                    if (!requireUnlockedSession()) {
                        return;
                    }

                    Toast.makeText(
                            GeneratorActivity.this,
                            R.string.home_alerts_navigation_pending,
                            Toast.LENGTH_SHORT
                    ).show();
                }
        );

        navSettings.setOnClickListener(
                view -> {

                    if (!requireUnlockedSession()) {
                        return;
                    }

                    Toast.makeText(
                            GeneratorActivity.this,
                            R.string.home_settings_navigation_pending,
                            Toast.LENGTH_SHORT
                    ).show();
                }
        );
    }

    private void returnGeneratedPassword() {

        if (generatedPassword == null
                || generatedPassword.length == 0) {
            return;
        }

        Intent resultIntent =
                new Intent();

        resultIntent.putExtra(
                EXTRA_GENERATED_PASSWORD,
                new String(
                        generatedPassword
                )
        );

        setResult(
                RESULT_OK,
                resultIntent
        );

        finish();
    }

    @SuppressLint("InlinedApi")
    private void copyGeneratedPassword() {

        if (generatedPassword == null
                || generatedPassword.length == 0) {
            return;
        }

        ClipboardManager clipboardManager =
                (ClipboardManager) getSystemService(
                        Context.CLIPBOARD_SERVICE
                );

        ClipData clipData =
                ClipData.newPlainText(
                        getString(
                                R.string.generator_password_content_description
                        ),
                        new String(
                                generatedPassword
                        )
                );

        PersistableBundle clipDescriptionExtras =
                new PersistableBundle();
        clipDescriptionExtras.putBoolean(
                ClipDescription.EXTRA_IS_SENSITIVE,
                true
        );
        clipData.getDescription().setExtras(
                clipDescriptionExtras
        );

        clipboardManager.setPrimaryClip(
                clipData
        );

        Toast.makeText(
                this,
                R.string.generator_copy_success,
                Toast.LENGTH_SHORT
        ).show();
    }

    private void toggleGeneratedPasswordVisibility() {

        passwordVisible =
                !passwordVisible;

        if (passwordVisible) {

            textGeneratedPassword.setText(
                    generatedPassword == null
                            ? ""
                            : new String(generatedPassword)
            );

            buttonToggleGeneratedPassword.setImageResource(
                    R.drawable.ic_password_visible
            );

            buttonToggleGeneratedPassword.setContentDescription(
                    getString(
                            R.string.hide_password_content_description
                    )
            );

        } else {

            if (generatedPassword == null) {

                textGeneratedPassword.setText("");

            } else {

                char[] hiddenPassword =
                        new char[generatedPassword.length];

                Arrays.fill(
                        hiddenPassword,
                        '•'
                );

                textGeneratedPassword.setText(
                        new String(hiddenPassword)
                );

                Arrays.fill(
                        hiddenPassword,
                        '\0'
                );
            }

            buttonToggleGeneratedPassword.setImageResource(
                    R.drawable.ic_password_hidden
            );

            buttonToggleGeneratedPassword.setContentDescription(
                    getString(
                            R.string.show_password_content_description
                    )
            );
        }
    }

    private void setupCharacterTypeControls() {

        checkUppercase.setOnCheckedChangeListener(
                (buttonView, isChecked) ->
                        handleCharacterTypeChanged(
                                checkUppercase
                        )
        );

        checkLowercase.setOnCheckedChangeListener(
                (buttonView, isChecked) ->
                        handleCharacterTypeChanged(
                                checkLowercase
                        )
        );

        checkNumbers.setOnCheckedChangeListener(
                (buttonView, isChecked) ->
                        handleCharacterTypeChanged(
                                checkNumbers
                        )
        );

        checkSymbols.setOnCheckedChangeListener(
                (buttonView, isChecked) ->
                        handleCharacterTypeChanged(
                                checkSymbols
                        )
        );
    }

    private void handleCharacterTypeChanged(
            CheckBox changedCheckBox
    ) {

        boolean anySelected =
                checkUppercase.isChecked()
                        || checkLowercase.isChecked()
                        || checkNumbers.isChecked()
                        || checkSymbols.isChecked();

        if (!anySelected) {

            changedCheckBox.setChecked(
                    true
            );

            return;
        }

        generatePassword();
    }

    private boolean requireUnlockedSession() {

        if (!SafeKeySession.recordActivity()) {

            navigateToSignIn();

            return false;
        }

        return true;
    }

    private void navigateToSignIn() {

        if (isFinishing()) {
            return;
        }

        Toast.makeText(
                this,
                R.string.home_session_locked,
                Toast.LENGTH_SHORT
        ).show();

        Intent intent =
                new Intent(
                        GeneratorActivity.this,
                        SignInActivity.class
                );

        intent.addFlags(
                Intent.FLAG_ACTIVITY_CLEAR_TOP
        );

        startActivity(
                intent
        );

        finish();
    }

    @Override
    protected void onDestroy() {

        strengthRequestId++;

        List<Runnable> cancelledTasks =
                strengthExecutor.shutdownNow();

        for (Runnable task : cancelledTasks) {
            if (task instanceof StrengthEvaluationTask) {
                ((StrengthEvaluationTask) task)
                        .clearPasswordSnapshot();
            }
        }

        if (generatedPassword != null) {

            Arrays.fill(
                    generatedPassword,
                    '\0'
            );

            generatedPassword = null;
        }

        textGeneratedPassword.setText("");

        super.onDestroy();
    }
}
package com.safekey.app.vault;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.util.TypedValue;
import android.view.ViewGroup;
import android.widget.PopupWindow;
import android.widget.TextView;
import android.widget.PopupMenu;
import android.text.Editable;
import android.text.TextWatcher;

import com.safekey.app.session.ProtectedActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.core.content.ContextCompat;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.recyclerview.widget.ConcatAdapter;

import com.safekey.app.R;
import com.safekey.app.auth.SignInActivity;
import com.safekey.app.data.model.Credential;
import com.safekey.app.home.HomeActivity;
import com.safekey.app.session.SafeKeySession;
import com.safekey.app.data.model.SecureNote;
import com.safekey.app.SafeKeyApplication;
import com.safekey.app.data.service.VaultDataService;
import com.safekey.app.security.storage.SecureVaultCoordinator;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class VaultActivity extends ProtectedActivity {

    private VaultCredentialAdapter adapter;
    private SecureVaultCoordinator secureVaultCoordinator;
    private VaultSecureNoteAdapter noteAdapter;
    private RecyclerView recyclerVault;

    private View layoutVaultState;
    private View layoutVaultLoading;
    private View layoutVaultEmpty;
    private View layoutVaultError;

    private ConcatAdapter allItemsAdapter;

    private final List<SecureNote> allNotes =
            new ArrayList<>();
    private final List<Credential> allCredentials =
            new ArrayList<>();

    private final List<VaultCredentialAdapter.RiskStatus> allRiskStatuses =
            new ArrayList<>();

    private enum VaultFilter {
        ALL,
        FAVORITES,
        NOTES
    }

    private VaultFilter activeFilter =
            VaultFilter.ALL;

    private String currentSearchQuery = "";

    private TextView filterAll;
    private TextView filterFavorites;

    private TextView filterNotes;

    @Override
    protected void onCreate(
            Bundle savedInstanceState
    ) {

        super.onCreate(
                savedInstanceState
        );

        secureVaultCoordinator =
                ((SafeKeyApplication) getApplication())
                        .getSecureVaultCoordinator();

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
                R.layout.activity_vault
        );

        View rootVault =
                findViewById(
                        R.id.rootVault
                );

        ViewCompat.setOnApplyWindowInsetsListener(
                rootVault,
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
                rootVault
        );

        setupCredentialList();
        setupSearch();
        setupFilters();
        setupActions();
    }

    private void setupCredentialList() {

        recyclerVault =
                findViewById(
                        R.id.recyclerVault
                );

        layoutVaultState =
                findViewById(
                        R.id.layoutVaultState
                );

        layoutVaultLoading =
                findViewById(
                        R.id.layoutVaultLoading
                );

        layoutVaultEmpty =
                findViewById(
                        R.id.layoutVaultEmpty
                );

        layoutVaultError =
                findViewById(
                        R.id.layoutVaultError
                );

        recyclerVault.setLayoutManager(
                new LinearLayoutManager(
                        this
                )
        );

        adapter =
                new VaultCredentialAdapter(
                        new VaultCredentialAdapter.OnCredentialActionListener() {

                            @Override
                            public void onFavoriteClicked(
                                    Credential credential,
                                    int position
                            ) {

                                boolean newFavorite =
                                        !credential.isFavorite();

                                credential.setFavorite(
                                        newFavorite
                                );

                                applyFilters();

                                secureVaultCoordinator.setCredentialFavorite(
                                        credential.getId(),
                                        newFavorite,
                                        new VaultDataService.ResultCallback<Integer>() {

                                            @Override
                                            public void onSuccess(
                                                    Integer rows
                                            ) {

                                                if (rows == null || rows <= 0) {

                                                    credential.setFavorite(
                                                            !newFavorite
                                                    );

                                                    applyFilters();

                                                    Toast.makeText(
                                                            VaultActivity.this,
                                                            R.string.credential_save_error,
                                                            Toast.LENGTH_SHORT
                                                    ).show();
                                                }
                                            }

                                            @Override
                                            public void onError(
                                                    Exception exception
                                            ) {

                                                credential.setFavorite(
                                                        !newFavorite
                                                );

                                                applyFilters();

                                                Toast.makeText(
                                                        VaultActivity.this,
                                                        R.string.credential_save_error,
                                                        Toast.LENGTH_SHORT
                                                ).show();
                                            }
                                        }
                                );
                            }

                            @Override
                            public void onRiskClicked(
                                    Credential credential,
                                    VaultCredentialAdapter.RiskStatus riskStatus,
                                    View anchorView
                            ) {

                                showRiskTooltip(
                                        anchorView,
                                        riskStatus
                                );
                            }

                            @Override
                            public void onCredentialClicked(
                                    Credential credential
                            ) {

                                if (!requireUnlockedSession()) {
                                    return;
                                }

                                openCredentialDetails(
                                        credential
                                );
                            }
                        }
                );

        noteAdapter =
                new VaultSecureNoteAdapter(
                        note -> {

                            if (!requireUnlockedSession()) {
                                return;
                            }

                            openSecureNoteDetails(
                                    note
                            );
                        }
                );

        allItemsAdapter =
                new ConcatAdapter(
                        adapter,
                        noteAdapter
                );

        recyclerVault.setAdapter(
                allItemsAdapter
        );
    }

    private void showVaultLoadingState() {

        recyclerVault.setVisibility(
                View.GONE
        );

        layoutVaultState.setVisibility(
                View.VISIBLE
        );

        layoutVaultLoading.setVisibility(
                View.VISIBLE
        );

        layoutVaultEmpty.setVisibility(
                View.GONE
        );

        layoutVaultError.setVisibility(
                View.GONE
        );
    }

    private void showVaultContentState() {

        recyclerVault.setVisibility(
                View.VISIBLE
        );

        layoutVaultState.setVisibility(
                View.GONE
        );

        layoutVaultLoading.setVisibility(
                View.GONE
        );

        layoutVaultEmpty.setVisibility(
                View.GONE
        );

        layoutVaultError.setVisibility(
                View.GONE
        );
    }

    private void showVaultEmptyState() {

        recyclerVault.setVisibility(
                View.GONE
        );

        layoutVaultState.setVisibility(
                View.VISIBLE
        );

        layoutVaultLoading.setVisibility(
                View.GONE
        );

        layoutVaultEmpty.setVisibility(
                View.VISIBLE
        );

        layoutVaultError.setVisibility(
                View.GONE
        );
    }

    private void showVaultErrorState() {

        recyclerVault.setVisibility(
                View.GONE
        );

        layoutVaultState.setVisibility(
                View.VISIBLE
        );

        layoutVaultLoading.setVisibility(
                View.GONE
        );

        layoutVaultEmpty.setVisibility(
                View.GONE
        );

        layoutVaultError.setVisibility(
                View.VISIBLE
        );
    }

    private void refreshVaultData() {

        showVaultLoadingState();

        secureVaultCoordinator.getCredentials(
                new VaultDataService.ResultCallback<List<Credential>>() {

                    @Override
                    public void onSuccess(
                            List<Credential> credentials
                    ) {

                        allCredentials.clear();
                        allCredentials.addAll(
                                credentials
                        );

                        allRiskStatuses.clear();

                        for (int i = 0;
                             i < allCredentials.size();
                             i++) {

                            allRiskStatuses.add(
                                    VaultCredentialAdapter.RiskStatus.NONE
                            );
                        }

                        loadSecureNotes();
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        showVaultErrorState();
                    }
                }
        );
    }

    private void loadSecureNotes() {

        secureVaultCoordinator.getSecureNotes(
                new VaultDataService.ResultCallback<List<SecureNote>>() {

                    @Override
                    public void onSuccess(
                            List<SecureNote> notes
                    ) {

                        allNotes.clear();
                        allNotes.addAll(
                                notes
                        );

                        applyFilters();

                        if (allCredentials.isEmpty()
                                && allNotes.isEmpty()) {

                            showVaultEmptyState();

                        } else {

                            showVaultContentState();
                        }
                    }

                    @Override
                    public void onError(
                            Exception exception
                    ) {

                        showVaultErrorState();
                    }
                }
        );
    }

    private void openCredentialDetails(
            Credential credential
    ) {

        Intent intent =
                new Intent(
                        VaultActivity.this,
                        CredentialDetailsActivity.class
                );

        intent.putExtra(
                CredentialDetailsActivity.EXTRA_ID,
                credential.getId()
        );

        startActivity(
                intent
        );
    }
    private void openSecureNoteDetails(
            SecureNote note
    ) {

        Intent intent =
                new Intent(
                        VaultActivity.this,
                        SecureNoteDetailsActivity.class
                );

        intent.putExtra(
                SecureNoteDetailsActivity.EXTRA_ID,
                note.getId()
        );

        startActivity(
                intent
        );
    }

    private void setupSearch() {

        AppCompatEditText editSearchVault =
                findViewById(
                        R.id.editSearchVault
                );

        editSearchVault.addTextChangedListener(
                new TextWatcher() {

                    @Override
                    public void beforeTextChanged(
                            CharSequence s,
                            int start,
                            int count,
                            int after
                    ) {
                        // No action needed.
                    }

                    @Override
                    public void onTextChanged(
                            CharSequence s,
                            int start,
                            int before,
                            int count
                    ) {
                        // No action needed.
                    }

                    @Override
                    public void afterTextChanged(
                            Editable editable
                    ) {

                        currentSearchQuery =
                                editable == null
                                        ? ""
                                        : editable.toString();

                        applyFilters();
                    }
                }
        );
    }

    private void applyFilters() {

        String normalizedQuery =
                currentSearchQuery
                        .trim()
                        .toLowerCase(
                                Locale.ROOT
                        );

        List<Credential> filteredCredentials =
                new ArrayList<>();

        List<VaultCredentialAdapter.RiskStatus> filteredRisks =
                new ArrayList<>();

        List<SecureNote> filteredNotes =
                new ArrayList<>();

        /*
         * Credentials appear in:
         * ALL
         * FAVORITES
         *
         * They do not appear in NOTES.
         */
        if (activeFilter != VaultFilter.NOTES) {

            for (int i = 0;
                 i < allCredentials.size();
                 i++) {

                Credential credential =
                        allCredentials.get(i);

                if (activeFilter == VaultFilter.FAVORITES
                        && !credential.isFavorite()) {

                    continue;
                }

                boolean matchesSearch =
                        normalizedQuery.isEmpty()
                                || containsSearchText(
                                credential.getTitle(),
                                normalizedQuery
                        )
                                || containsSearchText(
                                credential.getUsername(),
                                normalizedQuery
                        )
                                || containsSearchText(
                                credential.getWebsite(),
                                normalizedQuery
                        );

                if (matchesSearch) {

                    filteredCredentials.add(
                            credential
                    );

                    if (i < allRiskStatuses.size()) {

                        filteredRisks.add(
                                allRiskStatuses.get(i)
                        );

                    } else {

                        filteredRisks.add(
                                VaultCredentialAdapter.RiskStatus.NONE
                        );
                    }
                }
            }
        }

        /*
         * Secure Notes appear in:
         * ALL
         * NOTES
         *
         * They do not appear in FAVORITES because
         * SecureNote currently has no favorite field.
         */
        if (activeFilter != VaultFilter.FAVORITES) {

            for (SecureNote note : allNotes) {

                boolean matchesSearch =
                        normalizedQuery.isEmpty()
                                || containsSearchText(
                                note.getTitle(),
                                normalizedQuery
                        )
                                || containsSearchText(
                                note.getContent(),
                                normalizedQuery
                        );

                if (matchesSearch) {

                    filteredNotes.add(
                            note
                    );
                }
            }
        }

        adapter.submitCredentials(
                filteredCredentials,
                filteredRisks
        );

        noteAdapter.submitNotes(
                filteredNotes
        );
    }

    private boolean containsSearchText(
            String value,
            String normalizedQuery
    ) {

        return value != null
                && value
                .toLowerCase(
                        Locale.ROOT
                )
                .contains(
                        normalizedQuery
                );
    }

    private void setupFilters() {

        filterAll =
                findViewById(
                        R.id.filterAll
                );

        filterFavorites =
                findViewById(
                        R.id.filterFavorites
                );

        filterNotes =
                findViewById(
                        R.id.filterNotes
                );

        filterAll.setOnClickListener(
                view -> {

                    activeFilter =
                            VaultFilter.ALL;

                    updateFilterAppearance();

                    applyFilters();
                }
        );

        filterFavorites.setOnClickListener(
                view -> {

                    activeFilter =
                            VaultFilter.FAVORITES;

                    updateFilterAppearance();

                    applyFilters();
                }
        );

        filterNotes.setOnClickListener(
                view -> {

                    activeFilter =
                            VaultFilter.NOTES;

                    updateFilterAppearance();

                    applyFilters();
                }
        );

        updateFilterAppearance();
    }

    private void updateFilterAppearance() {

        updateFilterChip(
                filterAll,
                activeFilter == VaultFilter.ALL
        );

        updateFilterChip(
                filterFavorites,
                activeFilter == VaultFilter.FAVORITES
        );

        updateFilterChip(
                filterNotes,
                activeFilter == VaultFilter.NOTES
        );

        TextView textAddCredential =
                findViewById(
                        R.id.textAddCredential
                );

        if (activeFilter == VaultFilter.NOTES) {

            textAddCredential.setText(
                    R.string.vault_add_secure_note
            );

        } else {

            textAddCredential.setText(
                    R.string.vault_add_credential
            );
        }
    }

    private void updateFilterChip(
            TextView filter,
            boolean active
    ) {

        filter.setBackgroundResource(
                active
                        ? R.drawable.vault_chip_active_bg
                        : R.drawable.vault_chip_inactive_bg
        );

        filter.setTextColor(
                ContextCompat.getColor(
                        this,
                        active
                                ? R.color.vault_chip_text_dark
                                : R.color.vault_text_secondary
                )
        );
    }

    private void setupActions() {

        View buttonQuickAdd =
                findViewById(
                        R.id.buttonQuickAdd
                );

        View buttonAddCredential =
                findViewById(
                        R.id.buttonAddCredential
                );

        View buttonVaultRetry =
                findViewById(
                        R.id.buttonVaultRetry
                );

        View navHome =
                findViewById(
                        R.id.navHome
                );

        View navVault =
                findViewById(
                        R.id.navVault
                );

        View navAlerts =
                findViewById(
                        R.id.navAlerts
                );

        View navSettings =
                findViewById(
                        R.id.navSettings
                );

        buttonQuickAdd.setOnClickListener(
                this::showQuickAddMenu
        );

        buttonVaultRetry.setOnClickListener(
                view -> refreshVaultData()
        );

        buttonAddCredential.setOnClickListener(
                view -> {

                    if (activeFilter == VaultFilter.NOTES) {

                        openAddSecureNoteScreen();

                    } else {

                        openAddCredentialScreen();
                    }
                }
        );

        navHome.setOnClickListener(
                view -> {

                    if (!requireUnlockedSession()) {
                        return;
                    }

                    Intent intent =
                            new Intent(
                                    VaultActivity.this,
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
                view ->
                        requireUnlockedSession()
        );

        navAlerts.setOnClickListener(
                view -> {

                    if (!requireUnlockedSession()) {
                        return;
                    }

                    Toast.makeText(
                            VaultActivity.this,
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
                            VaultActivity.this,
                            R.string.home_settings_navigation_pending,
                            Toast.LENGTH_SHORT
                    ).show();
                }
        );
    }

    private void showQuickAddMenu(
            View anchorView
    ) {

        if (!requireUnlockedSession()) {
            return;
        }

        final int addCredentialItemId =
                1;

        final int addSecureNoteItemId =
                2;

        PopupMenu popupMenu =
                new PopupMenu(
                        this,
                        anchorView
                );

        popupMenu.getMenu().add(
                0,
                addCredentialItemId,
                0,
                R.string.vault_add_credential
        );

        popupMenu.getMenu().add(
                0,
                addSecureNoteItemId,
                1,
                R.string.vault_add_secure_note
        );

        popupMenu.setOnMenuItemClickListener(
                menuItem -> {

                    if (menuItem.getItemId()
                            == addCredentialItemId) {

                        openAddCredentialScreen();

                        return true;
                    }

                    if (menuItem.getItemId()
                            == addSecureNoteItemId) {

                        openAddSecureNoteScreen();

                        return true;
                    }

                    return false;
                }
        );

        popupMenu.show();
    }

    private void openAddCredentialScreen() {

        if (!requireUnlockedSession()) {
            return;
        }

        Intent intent =
                new Intent(
                        VaultActivity.this,
                        AddCredentialActivity.class
                );

        startActivity(
                intent
        );
    }

    private void openAddSecureNoteScreen() {

        if (!requireUnlockedSession()) {
            return;
        }

        Intent intent =
                new Intent(
                        VaultActivity.this,
                        AddSecureNoteActivity.class
                );

        startActivity(
                intent
        );
    }

    private void showRiskTooltip(
            View anchorView,
            VaultCredentialAdapter.RiskStatus riskStatus
    ) {

        int textResource;
        int backgroundResource;
        int textColorResource;

        if (riskStatus
                == VaultCredentialAdapter.RiskStatus.BREACH) {

            textResource =
                    R.string.vault_risk_breach;

            backgroundResource =
                    R.drawable.vault_risk_tooltip_red_bg;

            textColorResource =
                    R.color.vault_risk_red;

        } else if (riskStatus
                == VaultCredentialAdapter.RiskStatus.AT_RISK) {

            textResource =
                    R.string.vault_risk_at_risk;

            backgroundResource =
                    R.drawable.vault_risk_tooltip_amber_bg;

            textColorResource =
                    R.color.vault_risk_amber;

        } else {

            return;
        }

        TextView tooltip =
                new TextView(
                        this
                );

        tooltip.setText(
                textResource
        );

        tooltip.setTextColor(
                ContextCompat.getColor(
                        this,
                        textColorResource
                )
        );

        tooltip.setTextSize(
                TypedValue.COMPLEX_UNIT_SP,
                12
        );

        tooltip.setTypeface(
                tooltip.getTypeface(),
                Typeface.BOLD
        );

        tooltip.setPadding(
                dpToPx(10),
                dpToPx(6),
                dpToPx(10),
                dpToPx(6)
        );

        tooltip.setBackgroundResource(
                backgroundResource
        );

        PopupWindow popup =
                new PopupWindow(
                        tooltip,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        true
                );

        popup.setBackgroundDrawable(
                new ColorDrawable(
                        Color.TRANSPARENT
                )
        );

        popup.setOutsideTouchable(
                true
        );

        popup.setElevation(
                dpToPx(4)
        );

        popup.showAsDropDown(
                anchorView,
                -dpToPx(42),
                dpToPx(4)
        );
    }

    private int dpToPx(
            int dp
    ) {

        return Math.round(
                dp
                        * getResources()
                        .getDisplayMetrics()
                        .density
        );
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (isFinishing()) {
            return;
        }

        if (adapter != null && noteAdapter != null) {
            refreshVaultData();
        }
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
                        VaultActivity.this,
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
}